import asyncio
import logging
from datetime import datetime
from typing import Iterable, List

from sqlalchemy.orm import Session

from .. import models
from ..services import ai, cve, prioritization
from ..services.tooling import get_tool_runner

try:
    from celery.exceptions import CeleryError
except Exception:  # pragma: no cover - celery always available in runtime image
    CeleryError = Exception

try:
    from kombu.exceptions import KombuError
except Exception:  # pragma: no cover - kombu always available in runtime image
    KombuError = Exception

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    """High-level orchestration of vulnerability scans and result enrichment."""

    def __init__(self, db: Session):
        self.db = db

    def enqueue_scan(self, scan: models.Scan) -> None:
        scan.status = models.ScanStatus.running
        self.db.add(scan)
        self.db.commit()
        from ..tasks import scans as scan_tasks

        try:
            scan_tasks.execute_scan.delay(str(scan.id))
        except (KombuError, CeleryError, ConnectionError) as exc:
            logger.warning(
                "Falling back to inline scan execution due to broker error: %s", exc
            )
            self._execute_scan_inline(scan)

    def _execute_scan_inline(self, scan: models.Scan) -> None:
        """Run the scan synchronously when async queue processing is unavailable."""

        try:
            try:
                asyncio.run(self.run_scan(scan))
            except RuntimeError:
                # Event loop already running (e.g. during tests) -> reuse loop.
                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.run_scan(scan))
        except Exception:
            logger.exception("Inline scan execution failed")
            scan.status = models.ScanStatus.failed
            scan.finished_at = datetime.utcnow()
            self.db.add(scan)
            self.db.commit()
            raise

    def process_tool_results(
        self, scan: models.Scan, findings: Iterable[dict]
    ) -> None:
        for item in findings:
            if isinstance(item, Exception):
                finding = models.Finding(
                    scan=scan,
                    tool="unknown",
                    title="Error ejecutando herramienta",
                    description=str(item),
                    severity=models.Severity.info,
                    remediation="Reintente el escaneo o valide la configuración del contenedor.",
                    exploitation="No se generó vector de explotación por error de ejecución.",
                    evidence={"error": str(item)},
                    metadata={},
                )
                self.db.add(finding)
                continue

            severity_value = item.get("severity")
            severity = None
            if severity_value is not None:
                try:
                    severity = models.Severity(severity_value)
                except ValueError:
                    logger.debug(
                        "Invalid severity '%s' received from tool %s", severity_value, item
                    )
            if severity is None:
                severity = prioritization.prioritizer.evaluate(item)

            remediation = ai.assistant.suggest_remediation(item)
            exploitation = ai.assistant.summarize_exploitation(item)
            cve_id = cve.cve_enricher.correlate(item)

            finding = models.Finding(
                scan=scan,
                tool=item.get("tool", "unknown"),
                title=item.get("title", "Unknown finding"),
                description=item.get("description", ""),
                severity=severity,
                remediation=remediation,
                exploitation=exploitation,
                cve=cve_id,
                evidence=item.get("evidence", {}),
                metadata=item.get("metadata", {}),
            )
            self.db.add(finding)
        scan.finished_at = datetime.utcnow()
        scan.status = models.ScanStatus.completed
        self.db.commit()

    async def execute_tool(self, tool: str, target: str) -> List[dict]:
        try:
            runner = get_tool_runner(tool)
        except ValueError as exc:
            logger.error("Herramienta no registrada solicitada: %s", tool)
            return [
                {
                    "tool": tool,
                    "title": f"Herramienta '{tool}' no está configurada",
                    "description": (
                        "La herramienta solicitada no forma parte del registro actual. "
                        "Revise la configuración del backend o actualice la lista de "
                        "herramientas permitidas."
                    ),
                    "severity": "informational",
                    "evidence": {"error": str(exc)},
                    "metadata": {
                        "simulated": True,
                        "reason": "tool_not_registered",
                    },
                }
            ]
        try:
            result = await runner.run(target)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Error inesperado ejecutando %s", tool)
            return runner.synthetic_findings(target, reason=str(exc))

        findings = runner.produce_findings(result, target)
        if findings:
            for item in findings:
                metadata = item.setdefault("metadata", {})
                metadata.setdefault("exit_code", result.exit_code)
            return findings

        def _augment_synthetic(findings: List[dict], reason: str | None) -> List[dict]:
            for entry in findings:
                metadata = entry.setdefault("metadata", {})
                metadata.setdefault("exit_code", result.exit_code)
                if reason and "reason" not in metadata:
                    metadata.setdefault("reason", reason)
                evidence = entry.setdefault("evidence", {})
                if result.stdout and "stdout" not in evidence:
                    evidence["stdout"] = result.stdout
                if result.stderr and "stderr" not in evidence:
                    evidence["stderr"] = result.stderr
            return findings

        if result.exit_code == 127:
            logger.error("Herramienta %s no disponible en el entorno actual", tool)
            findings = [
                {
                    "tool": tool,
                    "title": f"{tool} no está instalado",
                    "description": (
                        "El ejecutable no se encontró en el contenedor de trabajo. "
                        "Instala la herramienta o habilita el uso de contenedores de escaneo."
                    ),
                    "severity": "informational",
                    "metadata": {
                        "simulated": False,
                        "reason": "tool_missing",
                        "exit_code": result.exit_code,
                    },
                    "evidence": {"stderr": result.stderr} if result.stderr else {},
                }
            ]
            synthetic = runner.synthetic_findings(target, reason="tool_missing")
            findings.extend(_augment_synthetic(synthetic, reason="tool_missing"))
            return findings

        logger.warning(
            "La herramienta %s no produjo salida útil (exit code %s). Se generará resultado simulado.",
            tool,
            result.exit_code,
        )
        reason = (
            f"exit_code={result.exit_code}"
            if result.exit_code != 0
            else "sin_salida"
        )
        findings = runner.synthetic_findings(target, reason=reason)
        return _augment_synthetic(findings, reason)

    async def run_scan(self, scan: models.Scan) -> None:
        tasks = [self.execute_tool(tool, scan.target.url) for tool in scan.requested_tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        flattened: List[dict | Exception] = []
        for item in results:
            if isinstance(item, Exception):
                flattened.append(item)
                continue
            flattened.extend(item)
        self.process_tool_results(scan, flattened)
