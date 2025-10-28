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
        runner = get_tool_runner(tool)
        try:
            result = await runner.run(target)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Error inesperado ejecutando %s", tool)
            return runner.synthetic_findings(target, reason=str(exc))

        if result.success and (result.stdout or result.stderr):
            description = result.stdout or result.stderr
            return [
                {
                    "tool": tool,
                    "title": f"Resultado de {tool}",
                    "description": description,
                    "severity": "medium",
                    "evidence": {"stdout": result.stdout, "stderr": result.stderr},
                    "metadata": {
                        "exit_code": result.exit_code,
                        "cvss": 5.0,
                        "simulated": False,
                    },
                }
            ]

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
        for item in findings:
            evidence = item.setdefault("evidence", {})
            if result.stdout:
                evidence.setdefault("stdout", result.stdout)
            if result.stderr:
                evidence.setdefault("stderr", result.stderr)
            metadata = item.setdefault("metadata", {})
            metadata.setdefault("exit_code", result.exit_code)
        return findings

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
