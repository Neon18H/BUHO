from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from ..config import settings


logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    tool: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.exit_code == 0


class ToolRunner:
    """Base class for interacting with CLI security tools in an isolated way."""

    name: str = "tool"
    container_image: str | None = None

    def build_command(self, target: str) -> List[str]:
        return [self.name, target]

    def build_container_command(self, target: str) -> List[str]:
        if not self.container_image:
            raise ValueError(f"No container image configured for {self.name}")
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            self.container_image,
            *self.build_command(target),
        ]

    async def run(self, target: str) -> ToolResult:
        """Execute the underlying tool preferring containers when available."""

        execution_plan: List[Tuple[str, List[str]]] = []
        container_enabled = bool(settings.enable_tool_containers and self.container_image)

        if container_enabled:
            docker_path = shutil.which("docker")
            if docker_path:
                execution_plan.append(("container", self.build_container_command(target)))
            else:
                logger.info(
                    "Docker CLI no encontrado; usando ejecución nativa para %s", self.name
                )
        execution_plan.append(("native", self.build_command(target)))

        last_error: Exception | None = None
        for mode, cmd in execution_plan:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                last_error = exc
                logger.debug(
                    "No se encontró comando '%s' para %s (modo %s)",
                    cmd[0],
                    self.name,
                    mode,
                )
                continue

            stdout, stderr = await process.communicate()
            result = ToolResult(
                tool=self.name,
                exit_code=process.returncode,
                stdout=stdout.decode(),
                stderr=stderr.decode(),
            )
            return self.enrich_result(result, target)

        if last_error:
            return ToolResult(
                tool=self.name,
                exit_code=127,
                stdout="",
                stderr=str(last_error),
            )

        # Fall back to a generic failure if no command could be executed.
        return ToolResult(tool=self.name, exit_code=1, stdout="", stderr="execution_failed")

    def enrich_result(self, result: ToolResult, target: str) -> ToolResult:
        """Permite a los runners complementar la salida con artefactos."""

        return result

    def synthetic_findings(self, target: str, reason: str) -> List[dict]:
        """Fallback findings when the real tool output is unavailable."""

        return [
            {
                "tool": self.name,
                "title": f"{self.name.title()} verificación superficial en {target}",
                "description": (
                    "Se generó un hallazgo simulado porque la herramienta no está disponible. "
                    "Valide la instalación o active el uso de contenedores de escaneo."
                ),
                "severity": "informational",
                "metadata": {
                    "simulated": True,
                    "reason": reason,
                    "technology": "servicio web",
                    "attack_vector": "remoto",
                    "cvss": 0,
                },
                "evidence": {},
            }
        ]

    def produce_findings(self, result: ToolResult, target: str) -> List[dict]:
        """Genera hallazgos estructurados en base al resultado de la herramienta."""

        if result.success and (result.stdout.strip() or result.stderr.strip()):
            description = result.stdout.strip() or result.stderr.strip()
            return [
                {
                    "tool": self.name,
                    "title": f"Resultado de {self.name}",
                    "description": description,
                    "severity": "medium",
                    "metadata": {
                        "simulated": False,
                        "attack_vector": "remoto",
                        "technology": "servicio",
                    },
                    "evidence": {
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    },
                }
            ]

        return []


class WapitiRunner(ToolRunner):
    name = "wapiti"
    container_image = "buh/wapiti"
    report_path = Path("/tmp/wapiti-report.json")

    def build_command(self, target: str) -> List[str]:
        return [
            "wapiti",
            "-u",
            target,
            "-f",
            "json",
            "-o",
            "/tmp/wapiti-report.json",
        ]

    def enrich_result(self, result: ToolResult, target: str) -> ToolResult:
        if not result.success:
            return result

        try:
            report = self.report_path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return result

        return ToolResult(
            tool=result.tool,
            exit_code=result.exit_code,
            stdout=report,
            stderr=result.stderr,
        )

    def synthetic_findings(self, target: str, reason: str) -> List[dict]:
        findings = super().synthetic_findings(target, reason)
        findings[0].update(
            {
                "title": f"Exposición OWASP Top 10 en {target}",
                "description": (
                    "Wapiti no se ejecutó correctamente, por lo que se generó un resultado "
                    "de referencia basado en firmas OWASP."
                ),
                "severity": "high",
                "metadata": {
                    "simulated": True,
                    "reason": reason,
                    "technology": "aplicación web",
                    "attack_vector": "remoto",
                    "cvss": 8.2,
                },
            }
        )
        return findings

    def produce_findings(self, result: ToolResult, target: str) -> List[dict]:
        if not result.success:
            return []

        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return super().produce_findings(result, target)

        vulnerabilities: Iterable[dict] = data.get("vulnerabilities", [])
        findings: List[dict] = []
        for vulnerability in vulnerabilities:
            title = (
                vulnerability.get("name")
                or vulnerability.get("type")
                or "Vulnerabilidad identificada"
            )
            url = vulnerability.get("url") or vulnerability.get("path")
            attack = vulnerability.get("attack") or vulnerability.get("description")
            parameter = vulnerability.get("parameter")
            severity_value = (vulnerability.get("severity") or "medium").lower()
            severity = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "informational",
                "informational": "informational",
            }.get(severity_value, "medium")

            description_parts = [part for part in [attack, url] if part]
            description = "\n".join(description_parts) if description_parts else title
            evidence = {
                "url": url,
                "parameter": parameter,
                "classification": vulnerability.get("classification"),
            }
            metadata = {
                "technology": "aplicación web",
                "attack_vector": "remoto",
                "simulated": False,
            }
            references = vulnerability.get("references")
            if references:
                evidence["references"] = references

            findings.append(
                {
                    "tool": self.name,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "metadata": metadata,
                    "evidence": evidence,
                }
            )

        if findings:
            return findings

        return super().produce_findings(result, target)


class NiktoRunner(ToolRunner):
    name = "nikto"
    container_image = "buh/nikto"
    report_path = Path("/tmp/nikto-report.json")

    def build_command(self, target: str) -> List[str]:
        return ["nikto", "-h", target, "-output", "/tmp/nikto-report.json", "-Format", "json"]

    def enrich_result(self, result: ToolResult, target: str) -> ToolResult:
        if not result.success:
            return result

        try:
            report = self.report_path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return result

        return ToolResult(
            tool=result.tool,
            exit_code=result.exit_code,
            stdout=report,
            stderr=result.stderr,
        )

    def synthetic_findings(self, target: str, reason: str) -> List[dict]:
        findings = super().synthetic_findings(target, reason)
        findings[0].update(
            {
                "title": f"Cabeceras inseguras detectadas en {target}",
                "description": (
                    "Nikto no pudo ejecutarse. Se documenta un hallazgo simulado sobre cabeceras HTTP "
                    "faltantes para mantener visibilidad en el tablero."
                ),
                "severity": "medium",
                "metadata": {
                    "simulated": True,
                    "reason": reason,
                    "technology": "servidor web",
                    "attack_vector": "remoto",
                    "cvss": 6.1,
                },
            }
        )
        return findings

    def produce_findings(self, result: ToolResult, target: str) -> List[dict]:
        if not result.success:
            return []

        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return super().produce_findings(result, target)

        items: Iterable[dict] = data.get("vulnerabilities") or data.get("findings") or []
        findings: List[dict] = []
        for entry in items:
            message = entry.get("msg") or entry.get("description") or entry.get("issue")
            if not message:
                continue
            url = entry.get("url") or entry.get("uri")
            risk = (entry.get("risk") or entry.get("severity") or "medium").lower()
            severity = {
                "informational": "informational",
                "info": "informational",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical",
            }.get(risk, "medium")
            references = entry.get("references") or entry.get("ids")
            evidence = {
                "url": url,
                "message": message,
                "references": references,
                "method": entry.get("method"),
            }
            metadata = {
                "technology": "servidor web",
                "attack_vector": "remoto",
                "simulated": False,
            }
            findings.append(
                {
                    "tool": self.name,
                    "title": entry.get("id") or f"Hallazgo Nikto en {target}",
                    "description": message,
                    "severity": severity,
                    "metadata": metadata,
                    "evidence": evidence,
                }
            )

        if findings:
            return findings

        return super().produce_findings(result, target)


class SQLMapRunner(ToolRunner):
    name = "sqlmap"
    container_image = "buh/sqlmap"
    output_dir = Path("/tmp/sqlmap")

    def build_command(self, target: str) -> List[str]:
        return ["sqlmap", "-u", target, "--batch", "--output-dir", "/tmp/sqlmap"]

    def produce_findings(self, result: ToolResult, target: str) -> List[dict]:
        if not result.success:
            return []

        if not self.output_dir.exists():
            return super().produce_findings(result, target)

        try:
            candidate_dirs = [path for path in self.output_dir.iterdir() if path.is_dir()]
        except OSError:
            return super().produce_findings(result, target)

        if not candidate_dirs:
            return super().produce_findings(result, target)

        latest_dir = max(candidate_dirs, key=lambda path: path.stat().st_mtime)
        log_file = latest_dir / "log"
        if not log_file.exists():
            return super().produce_findings(result, target)

        try:
            log_content = log_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return super().produce_findings(result, target)

        findings: List[dict] = []
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for line in log_content.splitlines():
            match = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.*)", line)
            if not match:
                continue
            label, message = match.groups()
            message = message.strip()
            if not message:
                continue
            findings.append(
                {
                    "tool": self.name,
                    "title": f"{label.title()} SQLMap",
                    "description": message,
                    "severity": severity_map.get(label, "medium"),
                    "metadata": {
                        "technology": "base de datos",
                        "attack_vector": "remoto",
                        "simulated": False,
                    },
                    "evidence": {
                        "log_line": line.strip(),
                    },
                }
            )

        if findings:
            return findings

        return super().produce_findings(result, target)

    def synthetic_findings(self, target: str, reason: str) -> List[dict]:
        findings = super().synthetic_findings(target, reason)
        findings[0].update(
            {
                "title": f"Vector de inyección SQL potencial en {target}",
                "description": (
                    "SQLmap no está disponible. Se crea un hallazgo hipotético que describe parámetros "
                    "propensos a inyección basados en patrones comunes."
                ),
                "severity": "critical",
                "metadata": {
                    "simulated": True,
                    "reason": reason,
                    "technology": "motor de base de datos",
                    "attack_vector": "remoto",
                    "cvss": 9.4,
                },
            }
        )
        return findings


class GoBusterRunner(ToolRunner):
    name = "gobuster"
    container_image = "buh/gobuster"
    report_path = Path("/tmp/gobuster.txt")

    def build_command(self, target: str) -> List[str]:
        wordlist = "/lists/common.txt"
        return [
            "gobuster",
            "dir",
            "-u",
            target,
            "-w",
            wordlist,
            "-o",
            "/tmp/gobuster.txt",
        ]

    def produce_findings(self, result: ToolResult, target: str) -> List[dict]:
        if not result.success:
            return []

        try:
            report = self.report_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return super().produce_findings(result, target)
        except OSError:
            return super().produce_findings(result, target)

        entries = [
            line.strip()
            for line in report.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        findings: List[dict] = []
        for entry in entries:
            path = entry.split()[0]
            findings.append(
                {
                    "tool": self.name,
                    "title": f"Recurso descubierto: {path}",
                    "description": entry,
                    "severity": "medium",
                    "metadata": {
                        "technology": "servidor web",
                        "attack_vector": "descubrimiento",
                        "simulated": False,
                    },
                    "evidence": {
                        "path": path,
                        "raw": entry,
                    },
                }
            )

        if findings:
            return findings

        return super().produce_findings(result, target)

    def synthetic_findings(self, target: str, reason: str) -> List[dict]:
        findings = super().synthetic_findings(target, reason)
        findings[0].update(
            {
                "title": f"Directorio sensible expuesto en {target}",
                "description": (
                    "GoBuster no devolvió resultados reales. Se añade un directorio administrativo "
                    "simulado para ilustrar el riesgo de exposición de recursos."
                ),
                "severity": "medium",
                "metadata": {
                    "simulated": True,
                    "reason": reason,
                    "technology": "servidor web",
                    "attack_vector": "descubrimiento",
                    "cvss": 5.8,
                },
                "evidence": {"path": "/admin/backup/"},
            }
        )
        return findings


TOOL_REGISTRY: Dict[str, ToolRunner] = {
    "wapiti": WapitiRunner(),
    "nikto": NiktoRunner(),
    "sqlmap": SQLMapRunner(),
    "gobuster": GoBusterRunner(),
}


def get_tool_runner(name: str) -> ToolRunner:
    if name not in TOOL_REGISTRY:
        raise ValueError(f"Tool '{name}' is not registered")
    return TOOL_REGISTRY[name]
