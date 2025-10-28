from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Dict, List

from ..config import settings


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
        if settings.enable_tool_containers and self.container_image:
            cmd = self.build_container_command(target)
        else:
            cmd = self.build_command(target)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            # Herramienta no disponible en el entorno actual.
            return ToolResult(
                tool=self.name,
                exit_code=127,
                stdout="",
                stderr=str(exc),
            )

        stdout, stderr = await process.communicate()
        return ToolResult(
            tool=self.name,
            exit_code=process.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
        )

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


class WapitiRunner(ToolRunner):
    name = "wapiti"
    container_image = "buh/wapiti"

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


class NiktoRunner(ToolRunner):
    name = "nikto"
    container_image = "buh/nikto"

    def build_command(self, target: str) -> List[str]:
        return ["nikto", "-h", target, "-output", "/tmp/nikto-report.json", "-Format", "json"]

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


class SQLMapRunner(ToolRunner):
    name = "sqlmap"
    container_image = "buh/sqlmap"

    def build_command(self, target: str) -> List[str]:
        return ["sqlmap", "-u", target, "--batch", "--output-dir", "/tmp/sqlmap"]

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
