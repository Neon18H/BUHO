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

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return ToolResult(
            tool=self.name,
            exit_code=process.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
        )


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


class NiktoRunner(ToolRunner):
    name = "nikto"
    container_image = "buh/nikto"

    def build_command(self, target: str) -> List[str]:
        return ["nikto", "-h", target, "-output", "/tmp/nikto-report.json", "-Format", "json"]


class SQLMapRunner(ToolRunner):
    name = "sqlmap"
    container_image = "buh/sqlmap"

    def build_command(self, target: str) -> List[str]:
        return ["sqlmap", "-u", target, "--batch", "--output-dir", "/tmp/sqlmap"]


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


TOOL_REGISTRY: Dict[str, ToolRunner] = {
    "wapiti": WapitiRunner(),
    "nikto": NiktoRunner(),
    "sqlmap": SQLMapRunner(),
    "gobuster": GoBusterRunner(),
}
