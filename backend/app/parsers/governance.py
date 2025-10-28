from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

from app.models import Vulnerability
from .gobuster import parse_gobuster
from .nikto import parse_nikto
from .sqlmap import parse_sqlmap
from .wapiti import parse_wapiti

PARSERS = {
    "wapiti": parse_wapiti,
    "nikto": parse_nikto,
    "sqlmap": parse_sqlmap,
    "gobuster": parse_gobuster,
}


def apply_parsers(tool: str, path: Path) -> List[Dict]:
    parser = PARSERS.get(tool)
    if not parser:
        raise ValueError(f"Unsupported tool {tool}")
    parsed = parser(path)
    return [item for item in parsed]
