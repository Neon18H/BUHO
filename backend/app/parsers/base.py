from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Protocol


class Parser(Protocol):
    def parse(self, path: Path) -> Iterable[Dict]:
        ...


def load_json(path: Path) -> Dict:
    import json

    with path.open("r", encoding="utf-8") as handler:
        return json.load(handler)
