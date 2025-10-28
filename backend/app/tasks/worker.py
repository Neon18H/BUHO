import json
import uuid
from pathlib import Path
from typing import Dict, List

from celery import Celery
from structlog import get_logger

from app.config import settings
from app.models import Vulnerability
from app.parsers.governance import apply_parsers
from app.services.prioritization import compute_priority

logger = get_logger()

celery_app = Celery(
    "buho",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"])


def _prepare_environment(scan_id: str) -> Path:
    workdir = Path("/tmp_scans") / scan_id
    workdir.mkdir(parents=True, exist_ok=True)
    return workdir


@celery_app.task(name="run_tool")
def run_tool(tool: str, target: str, options: Dict[str, str] | None = None) -> Dict[str, List[Dict]]:
    """Mocked execution that would call subprocess tools with safe parameters."""
    options = options or {}
    scan_id = str(uuid.uuid4())
    workdir = _prepare_environment(scan_id)
    output_file = workdir / f"{tool}_output.json"

    # In the MVP we simulate outputs, but keep subprocess signature for future.
    simulated = {
        "id_local": f"{tool}-{uuid.uuid4()}",
        "scan_id": scan_id,
        "tool": tool,
        "target": target,
        "path": "/login",
        "parameter": "username",
        "title": f"{tool.title()} detected issue",
        "description": f"Simulated finding from {tool}",
        "severity": "high",
        "cvss_v3": 8.0,
        "cve": ["CVE-2024-1234"],
        "confidence": "high",
        "evidence": {"request": "GET /login"},
        "references": ["https://example.com/vuln"],
        "timestamp": "2024-01-01T00:00:00Z",
        "priority_score": None,
        "exploitability_notes": "",
    }
    output_file.write_text(json.dumps({"vulnerabilities": [simulated]}))
    return {"scan_id": scan_id, "path": str(output_file)}


@celery_app.task(name="normalize_results")
def normalize_results(tool: str, payload: Dict[str, str]) -> List[Dict]:
    file_path = Path(payload["path"])
    logger.info("normalizing", tool=tool, file=str(file_path))
    parsed = apply_parsers(tool, file_path)
    vulns = []
    for item in parsed:
        vuln = Vulnerability(**item)
        score, _ = compute_priority(vuln)
        vuln.priority_score = score
        vulns.append(vuln.dict())
    return vulns


async def gather_and_normalize(tool: str, file_path: Path) -> List[Vulnerability]:
    parsed = apply_parsers(tool, file_path)
    vulns: List[Vulnerability] = []
    for item in parsed:
        vuln = Vulnerability(**item)
        score, _ = compute_priority(vuln)
        vuln.priority_score = score
        vulns.append(vuln)
    return vulns
