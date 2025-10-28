from datetime import datetime

from app.models import Vulnerability
from app.services.prioritization import compute_priority


def make_vuln(**kwargs):
    base = dict(
        id_local="test",
        scan_id="scan",
        tool="wapiti",
        target="https://example.com",
        path="/",
        parameter=None,
        title="Test",
        description="desc",
        severity="high",
        cvss_v3=8.0,
        cve=[],
        confidence="high",
        evidence={},
        references=[],
        timestamp=datetime.utcnow(),
        priority_score=None,
        exploitability_notes="",
    )
    base.update(kwargs)
    return Vulnerability(**base)


def test_priority_high_severity():
    vuln = make_vuln(severity="critical")
    score, label = compute_priority(vuln)
    assert label == "P1"
    assert score > 8


def test_priority_low_severity():
    vuln = make_vuln(severity="low", confidence="low", cvss_v3=2.0)
    score, label = compute_priority(vuln)
    assert label in {"P3", "P4"}
