from typing import Tuple

from app.models import Vulnerability

SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    None: 1,
}

CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
    None: 0.5,
}


PRIORITY_THRESHOLDS: Tuple[Tuple[float, str], ...] = (
    (8.0, "P1"),
    (6.0, "P2"),
    (3.5, "P3"),
    (0.0, "P4"),
)


def compute_priority(vuln: Vulnerability, asset_value: float = 1.0) -> Tuple[float, str]:
    severity_weight = SEVERITY_WEIGHTS.get(vuln.severity, 1)
    confidence_weight = CONFIDENCE_WEIGHTS.get(vuln.confidence, 0.5)
    cvss_component = vuln.cvss_v3 or 5.0
    exposure = 1.2 if vuln.target.startswith("https") else 1.0
    raw_score = (cvss_component * 0.6 + severity_weight * 1.5) * confidence_weight * exposure * asset_value
    return raw_score, label_from_score(raw_score)


def label_from_score(score: float) -> str:
    for threshold, label in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "P4"
