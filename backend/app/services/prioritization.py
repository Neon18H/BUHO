from typing import Dict

from ..models import Severity


class RiskPrioritizer:
    """Calculates severity levels based on contextual metadata."""

    def evaluate(self, finding: Dict) -> Severity:
        cvss = finding.get("metadata", {}).get("cvss", 0)
        if cvss >= 9:
            return Severity.critical
        if cvss >= 7:
            return Severity.high
        if cvss >= 4:
            return Severity.medium
        if cvss > 0:
            return Severity.low
        return Severity.info


prioritizer = RiskPrioritizer()
