from typing import Optional

from .ai import assistant


class CVEEnricher:
    """Simple placeholder for CVE correlation logic."""

    def correlate(self, finding: dict) -> Optional[str]:
        # In a real implementation this would query NVD or Vulners APIs.
        return assistant.predict_cve(finding)


cve_enricher = CVEEnricher()
