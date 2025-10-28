from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings


class CVEEnrichmentClient:
    """Simple client to fetch CVE data. In MVP we simulate data for offline use."""

    def __init__(self, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0") -> None:
        self.base_url = base_url

async def fetch(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        enriched: Dict[str, Dict[str, Any]] = {}
        if settings.demo_mode:
            for cve in cve_ids:
                enriched[cve] = {
                    "cve": cve,
                    "cvss_v3": 8.3,
                    "summary": f"Mocked description for {cve}",
                    "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                }
            return enriched
        async with httpx.AsyncClient(timeout=10.0) as client:
            for cve in cve_ids:
                resp = await client.get(self.base_url, params={"cveId": cve})
                if resp.status_code == 200:
                    data = resp.json()
                    metrics = data.get("vulnerabilities", [{}])[0].get("cve", {}).get("metrics", {})
                    cvss_score = (
                        metrics.get("cvssMetricV31", [{}])[0]
                        .get("cvssData", {})
                        .get("baseScore")
                    )
                    enriched[cve] = {
                        "cve": cve,
                        "cvss_v3": cvss_score,
                        "summary": data.get("vulnerabilities", [{}])[0].get("cve", {}).get("descriptions", [{}])[0].get("value"),
                        "references": [ref.get("url") for ref in data.get("vulnerabilities", [{}])[0].get("cve", {}).get("references", {}).get("referenceData", [])],
                    }
        return enriched


async def enrich_vulnerability_async(vuln: Dict[str, Any], client: Optional[CVEEnrichmentClient] = None) -> Dict[str, Any]:
    client = client or CVEEnrichmentClient()
    cves = vuln.get("cve", [])
    if not cves:
        return vuln
    enrichment = await client.fetch(cves)
    if enrichment:
        top_cve = next(iter(enrichment.values()))
        vuln.setdefault("references", []).extend(top_cve.get("references", []))
        vuln.setdefault("cvss_v3", top_cve.get("cvss_v3"))
        vuln.setdefault("exploitability_notes", top_cve.get("summary"))
    return vuln


def enrich_vulnerability(vuln: Dict[str, Any], client: Optional[CVEEnrichmentClient] = None) -> Dict[str, Any]:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        raise RuntimeError("Use enrich_vulnerability_async inside async contexts")
    return asyncio.run(enrich_vulnerability_async(vuln, client))
