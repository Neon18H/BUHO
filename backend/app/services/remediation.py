from typing import Any, Dict


class RemediationClient:
    def __init__(self) -> None:
        self.provider = "mock"
        self.config: Dict[str, Any] = {}

    def configure(self, provider: str, **kwargs: Any) -> None:
        self.provider = provider
        self.config.update(kwargs)

    def remediate(self, prompt: str) -> Dict[str, Any]:
        # Placeholder for real LLM invocation
        return {
            "remediation_short": "Aplicar parche disponible",
            "remediation_steps": ["Identificar versión", "Aplicar parche", "Verificar"],
            "mitigation_timeline": {
                "immediate": "Bloquear acceso temporal",
                "short_term": "Aplicar parche",
                "long_term": "Implementar WAF",
            },
            "exploitability": "Un atacante enviaría payload malicioso para explotación.",
            "related_cve": [],
            "verification_commands": ["curl -I https://example.com/login"],
            "risk_explanation": "Basado en CVSS y evidencia capturada.",
        }
