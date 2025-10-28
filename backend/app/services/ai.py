from typing import Dict

from .config import settings


class RemediationAssistant:
    """Lightweight placeholder for an AI-backed remediation recommender."""

    def __init__(self, model_name: str | None = None):
        self.model_name = model_name or settings.ai_model

    def suggest_remediation(self, finding: Dict) -> str:
        base = finding.get("title", "vulnerability")
        tech = finding.get("metadata", {}).get("technology", "la aplicación objetivo")
        severity = finding.get("severity", "medium")
        return (
            f"Revise la configuración de {tech} para mitigar '{base}'. "
            f"Priorice acciones de hardening y despliegue parches basados en la criticidad {severity}."
        )

    def summarize_exploitation(self, finding: Dict) -> str:
        vector = finding.get("metadata", {}).get("attack_vector", "remoto")
        return (
            f"Un atacante podría explotar esta vulnerabilidad a través de un vector {vector}, "
            "aprovechando una superficie expuesta sin controles adicionales."
        )

    def predict_cve(self, finding: Dict) -> str | None:
        hints = finding.get("metadata", {}).get("cpe", "")
        if not hints:
            return None
        return f"CVE-PREDICTED::{hints}"  # Placeholder for future ML implementation


assistant = RemediationAssistant()
