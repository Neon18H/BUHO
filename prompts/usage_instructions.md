# Uso del módulo de remediación asistida por IA

La API expone `POST /api/vulns/{id}/remediate` que genera un prompt basado en el archivo `ia_remediation_prompt.txt`.

## Configuración de proveedores de IA

1. Defina la variable de entorno `LLM_PROVIDER` (`openai`, `azure`, `local`).
2. Configure `OPENAI_API_KEY` o `LLM_ENDPOINT` según aplique.
3. Ajuste `MODEL_NAME` para apuntar al modelo deseado.

El cliente por defecto es un _mock_ que devuelve un JSON estático. Para integrar un modelo real:

```python
from app.services.remediation import RemediationClient
client = RemediationClient()
client.configure(provider="openai", api_key="${OPENAI_API_KEY}")
```

La respuesta debe respetar la estructura definida en el prompt y nunca contener PoC destructivas.
