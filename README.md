# Buh - Plataforma de Escaneo de Vulnerabilidades

Buh es una plataforma profesional para la orquestación de escaneos web mediante herramientas OSS líderes (Wapiti, Nikto, SQLmap y GoBuster). La solución ofrece enriquecimiento automático con IA, correlación de CVE, priorización basada en riesgo y un dashboard interactivo para visualizar el estado de la superficie expuesta.

## Arquitectura

La plataforma se ejecuta sobre contenedores Docker completamente aislados y orquestados a través de `docker-compose`.

- **backend** (`FastAPI`, `Celery`, `PostgreSQL`, `Redis`): expone APIs REST, programa escaneos y procesa resultados.
- **worker**: ejecuta tareas asincrónicas de orquestación de herramientas y enriquecimiento mediante Celery.
- **frontend** (`React + Vite`): dashboard con métricas de criticidad, mapa de impacto y detalle de hallazgos.
- **db**: PostgreSQL para persistencia relacional.
- **redis**: broker/resultado para Celery y coordinación de tareas.
- **scanners**: imágenes individuales para cada herramienta (Wapiti, Nikto, SQLmap, GoBuster) que pueden ser invocadas bajo demanda.

![Arquitectura](docs/architecture-diagram.png)

> **Nota**: El diagrama es un marcador de posición. Sustituya por un diagrama generado según sea necesario.

## Requisitos Previos

- Docker 24+
- Docker Compose Plugin v2
- Node.js 20+ (solo para desarrollo local del frontend)
- Python 3.11+ (para ejecutar el backend sin contenedor, opcional)

## Puesta en Marcha

1. Copie `.env.example` a `backend/.env` si requiere personalizar variables (por ejemplo, para habilitar/deshabilitar el uso de contenedores de herramientas).
2. Construya e inicie todos los servicios:

   ```bash
   docker compose up --build
   ```

3. Acceda al dashboard en `http://localhost:3000` y al API en `http://localhost:8000/docs`.

### Servicios de escaneo

Cada herramienta dispone de una imagen dedicada bajo `scanners/<tool>/Dockerfile`. El backend puede invocar estos contenedores usando el registro `TOOL_REGISTRY`. Para ambientes con restricciones de ejecución directa de binarios, se recomienda:

- Habilitar la ejecución mediante `docker run --rm buh/<tool>` desde tareas Celery (el servicio `worker` ya monta el socket de Docker del host).
- Usar wrappers Python como los definidos en `backend/app/services/tooling.py` para capturar `stdout/stderr` y artefactos JSON/HTML.

## Backend

- Configuración en `backend/app/config.py`.
- Modelos SQLAlchemy y esquemas Pydantic para persistencia de escaneos, hallazgos y priorización (`backend/app/models.py`, `backend/app/schemas.py`).
- Orquestación de tareas y enriquecimiento IA en `backend/app/services/` y `backend/app/tasks/`.
- Endpoints principales disponibles bajo `/scans`.

Ejecutar localmente (fuera de Docker):

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Frontend

Aplicación creada con React + Vite.

```bash
cd frontend
npm install
npm run dev
```

La vista principal incluye:

- Tarjetas de métricas globales.
- Mapa de impacto para webs escaneadas con indicadores de criticidad (Rojo/Amarillo/Verde).
- Tabla interactiva de hallazgos con filtrado por severidad.

## IA y Enriquecimiento

El módulo de IA (`backend/app/services/ai.py`) actúa como punto de integración para modelos de lenguaje que generan recomendaciones contextuales de remediación, análisis de explotación y correlación CVE asistida. Se puede sustituir por un modelo externo (OpenAI, HuggingFace, etc.) configurando la variable `AI_MODEL` y extendiendo las clases provistas.

## Futuras Extensiones

- Persistencia de artefactos de reporte JSON/XML por herramienta.
- Integración con colas de trabajo externas (RabbitMQ, AWS SQS).
- Autenticación y control de acceso basado en roles.
- Generación de reportes PDF automatizados.
