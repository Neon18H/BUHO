# Buho

Buho es un MVP de orquestación de escaneos web que integra herramientas populares (Wapiti, Nikto, sqlmap y Gobuster) y ofrece un dashboard React para visualizar hallazgos, priorizar y generar recomendaciones asistidas por IA.

> **Aviso legal:** Solo escanear sistemas con permiso explícito y por escrito. El autor no se responsabiliza por uso malicioso.

## Arquitectura

- **Backend**: FastAPI + Celery, persistencia en PostgreSQL, enriquecimiento CVE/CVSS y priorización de hallazgos.
- **Frontend**: React (Vite + Tailwind) con tabla filtrable, modal de detalle, mapa de cobertura y exportación CSV.
- **Infraestructura**: Docker Compose (backend, worker Celery, PostgreSQL, Redis, frontend).
- **Pipelines**: GitHub Actions ejecuta lint + tests + build del frontend y publica artefactos.

## Requisitos previos

- Docker y docker-compose
- Python 3.11+
- Node.js 20+
- Poetry (`pip install poetry`)
- Git LFS (ver más abajo)

## Puesta en marcha rápida

```bash
git clone <repo>
cd BUHO
cp .env.example .env  # opcional, configure credenciales si aplica
docker-compose up --build
```

Frontend disponible en `http://localhost:5173` y API en `http://localhost:8000`.

## Operaciones frecuentes

### Inicializar base de datos

```bash
poetry install --directory backend
./scripts/init_db.sh
./scripts/create_admin.sh
```

### Ejecutar demo de importación de hallazgos

```bash
# requiere jq instalado
./scripts/run_demo_scan.sh
```

### Ejecutar tests y linters

```bash
cd backend
poetry install
poetry run flake8
poetry run black --check app
poetry run isort --check-only app
poetry run pytest
```

Para el frontend:

```bash
cd frontend
npm install
npm run lint
npm run build
```

## Git LFS y manejo de binarios

Buho evita almacenar binarios pesados en el repositorio. Para manejar artefactos obligatorios:

1. Instalar Git LFS:
   ```bash
   git lfs install
   ```
2. Rastrear extensiones comunes (editar según necesidad):
   ```bash
   git lfs track "*.zip"
   git lfs track "*.tar.gz"
   git lfs track "*.png"
   ```
3. Migrar archivos existentes a LFS:
   ```bash
   git lfs migrate import --include="*.zip,*.tar.gz,*.exe,*.bin"
   ```
4. Eliminar un binario accidental de un commit:
   ```bash
   git rm --cached path/al/archivo
   ```

Los reportes o builds generados deben subirse como artefactos de CI/CD (por ejemplo, `actions/upload-artifact`) o GitHub Releases.

## Variables de entorno principales

| Variable | Descripción | Valor por defecto |
| --- | --- | --- |
| `DATABASE_URL` | Cadena async de SQLAlchemy | `postgresql+asyncpg://postgres:postgres@db:5432/buho` |
| `SYNC_DATABASE_URL` | Cadena sync para migraciones | `postgresql+psycopg://postgres:postgres@db:5432/buho` |
| `REDIS_URL` | Cola de tareas Celery | `redis://redis:6379/0` |
| `SECRET_KEY` | Firmado JWT | `super-secret-key-change` |
| `LLM_PROVIDER` | Proveedor IA remediación | `mock` |

Cree un archivo `.env` a partir de `.env.example` si necesita personalizar valores.

## Endpoints clave

- `POST /api/scan`: programa un escaneo seguro.
- `GET /api/scan/{scan_id}`: consulta estado y logs.
- `GET /api/vulns`: lista de vulnerabilidades con filtros.
- `GET /api/vulns/{id}`: detalle de vulnerabilidad.
- `POST /api/vulns/{id}/remediate`: genera plan de remediación asistido por IA.
- `POST /api/admin/import`: importa un ZIP con resultados (se usa `scripts/mocks_demo.zip` para demos).
- `GET /api/vulns/export/csv`: exporta CSV ligero.
- `GET /health`: verificación básica.

## Seguridad y cumplimiento

- Autenticación JWT + roles (`admin`, `operator`, `auditor`).
- Rate limiting configurable.
- Validación estricta de targets (solo HTTP/HTTPS).
- Logs estructurados JSON con `structlog`.
- Sin PoCs destructivas ni explotación automatizada.
- UI incluye aviso legal y controles de exportación.

## Observabilidad

- Endpoint `/health` para chequeos.
- Logs estructurados preparados para agregadores.
- Métricas Prometheus pueden añadirse extendiendo FastAPI.

## CI/CD

Workflow en `.github/workflows/ci.yml` ejecuta:
- Linter (flake8, black, isort).
- Tests (pytest con mocks ZIP).
- Build del frontend (npm run build).
- Publicación de artefactos generados por los tests/builds.

## Ética y uso responsable

Buho está diseñado para pruebas de seguridad autorizadas. Respete la legislación vigente y obtenga siempre consentimiento explícito y por escrito del propietario del sistema antes de ejecutar cualquier escaneo.
