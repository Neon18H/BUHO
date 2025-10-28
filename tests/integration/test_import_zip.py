from pathlib import Path

from fastapi.testclient import TestClient


def test_import_zip(client: TestClient):
    root = Path(__file__).resolve().parents[2]
    zip_path = root / 'scripts/mocks_demo.zip'
    with zip_path.open('rb') as handle:
        response = client.post('/api/admin/import', files={'file': ('mocks.zip', handle, 'application/zip')})
    assert response.status_code == 200
    payload = response.json()
    assert payload['imported'] >= 1
