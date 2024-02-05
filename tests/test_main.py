from fastapi.testclient import TestClient

from v4vapp_hive_fastapi_auth.main import app

client = TestClient(app)


def test_main_index():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}
