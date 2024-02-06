from fastapi.testclient import TestClient

from v4vapp_hive_fastapi_auth.main import app

client = TestClient(app)


def test_main_index():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}


def test_main_secure_fail():
    response = client.get("/secure")
    assert response.status_code == 401
    assert "detail" in response.json()
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["detail"] == "Not authenticated"
