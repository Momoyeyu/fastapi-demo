from fastapi import FastAPI
from fastapi.testclient import TestClient

from middleware import auth


def test_jwt_middleware_returns_401_when_missing_authorization_header():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()
    auth.setup_jwt_middleware(app)

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 401
    assert resp.json() == {"msg": "Unauthorized"}


def test_jwt_middleware_returns_401_when_token_invalid():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()
    auth.setup_jwt_middleware(app)

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/protected", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401
    assert resp.json() == {"msg": "Invalid token"}
