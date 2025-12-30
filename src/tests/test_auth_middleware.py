import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from middleware import auth


def test_jwt_middleware_returns_401_when_missing_authorization_header():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    auth.setup_jwt_middleware(app)
    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 401
    assert resp.json() == {"msg": "Unauthorized"}


def test_jwt_middleware_returns_401_when_token_invalid():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    auth.setup_jwt_middleware(app)
    client = TestClient(app)
    resp = client.get("/protected", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401
    assert resp.json() == {"msg": "Invalid token"}


def test_jwt_middleware_allows_exempt_route_without_authorization_header():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()

    @auth.exempt
    @app.get("/public")
    async def public():
        return {"ok": True}

    auth.setup_jwt_middleware(app)
    client = TestClient(app)
    resp = client.get("/public")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_jwt_middleware_allows_exempt_route_with_router_prefix():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()

    router = APIRouter(prefix="/user")

    @auth.exempt
    @router.get("/ping")
    async def ping():
        return {"pong": True}

    app.include_router(router)
    auth.setup_jwt_middleware(app)
    client = TestClient(app)
    resp = client.get("/user/ping")
    assert resp.status_code == 200
    assert resp.json() == {"pong": True}


def test_setup_jwt_middleware_freezes_route_registration():
    auth.EXEMPT_PATHS.clear()
    app = FastAPI()

    auth.setup_jwt_middleware(app)

    with pytest.raises(RuntimeError):
        @app.get("/late")
        async def late():
            return {"ok": True}
