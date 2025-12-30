import time
from functools import lru_cache
from typing import Any, Callable, Dict, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from jwt import PyJWT, PyJWTError

from common import erri
from conf.config import JWT_ALGORITHM, JWT_EXPIRE_SECONDS, JWT_SECRET


@lru_cache(maxsize=1)
def _jwt() -> PyJWT:
    return PyJWT()


EXEMPT_PATHS: set[str] = set()
_EXEMPT_ENDPOINT_ATTR = "__jwt_exempt__"

TFunc = TypeVar("TFunc", bound=Callable[..., Any])


def exempt(fn: TFunc) -> TFunc:
    setattr(fn, _EXEMPT_ENDPOINT_ATTR, True)
    return fn


def _build_exempt_paths(app: FastAPI) -> set[str]:
    paths: set[str] = set()
    for route in list(getattr(app, "router").routes):
        if not isinstance(route, APIRoute):
            continue
        if getattr(route.endpoint, _EXEMPT_ENDPOINT_ATTR, False):
            paths.add(route.path)
    return paths


def create_token(subject: Dict[str, Any]) -> str:
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + JWT_EXPIRE_SECONDS}
    return _jwt().encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Dict[str, Any]:
    try:
        decoded = _jwt().decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except PyJWTError:
        raise erri.unauthorized("Invalid token")


def setup_jwt_middleware(app: FastAPI):
    EXEMPT_PATHS.update(_build_exempt_paths(app))

    @app.middleware("http")
    async def jwt_middleware(request: Request, call_next):
        path = request.url.path
        if path in EXEMPT_PATHS:
            return await call_next(request)

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"msg": "Unauthorized"})
        token = auth.split(" ", 1)[1]
        try:
            payload = verify_token(token)
        except erri.BusinessError as e:
            return JSONResponse(status_code=e.status_code, content={"msg": e.msg})
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"msg": e.detail})
        request.state.user = payload.get("sub")
        return await call_next(request)
