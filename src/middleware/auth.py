import time
from functools import lru_cache
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from jwt import PyJWT, PyJWTError

from conf.config import JWT_ALGORITHM, JWT_EXPIRE_SECONDS, JWT_SECRET


@lru_cache(maxsize=1)
def _jwt() -> PyJWT:
    return PyJWT()


EXEMPT_PATHS: set[str] = set()


def exempt(path: str):
    def decorator(fn):
        EXEMPT_PATHS.add(path)
        return fn
    return decorator


def create_token(subject: Dict[str, Any]) -> str:
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + JWT_EXPIRE_SECONDS}
    return _jwt().encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Dict[str, Any]:
    try:
        decoded = _jwt().decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def setup_jwt_middleware(app: FastAPI):
    @app.middleware("http")
    async def jwt_middleware(request: Request, call_next):
        path = request.url.path
        if path in EXEMPT_PATHS:
            return await call_next(request)

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized")
        token = auth.split(" ", 1)[1]
        payload = verify_token(token)
        request.state.user = payload.get("sub")
        return await call_next(request)
