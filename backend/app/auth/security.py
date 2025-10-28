from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class TokenPayload:
    def __init__(self, sub: str, exp: datetime, role: str) -> None:
        self.sub = sub
        self.exp = exp
        self.role = role


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode = {"sub": subject, "exp": expire, "role": role}
    return jwt.encode(to_encode, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return TokenPayload(sub=payload["sub"], exp=datetime.fromtimestamp(payload["exp"]), role=payload["role"])
    except jwt.PyJWTError as exc:  # pragma: no cover - simple rethrow
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials") from exc


async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    return decode_token(token)


async def require_role(role: str, token: TokenPayload = Depends(get_current_user)) -> TokenPayload:
    roles = {"admin": 3, "operator": 2, "auditor": 1}
    if roles.get(token.role, 0) < roles.get(role, 0):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return token
