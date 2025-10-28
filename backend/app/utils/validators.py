import re
from urllib.parse import urlparse

from fastapi import HTTPException, status

TARGET_REGEX = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def sanitize_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only http/https targets supported")
    if not TARGET_REGEX.match(parsed.netloc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid host in target")
    return target.rstrip('/')
