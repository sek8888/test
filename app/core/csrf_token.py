import os
import base64
import time

from fastapi import Request, HTTPException, Depends
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from app.core.config import settings


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key
        salt=salt,
        iterations=600000,  # High iteration count for security
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def encrypt(data: str, password: str, expiration_seconds: int = 3600) -> str:
    expires_at = str(int(time.time()) + expiration_seconds)
    data_with_expiry = f"{data}:{expires_at}"

    salt = os.urandom(16)  # Random salt for key derivation
    key = derive_key(password, salt)

    nonce = os.urandom(12)  # GCM requires 12-byte nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data_with_expiry.encode()) \
        + encryptor.finalize()

    # Combine salt, nonce, ciphertext, and tag for storage
    encrypted_data = salt + nonce + ciphertext + encryptor.tag
    return base64.urlsafe_b64encode(encrypted_data).decode()


def decrypt(token: str, password: str) -> str:
    encrypted_data = base64.urlsafe_b64decode(token.encode())

    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:-16]
    tag = encrypted_data[-16:]

    key = derive_key(password, salt)

    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    data, expires_at = decrypted_data.decode().rsplit(":", 1)
    if int(expires_at) < time.time():
        raise ValueError("Token expired")
    return data


async def generate_csrf_token(form_id: str) -> str:
    return encrypt(form_id, settings.CSRF_KEY)


async def validate_csrf_token(payload_id: str, csrf_token: str):
    try:
        decrypted_id = decrypt(csrf_token, settings.CSRF_KEY)
        if payload_id != decrypted_id:
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    except Exception:
        # TODO: Log the error for debugging
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def csrf_protected():
    '''
    Usage:
        @app.post('/')
        def func(
            _=csrf_protected(),
            x_csrf_token: Annotated[str | None, Header()] = None,
            x_payload_id: Annotated[str | None, Header()] = None
        ):
    '''
    async def dependency(request: Request):
        csrf_token = request.headers.get("X-CSRF-Token")
        payload_id = request.headers.get("X-PAYLOAD-ID")

        if not payload_id or not csrf_token:
            raise HTTPException(
                status_code=400, detail="Missing CSRF protection fields"
            )

        await validate_csrf_token(payload_id, csrf_token)

    return Depends(dependency)
