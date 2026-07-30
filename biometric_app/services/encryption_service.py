from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
from ctypes import wintypes
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from biometric_app.config import AES_KEY_PATH


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class EncryptionService:
    """AES-256-GCM biometric encryption with a Windows DPAPI-protected key."""

    MAGIC = b"BAE1"
    AAD = b"BioAccess biometric payload v1"
    NONCE_SIZE = 12
    KEY_SIZE = 32
    DPAPI_ENTROPY = b"BioAccess DPAPI key protection v1"
    DPAPI_UI_FORBIDDEN = 0x1
    DPAPI_LOCAL_MACHINE = 0x4

    def __init__(self, key: bytes | None = None, key_path: Path = AES_KEY_PATH) -> None:
        self.key_path = Path(key_path)
        self._key = key or self._load_key_from_environment() or self._load_or_create_dpapi_key()
        if len(self._key) != self.KEY_SIZE:
            raise ValueError("BIOMETRIC_AES256_KEY must decode to exactly 32 bytes.")
        self._cipher = AESGCM(self._key)

    def encrypt_json(self, payload: list[float] | dict) -> bytes:
        return self.encrypt_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def decrypt_json(self, encrypted_payload: bytes) -> list[float] | dict:
        try:
            return json.loads(self.decrypt_bytes(encrypted_payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Decrypted biometric JSON payload is invalid.") from exc

    def encrypt_bytes(self, payload: bytes) -> bytes:
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, payload, self.AAD)
        return self.MAGIC + nonce + ciphertext

    def decrypt_bytes(self, encrypted_payload: bytes) -> bytes:
        if not encrypted_payload.startswith(self.MAGIC):
            raise ValueError("Biometric payload is not in the AES-256-GCM format.")
        nonce_start = len(self.MAGIC)
        nonce_end = nonce_start + self.NONCE_SIZE
        if len(encrypted_payload) <= nonce_end:
            raise ValueError("Encrypted biometric payload is incomplete.")
        try:
            return self._cipher.decrypt(encrypted_payload[nonce_start:nonce_end], encrypted_payload[nonce_end:], self.AAD)
        except Exception as exc:
            raise ValueError("Biometric integrity verification failed.") from exc

    def close(self) -> None:
        self._cipher = None
        self._key = b""

    @staticmethod
    def _load_key_from_environment() -> bytes | None:
        encoded = os.getenv("BIOMETRIC_AES256_KEY", "").strip()
        if not encoded:
            return None
        try:
            return base64.urlsafe_b64decode(encoded)
        except Exception as exc:
            raise ValueError("BIOMETRIC_AES256_KEY is not valid URL-safe base64.") from exc

    def _load_or_create_dpapi_key(self) -> bytes:
        if os.name != "nt":
            raise RuntimeError("Windows DPAPI is required unless BIOMETRIC_AES256_KEY is set.")
        if self.key_path.exists():
            return self._dpapi_unprotect(self.key_path.read_bytes())
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(self.KEY_SIZE)
        protected = self._dpapi_protect(key)
        temporary_path = self.key_path.with_suffix(self.key_path.suffix + ".tmp")
        temporary_path.write_bytes(protected)
        os.replace(temporary_path, self.key_path)
        return key

    @classmethod
    def _blob(cls, data: bytes) -> tuple[_DataBlob, ctypes.Array]:
        buffer = ctypes.create_string_buffer(data)
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer

    @classmethod
    def _dpapi_protect(cls, data: bytes) -> bytes:
        source, source_buffer = cls._blob(data)
        entropy, entropy_buffer = cls._blob(cls.DPAPI_ENTROPY)
        output = _DataBlob()
        flags = cls.DPAPI_UI_FORBIDDEN | cls.DPAPI_LOCAL_MACHINE
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), "BioAccess AES-256 key", ctypes.byref(entropy), None, None, flags, ctypes.byref(output)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output.pbData)
            del source_buffer, entropy_buffer

    @classmethod
    def _dpapi_unprotect(cls, protected: bytes) -> bytes:
        source, source_buffer = cls._blob(protected)
        entropy, entropy_buffer = cls._blob(cls.DPAPI_ENTROPY)
        output = _DataBlob()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, ctypes.byref(entropy), None, None, cls.DPAPI_UI_FORBIDDEN, ctypes.byref(output)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output.pbData)
            del source_buffer, entropy_buffer
