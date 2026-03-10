import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedValue:
    ciphertext: str
    nonce: str
    key_version: str


class KeyProvider(Protocol):
    def get_key(self, key_version: str | None = None) -> tuple[str, bytes]:
        ...


class LocalKeyProvider:
    def __init__(self, key: bytes | None = None, key_version: str = "local-dev"):
        self._key = key or AESGCM.generate_key(bit_length=256)
        self._key_version = key_version

    def get_key(self, key_version: str | None = None) -> tuple[str, bytes]:
        if key_version and key_version != self._key_version:
            raise CryptoError(f"Unknown local key version: {key_version}")
        return self._key_version, self._key


class EnvironmentKeyProvider:
    def __init__(
        self,
        key_env_var: str = "PII_AES_KEY",
        key_version_env_var: str = "PII_AES_KEY_VERSION",
    ):
        self.key_env_var = key_env_var
        self.key_version_env_var = key_version_env_var

    def get_key(self, key_version: str | None = None) -> tuple[str, bytes]:
        configured_key_version = os.getenv(self.key_version_env_var, "env-v1")
        if key_version and key_version != configured_key_version:
            raise CryptoError(f"Requested key version {key_version} is not available")

        encoded_key = os.getenv(self.key_env_var)
        if not encoded_key:
            raise CryptoError(
                f"Missing AES-GCM key in environment variable {self.key_env_var}"
            )

        try:
            key = base64.urlsafe_b64decode(encoded_key)
        except Exception as exc:  # pragma: no cover - defensive decode path
            raise CryptoError("Configured AES-GCM key is not valid base64") from exc

        if len(key) not in {16, 24, 32}:
            raise CryptoError("AES-GCM key must decode to 16, 24, or 32 bytes")

        return configured_key_version, key


class FileKeyProvider:
    def __init__(self, file_path: str, current_key_version: str | None = None):
        self.file_path = Path(file_path)
        self.current_key_version = current_key_version

    def get_key(self, key_version: str | None = None) -> tuple[str, bytes]:
        config = self._load_config()
        resolved_key_version = key_version or self.current_key_version or config.get(
            "current_key_version"
        )
        if not resolved_key_version:
            raise CryptoError("Key file is missing current_key_version")

        keys = config.get("keys", {})
        encoded_key = keys.get(resolved_key_version)
        if not encoded_key:
            raise CryptoError(
                f"Key version {resolved_key_version} was not found in {self.file_path}"
            )

        try:
            key = base64.urlsafe_b64decode(encoded_key)
        except Exception as exc:  # pragma: no cover - defensive decode path
            raise CryptoError("Key file contains an invalid base64 key") from exc

        if len(key) not in {16, 24, 32}:
            raise CryptoError("Key file must contain AES keys of 16, 24, or 32 bytes")

        return resolved_key_version, key

    def _load_config(self) -> dict:
        if not self.file_path.exists():
            raise CryptoError(f"Key file does not exist: {self.file_path}")

        try:
            return json.loads(self.file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CryptoError(f"Key file is not valid JSON: {self.file_path}") from exc


def create_key_file(file_path: str, key_version: str = "local-file-v1") -> str:
    path = Path(file_path)
    if path.exists():
        raise CryptoError(f"Refusing to overwrite existing key file: {path}")

    config = {
        "current_key_version": key_version,
        "keys": {
            key_version: generate_key_base64(),
        },
    }
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return str(path)


class AesGcmCipher:
    def __init__(self, key_provider: KeyProvider):
        self.key_provider = key_provider

    def encrypt(self, plaintext: str) -> EncryptedValue:
        key_version, key = self.key_provider.get_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return EncryptedValue(
            ciphertext=_urlsafe_encode(ciphertext),
            nonce=_urlsafe_encode(nonce),
            key_version=key_version,
        )

    def decrypt(self, ciphertext: str, nonce: str, key_version: str) -> str:
        _, key = self.key_provider.get_key(key_version)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(
                _urlsafe_decode(nonce),
                _urlsafe_decode(ciphertext),
                None,
            )
        except Exception as exc:  # pragma: no cover - library error wrapping
            raise CryptoError("Unable to decrypt token value") from exc

        return plaintext.decode("utf-8")


def generate_key_base64() -> str:
    return _urlsafe_encode(AESGCM.generate_key(bit_length=256))


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))