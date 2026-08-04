"""Envelope encryption for BitLocker Manager (SR1: no plaintext keys at rest).

Model
-----
* Each stored key gets its own random 256-bit **data key (DEK)**.
* The key material is encrypted with the DEK using AES-256-GCM (authenticated).
* The DEK is then **wrapped** (encrypted) by the **key-encryption key (KEK)**.
* Only the wrapped DEK and the ciphertext are persisted. Plaintext exists only
  in memory, only at enrol / provision / reveal time.

The KEK lives behind ``KekProvider`` so it is pluggable (spec ``IKekProvider``):
``SoftwareKekProvider`` is the v1 default; a TPM/HSM provider can drop in later
without touching callers.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_DEK_LEN = 32
_AAD_MATERIAL = b"blm:key-material"
_AAD_DEK = b"blm:dek-wrap"


class KekProvider(ABC):
    """Wraps/unwraps data keys. The KEK itself never leaves the provider."""

    @abstractmethod
    def wrap_dek(self, dek: bytes) -> bytes: ...

    @abstractmethod
    def unwrap_dek(self, wrapped: bytes) -> bytes: ...


class SoftwareKekProvider(KekProvider):
    """v1 software KEK: derived from a master passphrase via Argon2id.

    In production the passphrase is unlocked by operator auth (SR6) and the salt
    is stored alongside the vault config. A TPM/HSM provider replaces this later.
    """

    def __init__(self, passphrase: bytes, salt: bytes,
                 *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4):
        if len(salt) < 16:
            raise ValueError("KEK salt must be at least 16 bytes")
        self._kek = hash_secret_raw(
            secret=passphrase, salt=salt,
            time_cost=time_cost, memory_cost=memory_cost,
            parallelism=parallelism, hash_len=_DEK_LEN, type=Type.ID,
        )

    def wrap_dek(self, dek: bytes) -> bytes:
        nonce = os.urandom(_NONCE_LEN)
        return nonce + AESGCM(self._kek).encrypt(nonce, dek, _AAD_DEK)

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        nonce, ct = wrapped[:_NONCE_LEN], wrapped[_NONCE_LEN:]
        return AESGCM(self._kek).decrypt(nonce, ct, _AAD_DEK)


def encrypt_key_material(plaintext: str, kek: KekProvider) -> tuple[bytes, bytes]:
    """Return (encrypted_material, wrapped_dek) for storage."""
    dek = os.urandom(_DEK_LEN)
    nonce = os.urandom(_NONCE_LEN)
    encrypted_material = nonce + AESGCM(dek).encrypt(nonce, plaintext.encode(), _AAD_MATERIAL)
    wrapped_dek = kek.wrap_dek(dek)
    return encrypted_material, wrapped_dek


def decrypt_key_material(encrypted_material: bytes, wrapped_dek: bytes, kek: KekProvider) -> str:
    """Recover plaintext key material. Raises on tamper or wrong KEK."""
    dek = kek.unwrap_dek(wrapped_dek)
    nonce, ct = encrypted_material[:_NONCE_LEN], encrypted_material[_NONCE_LEN:]
    return AESGCM(dek).decrypt(nonce, ct, _AAD_MATERIAL).decode()
