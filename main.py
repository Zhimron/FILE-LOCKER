from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from datetime import datetime
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - used only when dependency is missing.
    InvalidTag = None
    AESGCM = None
    ChaCha20Poly1305 = None
    Argon2id = None
    HKDF = None
    PBKDF2HMAC = None
    hashes = None
    CRYPTO_IMPORT_ERROR = exc


LEGACY_MAGIC = b"PYLOCKER1\n"
V2_MAGIC = b"PYLOCKER2\n"
MAGIC = LEGACY_MAGIC

LEGACY_FORMAT_VERSION = 1
V2_FORMAT_VERSION = 2
FORMAT_VERSION = V2_FORMAT_VERSION

LOCKED_SUFFIX = ".locked"
DEFAULT_CIPHER = "aes-256-gcm"
AES_GCM_CIPHER = "aes-256-gcm"
CHACHA20_POLY1305_CIPHER = "chacha20-poly1305"
SUPPORTED_CIPHERS = (AES_GCM_CIPHER, CHACHA20_POLY1305_CIPHER)

CHUNK_SIZE = 4 * 1024 * 1024
LEGACY_KDF_ITERATIONS = 600_000
ARGON2_MEMORY_KIB = int(os.environ.get("PYLOCKER_ARGON2_MEMORY_KIB", "65536"))
ARGON2_ITERATIONS = int(os.environ.get("PYLOCKER_ARGON2_ITERATIONS", "3"))
ARGON2_LANES = int(os.environ.get("PYLOCKER_ARGON2_LANES", "4"))
ARGON2_LENGTH = 32

SALT_BYTES = 16
NONCE_PREFIX_BYTES = 8
AEAD_NONCE_BYTES = 12
MAX_HEADER_BYTES = 64 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_FOOTER_BYTES = 64 * 1024
FOOTER_NONCE = b"footer-v2-00"

DEFAULT_MIN_PASSWORD_LENGTH = int(os.environ.get("PYLOCKER_MIN_PASSWORD_LENGTH", "12"))


class LockError(Exception):
    """Raised for expected lock/unlock failures."""


@dataclasses.dataclass(frozen=True)
class PasswordPolicy:
    """Configurable password policy used only when creating new encrypted data."""

    min_length: int = DEFAULT_MIN_PASSWORD_LENGTH
    require_upper: bool = False
    require_lower: bool = False
    require_digit: bool = False
    require_symbol: bool = False


@dataclasses.dataclass
class V2Envelope:
    salt: bytes
    metadata_nonce: bytes
    metadata_ciphertext: bytes

    @property
    def metadata_length(self) -> bytes:
        return struct.pack(">I", len(self.metadata_ciphertext))

    @property
    def metadata_aad(self) -> bytes:
        return V2_MAGIC + self.salt + self.metadata_nonce + self.metadata_length

    @property
    def record_aad_base(self) -> bytes:
        # The encrypted metadata is included in every later AAD value so metadata
        # replacement, chunk movement, truncation, or footer swapping is detected.
        return self.metadata_aad + self.metadata_ciphertext


@dataclasses.dataclass
class V2Keys:
    metadata_key: bytes
    data_key: bytes
    footer_key: bytes


def require_crypto() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise LockError(
            "Missing dependency: cryptography. Install it with "
            "`py -m pip install -r requirements.txt`."
        ) from CRYPTO_IMPORT_ERROR


def b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise LockError("The locked file is damaged or unsupported.") from exc


def read_exact(handle, size: int) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise LockError("The locked file is incomplete or damaged.")
    return data


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def safe_original_name(name: str) -> str:
    clean = Path(name).name
    if not clean or clean in {".", ".."}:
        raise LockError("The locked file has an unsafe original name.")
    return clean


def wipe_bytearray(value: bytearray | None) -> None:
    """Best-effort memory clearing for mutable buffers.

    Python strings and most bytes objects are immutable and may be copied by the
    interpreter or extension modules. This function clears only buffers that we
    control directly; it is a defense-in-depth step, not a forensic guarantee.
    """

    if value is None:
        return
    for index in range(len(value)):
        value[index] = 0


def password_to_buffer(password: str | bytes | bytearray) -> bytearray:
    if isinstance(password, bytearray):
        return bytearray(password)
    if isinstance(password, bytes):
        return bytearray(password)
    return bytearray(password.encode("utf-8"))


def validate_password_policy(password: str, policy: PasswordPolicy | None = None) -> None:
    policy = policy or PasswordPolicy()
    failures: list[str] = []
    if len(password) < policy.min_length:
        failures.append(f"at least {policy.min_length} characters")
    if policy.require_upper and not any(char.isupper() for char in password):
        failures.append("an uppercase letter")
    if policy.require_lower and not any(char.islower() for char in password):
        failures.append("a lowercase letter")
    if policy.require_digit and not any(char.isdigit() for char in password):
        failures.append("a number")
    if policy.require_symbol and not any(not char.isalnum() for char in password):
        failures.append("a symbol")
    if failures:
        raise LockError("Password must contain " + ", ".join(failures) + ".")


def read_key_file_secret(key_file: str | Path | None) -> bytearray | None:
    """Return a SHA-256 digest of the key file for use as Argon2id secret input."""

    if key_file is None:
        return None

    path = Path(key_file).expanduser()
    try:
        if path.is_symlink():
            raise LockError("Key files cannot be symlinks.")
        if not path.is_file():
            raise LockError("Key file does not exist or is not a file.")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        return bytearray(digest.digest())
    except LockError:
        raise
    except OSError as exc:
        raise LockError("Key file could not be read.") from exc


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def ensure_can_write(destination: Path, force: bool) -> None:
    if destination.exists() and destination.is_dir():
        raise LockError(f"Output is a folder, not a file: {destination}")
    if destination.exists() and not force:
        raise LockError(f"Output already exists: {destination}. Use --force to replace it.")
    destination.parent.mkdir(parents=True, exist_ok=True)


def default_locked_path(source: Path) -> Path:
    return source.with_name(source.name + LOCKED_SUFFIX)


def default_unlocked_path(locked_path: Path) -> Path:
    if locked_path.name.endswith(LOCKED_SUFFIX):
        return locked_path.with_name(locked_path.name[: -len(LOCKED_SUFFIX)])
    return locked_path.with_name(locked_path.stem)


def detect_file_version(path: Path) -> int:
    with path.open("rb") as handle:
        magic = read_exact(handle, len(V2_MAGIC))
    if magic == V2_MAGIC:
        return V2_FORMAT_VERSION
    if magic == LEGACY_MAGIC:
        return LEGACY_FORMAT_VERSION
    raise LockError("This is not a locked file created by this project.")


def normalize_cipher(cipher: str) -> str:
    normalized = cipher.lower().replace("_", "-")
    aliases = {
        "aes": AES_GCM_CIPHER,
        "aes-gcm": AES_GCM_CIPHER,
        "aes-256-gcm": AES_GCM_CIPHER,
        "chacha": CHACHA20_POLY1305_CIPHER,
        "chacha20": CHACHA20_POLY1305_CIPHER,
        "chacha20-poly1305": CHACHA20_POLY1305_CIPHER,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise LockError(f"Unsupported cipher. Choose one of: {', '.join(SUPPORTED_CIPHERS)}.") from exc


def make_aead(cipher: str, key: bytes):
    require_crypto()
    if cipher == AES_GCM_CIPHER:
        return AESGCM(key)
    if cipher == CHACHA20_POLY1305_CIPHER:
        return ChaCha20Poly1305(key)
    raise LockError("Unsupported cipher.")


def derive_master_key_v2(password: str | bytes | bytearray, salt: bytes, key_file: str | Path | None) -> bytearray:
    """Derive a memory-hard master key with Argon2id.

    The key file is hashed first and passed as Argon2id's secret parameter. That
    means both the password and key file are required, but the key file itself is
    never copied into memory in full.
    """

    require_crypto()
    password_buffer = password_to_buffer(password)
    key_file_secret = read_key_file_secret(key_file)
    master_key = bytearray(ARGON2_LENGTH)
    try:
        kdf = Argon2id(
            salt=salt,
            length=ARGON2_LENGTH,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
            secret=bytes(key_file_secret) if key_file_secret is not None else None,
        )
        kdf.derive_into(password_buffer, master_key)
        return master_key
    except Exception as exc:
        raise LockError("Authentication failed. Check the password, key file, or locked file integrity.") from exc
    finally:
        wipe_bytearray(password_buffer)
        wipe_bytearray(key_file_secret)


def derive_v2_keys(master_key: bytearray | bytes, cipher: str) -> V2Keys:
    require_crypto()
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=b"pylocker-v2-hkdf",
        info=b"pylocker-v2:" + cipher.encode("ascii"),
    ).derive(bytes(master_key))
    return V2Keys(
        metadata_key=key_material[:32],
        data_key=key_material[32:64],
        footer_key=key_material[64:96],
    )


def v2_chunk_nonce(metadata: dict, index: int) -> bytes:
    if index >= 2**32:
        raise LockError("This file is too large for the current lock format.")
    prefix = b64_decode(metadata["chunk_nonce_prefix"])
    if len(prefix) != NONCE_PREFIX_BYTES:
        raise LockError("The locked file is damaged or unsupported.")
    return prefix + index.to_bytes(4, "big")


def v2_record_aad(envelope: V2Envelope, index: int) -> bytes:
    return envelope.record_aad_base + b"record" + index.to_bytes(4, "big")


def v2_footer_aad(envelope: V2Envelope, chunk_count: int) -> bytes:
    return envelope.record_aad_base + b"footer" + chunk_count.to_bytes(4, "big")


def validate_v2_metadata(metadata: dict, expected_cipher: str) -> None:
    if metadata.get("version") != V2_FORMAT_VERSION:
        raise LockError("Unsupported locked file version.")
    if metadata.get("cipher") != expected_cipher:
        raise LockError("The locked file is damaged or unsupported.")
    if metadata.get("kind") not in {"file", "folder"}:
        raise LockError("The locked file type is not supported.")
    safe_original_name(str(metadata.get("name", "")))
    if metadata.get("compression") not in {"none", "zlib"}:
        raise LockError("The locked file compression mode is not supported.")
    if metadata.get("chunk_size") != CHUNK_SIZE:
        raise LockError("The locked file chunk size is not supported by this build.")
    if len(b64_decode(str(metadata.get("chunk_nonce_prefix", "")))) != NONCE_PREFIX_BYTES:
        raise LockError("The locked file is damaged or unsupported.")


def validate_v2_footer(footer: dict, expected_chunk_count: int) -> None:
    if footer.get("version") != V2_FORMAT_VERSION:
        raise LockError("The locked file footer is unsupported.")
    if footer.get("chunk_count") != expected_chunk_count:
        raise LockError("The locked file failed integrity verification.")
    if not isinstance(footer.get("payload_size"), int) or footer["payload_size"] < 0:
        raise LockError("The locked file failed integrity verification.")
    digest = footer.get("payload_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise LockError("The locked file failed integrity verification.")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise LockError("The locked file failed integrity verification.") from exc


def build_v2_metadata(
    kind: str,
    original_name: str,
    cipher: str,
    compression: str,
    key_file_required: bool,
    chunk_nonce_prefix: bytes,
) -> dict:
    return {
        "version": V2_FORMAT_VERSION,
        "kind": kind,
        "name": original_name,
        "created_at": int(time.time()),
        "cipher": cipher,
        "compression": compression,
        "chunk_size": CHUNK_SIZE,
        "chunk_nonce_prefix": b64_encode(chunk_nonce_prefix),
        "key_file_required": key_file_required,
        "kdf": {
            "name": "Argon2id",
            "memory_kib": ARGON2_MEMORY_KIB,
            "iterations": ARGON2_ITERATIONS,
            "lanes": ARGON2_LANES,
        },
    }


def read_v2_envelope(handle) -> V2Envelope:
    magic = read_exact(handle, len(V2_MAGIC))
    if magic != V2_MAGIC:
        raise LockError("This is not a v2 locked file.")
    salt = read_exact(handle, SALT_BYTES)
    metadata_nonce = read_exact(handle, AEAD_NONCE_BYTES)
    metadata_size = struct.unpack(">I", read_exact(handle, 4))[0]
    if metadata_size <= 16 or metadata_size > MAX_METADATA_BYTES:
        raise LockError("The locked file is damaged or unsupported.")
    metadata_ciphertext = read_exact(handle, metadata_size)
    return V2Envelope(salt=salt, metadata_nonce=metadata_nonce, metadata_ciphertext=metadata_ciphertext)


def decrypt_v2_metadata(envelope: V2Envelope, password: str | bytes | bytearray, key_file: str | Path | None) -> tuple[dict, V2Keys]:
    master_key = derive_master_key_v2(password, envelope.salt, key_file)
    try:
        for cipher in SUPPORTED_CIPHERS:
            keys = derive_v2_keys(master_key, cipher)
            try:
                plaintext = make_aead(cipher, keys.metadata_key).decrypt(
                    envelope.metadata_nonce,
                    envelope.metadata_ciphertext,
                    envelope.metadata_aad,
                )
            except InvalidTag:
                continue

            try:
                metadata = json.loads(plaintext.decode("utf-8"))
            except Exception as exc:
                raise LockError("The locked file is damaged or unsupported.") from exc
            validate_v2_metadata(metadata, cipher)
            return metadata, keys
    finally:
        wipe_bytearray(master_key)

    raise LockError("Authentication failed. Check the password, key file, or locked file integrity.")


def write_encrypted_record(handle, aead, nonce: bytes, plaintext: bytes, aad: bytes) -> None:
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    handle.write(struct.pack(">I", len(ciphertext)))
    handle.write(ciphertext)


def drain_encoded_buffer(
    handle,
    buffer: bytearray,
    aead,
    metadata: dict,
    envelope: V2Envelope,
    start_index: int,
) -> int:
    index = start_index
    while len(buffer) >= CHUNK_SIZE:
        chunk = bytes(buffer[:CHUNK_SIZE])
        del buffer[:CHUNK_SIZE]
        write_encrypted_record(handle, aead, v2_chunk_nonce(metadata, index), chunk, v2_record_aad(envelope, index))
        index += 1
    return index


def encrypt_payload_file_v2(
    source: Path,
    destination: Path,
    password: str,
    kind: str,
    original_name: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
    cipher: str = DEFAULT_CIPHER,
    compress: bool = False,
    password_policy: PasswordPolicy | None = None,
) -> None:
    require_crypto()
    validate_password_policy(password, password_policy)
    cipher = normalize_cipher(cipher)
    compression = "zlib" if compress else "none"
    if source.resolve() == destination.resolve(strict=False):
        raise LockError("Output must be different from the source path.")
    ensure_can_write(destination, force)

    salt = os.urandom(SALT_BYTES)
    metadata_nonce = os.urandom(AEAD_NONCE_BYTES)
    chunk_nonce_prefix = os.urandom(NONCE_PREFIX_BYTES)
    metadata = build_v2_metadata(
        kind=kind,
        original_name=original_name,
        cipher=cipher,
        compression=compression,
        key_file_required=key_file is not None,
        chunk_nonce_prefix=chunk_nonce_prefix,
    )
    metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")

    master_key = derive_master_key_v2(password, salt, key_file)
    try:
        keys = derive_v2_keys(master_key, cipher)
    finally:
        wipe_bytearray(master_key)

    metadata_length = struct.pack(">I", len(metadata_bytes) + 16)
    metadata_aad = V2_MAGIC + salt + metadata_nonce + metadata_length
    metadata_ciphertext = make_aead(cipher, keys.metadata_key).encrypt(metadata_nonce, metadata_bytes, metadata_aad)
    envelope = V2Envelope(salt=salt, metadata_nonce=metadata_nonce, metadata_ciphertext=metadata_ciphertext)

    data_aead = make_aead(cipher, keys.data_key)
    footer_aead = make_aead(cipher, keys.footer_key)
    temp_path: Path | None = None

    try:
        with source.open("rb") as src, tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=destination.parent,
            prefix=f"{destination.name}.tmp-",
        ) as tmp:
            temp_path = Path(tmp.name)
            tmp.write(V2_MAGIC)
            tmp.write(salt)
            tmp.write(metadata_nonce)
            tmp.write(struct.pack(">I", len(metadata_ciphertext)))
            tmp.write(metadata_ciphertext)

            digest = hashlib.sha256()
            payload_size = 0
            chunk_index = 0
            encoded_buffer = bytearray()
            compressor = zlib.compressobj(level=6) if compress else None

            while True:
                plaintext = src.read(CHUNK_SIZE)
                if not plaintext:
                    break
                digest.update(plaintext)
                payload_size += len(plaintext)
                encoded = compressor.compress(plaintext) if compressor else plaintext
                if encoded:
                    encoded_buffer.extend(encoded)
                    chunk_index = drain_encoded_buffer(tmp, encoded_buffer, data_aead, metadata, envelope, chunk_index)

            if compressor:
                encoded_buffer.extend(compressor.flush())
            while encoded_buffer:
                chunk = bytes(encoded_buffer[:CHUNK_SIZE])
                del encoded_buffer[:CHUNK_SIZE]
                write_encrypted_record(
                    tmp,
                    data_aead,
                    v2_chunk_nonce(metadata, chunk_index),
                    chunk,
                    v2_record_aad(envelope, chunk_index),
                )
                chunk_index += 1

            write_encrypted_record(
                tmp,
                data_aead,
                v2_chunk_nonce(metadata, chunk_index),
                b"",
                v2_record_aad(envelope, chunk_index),
            )

            footer = {
                "version": V2_FORMAT_VERSION,
                "payload_sha256": digest.hexdigest(),
                "payload_size": payload_size,
                "chunk_count": chunk_index,
            }
            footer_bytes = json.dumps(footer, sort_keys=True, separators=(",", ":")).encode("utf-8")
            footer_ciphertext = footer_aead.encrypt(FOOTER_NONCE, footer_bytes, v2_footer_aad(envelope, chunk_index))
            tmp.write(struct.pack(">I", len(footer_ciphertext)))
            tmp.write(footer_ciphertext)

        temp_path.replace(destination)
    except Exception:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def decrypt_payload_to_file_v2(
    locked_path: Path,
    destination: Path,
    password: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
) -> dict:
    require_crypto()
    ensure_can_write(destination, force)
    temp_path: Path | None = None

    try:
        with locked_path.open("rb") as src, tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=destination.parent,
            prefix=f"{destination.name}.tmp-",
        ) as tmp:
            temp_path = Path(tmp.name)
            envelope = read_v2_envelope(src)
            metadata, keys = decrypt_v2_metadata(envelope, password, key_file)
            data_aead = make_aead(metadata["cipher"], keys.data_key)
            footer_aead = make_aead(metadata["cipher"], keys.footer_key)
            decompressor = zlib.decompressobj() if metadata["compression"] == "zlib" else None
            digest = hashlib.sha256()
            payload_size = 0
            chunk_index = 0

            while True:
                raw_size = src.read(4)
                if raw_size == b"":
                    raise LockError("The locked file is incomplete or damaged.")
                if len(raw_size) != 4:
                    raise LockError("The locked file is incomplete or damaged.")
                size = struct.unpack(">I", raw_size)[0]
                if size < 16 or size > CHUNK_SIZE + 16:
                    raise LockError("The locked file is damaged or unsupported.")

                ciphertext = read_exact(src, size)
                try:
                    encoded = data_aead.decrypt(
                        v2_chunk_nonce(metadata, chunk_index),
                        ciphertext,
                        v2_record_aad(envelope, chunk_index),
                    )
                except InvalidTag as exc:
                    raise LockError("Authentication failed. Check the password, key file, or locked file integrity.") from exc

                if encoded == b"":
                    break

                if decompressor:
                    plaintext = decompressor.decompress(encoded)
                else:
                    plaintext = encoded
                if plaintext:
                    digest.update(plaintext)
                    payload_size += len(plaintext)
                    tmp.write(plaintext)
                chunk_index += 1

            if decompressor:
                tail = decompressor.flush()
                if tail:
                    digest.update(tail)
                    payload_size += len(tail)
                    tmp.write(tail)
                if not decompressor.eof:
                    raise LockError("The locked file failed integrity verification.")

            raw_footer_size = src.read(4)
            if len(raw_footer_size) != 4:
                raise LockError("The locked file is incomplete or damaged.")
            footer_size = struct.unpack(">I", raw_footer_size)[0]
            if footer_size <= 16 or footer_size > MAX_FOOTER_BYTES:
                raise LockError("The locked file is damaged or unsupported.")
            footer_ciphertext = read_exact(src, footer_size)
            if src.read(1):
                raise LockError("The locked file has unexpected data after the encrypted footer.")

            try:
                footer_bytes = footer_aead.decrypt(FOOTER_NONCE, footer_ciphertext, v2_footer_aad(envelope, chunk_index))
                footer = json.loads(footer_bytes.decode("utf-8"))
            except InvalidTag as exc:
                raise LockError("The locked file failed integrity verification.") from exc
            except Exception as exc:
                raise LockError("The locked file is damaged or unsupported.") from exc

            validate_v2_footer(footer, chunk_index)
            if footer["payload_size"] != payload_size or footer["payload_sha256"] != digest.hexdigest():
                raise LockError("The locked file failed integrity verification.")

        temp_path.replace(destination)
        return metadata
    except Exception:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def read_legacy_header(handle) -> tuple[dict, bytes]:
    magic = read_exact(handle, len(LEGACY_MAGIC))
    if magic != LEGACY_MAGIC:
        raise LockError("This is not a legacy locked file.")

    header_size = struct.unpack(">I", read_exact(handle, 4))[0]
    if header_size <= 0 or header_size > MAX_HEADER_BYTES:
        raise LockError("The locked file is damaged or unsupported.")

    header_bytes = read_exact(handle, header_size)
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise LockError("The locked file is damaged or unsupported.") from exc

    validate_legacy_header(header)
    aad = magic + struct.pack(">I", header_size) + header_bytes
    return header, aad


def validate_legacy_header(header: dict) -> None:
    if header.get("version") != LEGACY_FORMAT_VERSION:
        raise LockError("Unsupported locked file version.")
    if header.get("kind") not in {"file", "folder"}:
        raise LockError("The locked file type is not supported.")
    if header.get("cipher") != "AES-256-GCM-stream":
        raise LockError("The locked file cipher is not supported.")
    if header.get("kdf") != "PBKDF2-HMAC-SHA256":
        raise LockError("The locked file key format is not supported.")
    safe_original_name(str(header.get("name", "")))
    if not isinstance(header.get("iterations"), int) or header["iterations"] < 100_000:
        raise LockError("The locked file key settings are invalid.")
    if not isinstance(header.get("chunk_size"), int) or header["chunk_size"] <= 0:
        raise LockError("The locked file chunk settings are invalid.")
    if len(b64_decode(str(header.get("salt", "")))) != SALT_BYTES:
        raise LockError("The locked file salt is invalid.")
    if len(b64_decode(str(header.get("nonce_prefix", "")))) != NONCE_PREFIX_BYTES:
        raise LockError("The locked file nonce is invalid.")


def derive_legacy_key(password: str, header: dict) -> bytes:
    require_crypto()
    salt = b64_decode(header["salt"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=header["iterations"],
    )
    return kdf.derive(password.encode("utf-8"))


def legacy_nonce_for(header: dict, index: int) -> bytes:
    if index >= 2**32:
        raise LockError("This file is too large for the legacy lock format.")
    return b64_decode(header["nonce_prefix"]) + index.to_bytes(4, "big")


def read_legacy_metadata(path: Path) -> dict:
    with path.open("rb") as handle:
        header, _aad = read_legacy_header(handle)
        return header


def decrypt_payload_to_file_legacy(locked_path: Path, destination: Path, password: str, force: bool) -> dict:
    require_crypto()
    ensure_can_write(destination, force)
    temp_path: Path | None = None

    try:
        with locked_path.open("rb") as src, tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=destination.parent,
            prefix=f"{destination.name}.tmp-",
        ) as tmp:
            temp_path = Path(tmp.name)
            header, aad = read_legacy_header(src)
            key = derive_legacy_key(password, header)
            aesgcm = AESGCM(key)

            index = 0
            while True:
                raw_size = src.read(4)
                if raw_size == b"":
                    raise LockError("The locked file is incomplete or damaged.")
                if len(raw_size) != 4:
                    raise LockError("The locked file is incomplete or damaged.")

                size = struct.unpack(">I", raw_size)[0]
                if size < 16:
                    raise LockError("The locked file has an invalid encrypted chunk.")

                ciphertext = read_exact(src, size)
                try:
                    chunk = aesgcm.decrypt(legacy_nonce_for(header, index), ciphertext, aad)
                except InvalidTag as exc:
                    raise LockError("Authentication failed. Check the password or locked file integrity.") from exc

                if chunk == b"":
                    trailing = src.read(1)
                    if trailing:
                        raise LockError("The locked file has unexpected data after the end marker.")
                    break

                tmp.write(chunk)
                index += 1

        temp_path.replace(destination)
        return header
    except Exception:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def decrypt_payload_to_file(
    locked_path: Path,
    destination: Path,
    password: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
) -> dict:
    version = detect_file_version(locked_path)
    if version == LEGACY_FORMAT_VERSION:
        if key_file is not None:
            raise LockError("Legacy locked files do not support key-file authentication.")
        return decrypt_payload_to_file_legacy(locked_path, destination, password, force)
    return decrypt_payload_to_file_v2(locked_path, destination, password, force, key_file=key_file)


def read_locked_metadata(
    path: Path,
    password: str | None = None,
    *,
    key_file: str | Path | None = None,
) -> dict:
    version = detect_file_version(path)
    if version == LEGACY_FORMAT_VERSION:
        return read_legacy_metadata(path)

    if password is None:
        return {
            "version": V2_FORMAT_VERSION,
            "kind": "encrypted",
            "name": default_unlocked_path(path).name,
            "cipher": "encrypted",
            "kdf": "Argon2id",
            "metadata_encrypted": True,
            "created_at": None,
        }

    with path.open("rb") as handle:
        envelope = read_v2_envelope(handle)
    metadata, _keys = decrypt_v2_metadata(envelope, password, key_file)
    return metadata


def make_folder_archive(folder: Path, temp_root: Path) -> Path:
    """Create a deterministic, no-symlink ZIP payload for folder locking."""

    archive_path = temp_root / f"{folder.name}.zip"
    root = folder.resolve(strict=True)
    root_name = safe_original_name(folder.name)

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        root_info = zipfile.ZipInfo(f"{root_name}/")
        root_info.external_attr = (stat.S_IFDIR | 0o700) << 16
        archive.writestr(root_info, b"")

        for current_dir, dir_names, file_names in os.walk(root, topdown=True, followlinks=False):
            current = Path(current_dir)

            for dir_name in list(dir_names):
                directory = current / dir_name
                if directory.is_symlink():
                    raise LockError("Folders containing symlinks cannot be locked safely.")
                rel_dir = directory.relative_to(root)
                info = zipfile.ZipInfo(str(Path(root_name) / rel_dir).replace("\\", "/") + "/")
                info.external_attr = (stat.S_IFDIR | 0o700) << 16
                archive.writestr(info, b"")

            for file_name in file_names:
                file_path = current / file_name
                if file_path.is_symlink():
                    raise LockError("Folders containing symlinks cannot be locked safely.")
                try:
                    file_stat = os.stat(file_path, follow_symlinks=False)
                except OSError as exc:
                    raise LockError(f"Could not read folder item: {file_path}") from exc
                if not stat.S_ISREG(file_stat.st_mode):
                    raise LockError("Only regular files can be stored inside locked folders.")

                rel_file = file_path.relative_to(root)
                arcname = str(Path(root_name) / rel_file).replace("\\", "/")
                info = zipfile.ZipInfo(arcname, time.localtime(file_stat.st_mtime)[:6])
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.file_size = file_stat.st_size
                info.compress_type = zipfile.ZIP_STORED
                with file_path.open("rb") as src, archive.open(info, "w") as dst:
                    shutil.copyfileobj(src, dst, length=CHUNK_SIZE)

    return archive_path


def validate_zip_member(member_name: str, target_root: Path) -> Path:
    if not member_name:
        raise LockError("The folder archive contains an invalid empty path.")
    if ":" in member_name:
        raise LockError("The folder archive contains an unsafe path.")

    member_path = Path(member_name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise LockError("The folder archive contains an unsafe path.")

    destination = (target_root / member_name).resolve(strict=False)
    if not is_relative_to(destination, target_root):
        raise LockError("The folder archive contains a path outside the output folder.")
    return destination


def is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def safe_extract_zip(zip_path: Path, target_root: Path) -> None:
    target_root.mkdir(parents=True, exist_ok=True)
    resolved_root = target_root.resolve(strict=False)
    seen: set[Path] = set()

    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if is_zip_symlink(info):
                raise LockError("The folder archive contains an unsafe symlink.")
            destination = validate_zip_member(info.filename, resolved_root)
            if destination in seen:
                raise LockError("The folder archive contains duplicate paths.")
            seen.add(destination)

        for info in archive.infolist():
            destination = validate_zip_member(info.filename, resolved_root)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=CHUNK_SIZE)


def extract_folder_archive(zip_path: Path, destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        raise LockError(f"Output already exists: {destination}. Use --force to replace it.")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="pylocker-extract-") as temp_dir:
        extract_root = Path(temp_dir) / "root"
        safe_extract_zip(zip_path, extract_root)
        entries = list(extract_root.iterdir())

        if not entries:
            staged_folder = extract_root / destination.name
            staged_folder.mkdir()
        elif len(entries) == 1 and entries[0].is_dir():
            staged_folder = entries[0]
        else:
            staged_folder = extract_root

        if destination.exists():
            remove_path(destination)
        shutil.move(str(staged_folder), str(destination))


def secure_delete_file(path: Path) -> None:
    """Best-effort overwrite before unlinking.

    This helps on simple magnetic-disk cases. SSD wear leveling, journaling file
    systems, cloud sync, backups, snapshots, and antivirus quarantine can retain
    previous data elsewhere, so documentation must not promise forensic erasure.
    """

    flags = os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        file_stat = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(file_stat.st_mode):
            path.unlink()
            return

        fd = os.open(path, flags)
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise LockError("Refusing to overwrite a non-regular file.")
            remaining = opened_stat.st_size
            os.lseek(fd, 0, os.SEEK_SET)
            zero_chunk = b"\x00" * min(CHUNK_SIZE, 1024 * 1024)
            while remaining > 0:
                written = os.write(fd, zero_chunk[: min(len(zero_chunk), remaining)])
                if written <= 0:
                    raise LockError("Could not overwrite file before deletion.")
                remaining -= written
            os.fsync(fd)
        finally:
            os.close(fd)
        path.unlink()
    except OSError as exc:
        raise LockError(f"Secure deletion failed for: {path}") from exc


def secure_delete_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        for current_dir, dir_names, file_names in os.walk(path, topdown=False, followlinks=False):
            current = Path(current_dir)
            for file_name in file_names:
                secure_delete_file(current / file_name)
            for dir_name in dir_names:
                directory = current / dir_name
                if directory.is_symlink():
                    directory.unlink()
                else:
                    directory.rmdir()
        path.rmdir()
    else:
        secure_delete_file(path)


def delete_original_after_lock(path: Path, secure_delete: bool) -> None:
    if secure_delete:
        secure_delete_path(path)
    else:
        remove_path(path)


def stat_identity(path: Path) -> tuple[int, int, int, int]:
    file_stat = os.stat(path, follow_symlinks=False)
    return (file_stat.st_dev, file_stat.st_ino, file_stat.st_size, file_stat.st_mtime_ns)


def lock_path(
    source: Path,
    destination: Path,
    password: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
    cipher: str = DEFAULT_CIPHER,
    compress: bool = False,
    secure_delete: bool = False,
    password_policy: PasswordPolicy | None = None,
) -> None:
    if not source.exists():
        raise LockError(f"Path does not exist: {source}")
    if source.is_symlink():
        raise LockError("Symlinks are not supported.")

    destination = destination.resolve(strict=False)
    if source.is_dir():
        if is_relative_to(destination, source):
            raise LockError("Folder output cannot be inside the folder being locked.")

        with tempfile.TemporaryDirectory(prefix="pylocker-archive-") as temp_dir:
            archive_path = make_folder_archive(source, Path(temp_dir))
            encrypt_payload_file_v2(
                archive_path,
                destination,
                password,
                kind="folder",
                original_name=source.name,
                force=force,
                key_file=key_file,
                cipher=cipher,
                compress=compress,
                password_policy=password_policy,
            )
        delete_original_after_lock(source, secure_delete)
        return

    if source.is_file():
        before_identity = stat_identity(source)
        encrypt_payload_file_v2(
            source,
            destination,
            password,
            kind="file",
            original_name=source.name,
            force=force,
            key_file=key_file,
            cipher=cipher,
            compress=compress,
            password_policy=password_policy,
        )
        if stat_identity(source) != before_identity:
            raise LockError("Source changed during locking. The encrypted file was created, but the original was kept.")
        delete_original_after_lock(source, secure_delete)
        return

    raise LockError("Only regular files and folders can be locked.")


def unlock_path(
    locked_path: Path,
    destination: Path | None,
    password: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
) -> Path:
    if not locked_path.exists() or not locked_path.is_file():
        raise LockError(f"Locked file does not exist: {locked_path}")

    metadata = read_locked_metadata(locked_path, password, key_file=key_file)
    original_name = safe_original_name(metadata["name"])
    output = destination or locked_path.with_name(original_name)
    output = output.resolve(strict=False)

    if metadata["kind"] == "file":
        decrypt_payload_to_file(locked_path, output, password, force, key_file=key_file)
        return output

    with tempfile.TemporaryDirectory(prefix="pylocker-unlock-") as temp_dir:
        zip_path = Path(temp_dir) / "payload.zip"
        decrypt_payload_to_file(locked_path, zip_path, password, force=True, key_file=key_file)
        extract_folder_archive(zip_path, output, force)
    return output


def decrypt_for_open(
    locked_path: Path,
    temp_root: Path,
    password: str,
    *,
    key_file: str | Path | None = None,
) -> Path:
    metadata = read_locked_metadata(locked_path, password, key_file=key_file)
    original_name = safe_original_name(metadata["name"])

    if metadata["kind"] == "file":
        output = temp_root / original_name
        decrypt_payload_to_file(locked_path, output, password, force=True, key_file=key_file)
        return output

    zip_path = temp_root / "payload.zip"
    folder_output = temp_root / original_name
    decrypt_payload_to_file(locked_path, zip_path, password, force=True, key_file=key_file)
    extract_folder_archive(zip_path, folder_output, force=True)
    zip_path.unlink(missing_ok=True)
    return folder_output


def migrate_locked_file(
    locked_path: Path,
    destination: Path | None,
    password: str,
    force: bool,
    *,
    key_file: str | Path | None = None,
    cipher: str = DEFAULT_CIPHER,
    compress: bool = False,
    password_policy: PasswordPolicy | None = None,
) -> Path:
    if not locked_path.exists() or not locked_path.is_file():
        raise LockError(f"Locked file does not exist: {locked_path}")

    metadata = read_locked_metadata(locked_path, password, key_file=key_file)
    output = destination or locked_path.with_name(locked_path.name + ".v2")

    with tempfile.TemporaryDirectory(prefix="pylocker-migrate-") as temp_dir:
        payload_path = Path(temp_dir) / "payload.bin"
        decrypt_payload_to_file(locked_path, payload_path, password, force=True, key_file=key_file)
        encrypt_payload_file_v2(
            payload_path,
            output,
            password,
            kind=metadata["kind"],
            original_name=safe_original_name(metadata["name"]),
            force=force,
            key_file=key_file,
            cipher=cipher,
            compress=compress,
            password_policy=password_policy,
        )
    return output


def open_with_default_app(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def created_time(header: dict) -> str:
    created_at = header.get("created_at")
    if not isinstance(created_at, int):
        return "unknown"
    return datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M:%S")


def prompt_password(confirm: bool) -> str:
    while True:
        password = getpass.getpass("Password: ")
        if not password:
            print("Password cannot be empty.")
            continue
        if confirm:
            repeated = getpass.getpass("Confirm password: ")
            if password != repeated:
                print("Passwords do not match.")
                continue
        return password


def get_password(args, confirm: bool) -> str:
    if getattr(args, "password", None) is not None:
        if not args.password:
            raise LockError("--password cannot be empty.")
        return args.password
    return prompt_password(confirm)


def password_policy_from_args(args) -> PasswordPolicy:
    return PasswordPolicy(
        min_length=args.min_password_length,
        require_upper=args.require_upper,
        require_lower=args.require_lower,
        require_digit=args.require_digit,
        require_symbol=args.require_symbol,
    )


def cmd_lock(args) -> int:
    source = Path(args.path).expanduser()
    destination = Path(args.output).expanduser() if args.output else default_locked_path(source)
    password = get_password(args, confirm=True)
    lock_path(
        source,
        destination,
        password,
        args.force,
        key_file=args.key_file,
        cipher=args.cipher,
        compress=args.compress,
        secure_delete=args.secure_delete,
        password_policy=password_policy_from_args(args),
    )
    print(f"Locked: {source}")
    print(f"Created: {destination}")
    return 0


def cmd_unlock(args) -> int:
    locked_path = Path(args.path).expanduser()
    destination = Path(args.output).expanduser() if args.output else None
    password = get_password(args, confirm=False)
    output = unlock_path(locked_path, destination, password, args.force, key_file=args.key_file)
    print(f"Unlocked to: {output}")
    return 0


def cmd_open(args) -> int:
    locked_path = Path(args.path).expanduser()
    if not locked_path.exists():
        raise LockError(f"Locked file does not exist: {locked_path}")

    password = get_password(args, confirm=False)

    if args.keep:
        temp_root = Path(tempfile.mkdtemp(prefix="pylocker-open-"))
        opened_path = decrypt_for_open(locked_path, temp_root, password, key_file=args.key_file)
        open_with_default_app(opened_path)
        print(f"Opened: {opened_path}")
        print(f"Temporary decrypted copy kept at: {temp_root}")
        return 0

    with tempfile.TemporaryDirectory(prefix="pylocker-open-") as temp_dir:
        temp_root = Path(temp_dir)
        opened_path = decrypt_for_open(locked_path, temp_root, password, key_file=args.key_file)
        open_with_default_app(opened_path)
        print(f"Opened: {opened_path}")
        input("Press Enter after closing the viewer/player to remove the temporary copy...")
    return 0


def cmd_info(args) -> int:
    locked_path = Path(args.path).expanduser()
    if detect_file_version(locked_path) == V2_FORMAT_VERSION:
        password = get_password(args, confirm=False)
        header = read_locked_metadata(locked_path, password, key_file=args.key_file)
    else:
        header = read_locked_metadata(locked_path)
    print(f"Version: {header['version']}")
    print(f"Type: {header['kind']}")
    print(f"Original name: {header['name']}")
    print(f"Created: {created_time(header)}")
    print(f"Cipher: {header['cipher']}")
    if isinstance(header.get("kdf"), dict):
        kdf = header["kdf"]
        print(f"KDF: {kdf['name']} ({kdf['memory_kib']} KiB, {kdf['iterations']} iterations, {kdf['lanes']} lanes)")
    else:
        print(f"KDF: {header['kdf']} ({header.get('iterations', 'unknown')} iterations)")
    if "compression" in header:
        print(f"Compression: {header['compression']}")
    if "key_file_required" in header:
        print(f"Key file required: {header['key_file_required']}")
    return 0


def cmd_migrate(args) -> int:
    locked_path = Path(args.path).expanduser()
    destination = Path(args.output).expanduser() if args.output else None
    password = get_password(args, confirm=False)
    output = migrate_locked_file(
        locked_path,
        destination,
        password,
        args.force,
        key_file=args.key_file,
        cipher=args.cipher,
        compress=args.compress,
        password_policy=password_policy_from_args(args),
    )
    print(f"Migrated to: {output}")
    return 0


def add_password_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--password",
        help="Use this password instead of prompting. This is convenient but can expose it in shell history.",
    )


def add_key_file_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--key-file", help="Optional key file required together with the password.")


def add_password_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--min-password-length", type=int, default=DEFAULT_MIN_PASSWORD_LENGTH)
    parser.add_argument("--require-upper", action="store_true")
    parser.add_argument("--require-lower", action="store_true")
    parser.add_argument("--require-digit", action="store_true")
    parser.add_argument("--require-symbol", action="store_true")


def add_v2_write_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cipher", choices=SUPPORTED_CIPHERS, default=DEFAULT_CIPHER)
    parser.add_argument("--compress", action="store_true", help="Compress the payload before encryption.")
    add_password_policy_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lock files or folders so they cannot be opened normally.",
    )
    subparsers = parser.add_subparsers(dest="command")

    lock_parser = subparsers.add_parser("lock", help="Encrypt and remove the original file/folder.")
    lock_parser.add_argument("path", help="File or folder to lock.")
    lock_parser.add_argument("-o", "--output", help="Locked output path. Default: <name>.locked")
    lock_parser.add_argument("-f", "--force", action="store_true", help="Replace an existing output file.")
    lock_parser.add_argument(
        "--secure-delete",
        action="store_true",
        help="Best-effort overwrite before removing the original. Not reliable on SSDs or snapshots.",
    )
    add_password_argument(lock_parser)
    add_key_file_argument(lock_parser)
    add_v2_write_arguments(lock_parser)
    lock_parser.set_defaults(func=cmd_lock)

    unlock_parser = subparsers.add_parser("unlock", help="Restore a locked file/folder permanently.")
    unlock_parser.add_argument("path", help="Locked file created by this project.")
    unlock_parser.add_argument("-o", "--output", help="Output path. Default: original name beside the locked file.")
    unlock_parser.add_argument("-f", "--force", action="store_true", help="Replace an existing output path.")
    add_password_argument(unlock_parser)
    add_key_file_argument(unlock_parser)
    unlock_parser.set_defaults(func=cmd_unlock)

    open_parser = subparsers.add_parser("open", help="Open/play a locked item through a temporary decrypted copy.")
    open_parser.add_argument("path", help="Locked file created by this project.")
    open_parser.add_argument("--keep", action="store_true", help="Keep the temporary decrypted copy after opening.")
    add_password_argument(open_parser)
    add_key_file_argument(open_parser)
    open_parser.set_defaults(func=cmd_open)

    info_parser = subparsers.add_parser("info", help="Show metadata for a locked file.")
    info_parser.add_argument("path", help="Locked file created by this project.")
    add_password_argument(info_parser)
    add_key_file_argument(info_parser)
    info_parser.set_defaults(func=cmd_info)

    migrate_parser = subparsers.add_parser("migrate", help="Rewrite a locked file using the current v2 format.")
    migrate_parser.add_argument("path", help="Locked file to migrate.")
    migrate_parser.add_argument("-o", "--output", help="Migrated output path. Default: <locked-file>.v2")
    migrate_parser.add_argument("-f", "--force", action="store_true", help="Replace an existing output file.")
    add_password_argument(migrate_parser)
    add_key_file_argument(migrate_parser)
    add_v2_write_arguments(migrate_parser)
    migrate_parser.set_defaults(func=cmd_migrate)

    return parser


def prompt_path(label: str) -> str:
    return input(f"{label}: ").strip().strip('"')


def interactive_menu() -> int:
    print("Python File Locker")
    print("==================")
    print("1. Lock file/folder")
    print("2. Open/play locked item")
    print("3. Unlock permanently")
    print("4. Show locked item info")
    print("5. Migrate locked item to v2")
    print("6. Exit")
    choice = input("Choose: ").strip()

    if choice == "1":
        args = argparse.Namespace(
            path=prompt_path("File/folder path"),
            output=None,
            force=False,
            secure_delete=False,
            password=None,
            key_file=None,
            cipher=DEFAULT_CIPHER,
            compress=False,
            min_password_length=DEFAULT_MIN_PASSWORD_LENGTH,
            require_upper=False,
            require_lower=False,
            require_digit=False,
            require_symbol=False,
        )
        return cmd_lock(args)
    if choice == "2":
        args = argparse.Namespace(
            path=prompt_path("Locked file path"),
            keep=False,
            password=None,
            key_file=None,
        )
        return cmd_open(args)
    if choice == "3":
        args = argparse.Namespace(
            path=prompt_path("Locked file path"),
            output=None,
            force=False,
            password=None,
            key_file=None,
        )
        return cmd_unlock(args)
    if choice == "4":
        args = argparse.Namespace(path=prompt_path("Locked file path"), password=None, key_file=None)
        return cmd_info(args)
    if choice == "5":
        args = argparse.Namespace(
            path=prompt_path("Locked file path"),
            output=None,
            force=False,
            password=None,
            key_file=None,
            cipher=DEFAULT_CIPHER,
            compress=False,
            min_password_length=DEFAULT_MIN_PASSWORD_LENGTH,
            require_upper=False,
            require_lower=False,
            require_digit=False,
            require_symbol=False,
        )
        return cmd_migrate(args)
    if choice == "6":
        return 0

    print("Unknown choice.")
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        try:
            return interactive_menu()
        except LockError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\nCancelled.", file=sys.stderr)
            return 130
        except EOFError:
            print()
            return 1

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except LockError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
