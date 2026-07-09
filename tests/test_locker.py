from __future__ import annotations

import json
import os
import struct
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import main


PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def fast_crypto(monkeypatch):
    monkeypatch.setattr(main, "ARGON2_MEMORY_KIB", 8192)
    monkeypatch.setattr(main, "ARGON2_ITERATIONS", 1)
    monkeypatch.setattr(main, "ARGON2_LANES", 1)
    monkeypatch.setattr(main, "CHUNK_SIZE", 64 * 1024)


def make_legacy_locked(source: Path, destination: Path, password: str, kind: str = "file") -> None:
    salt = os.urandom(main.SALT_BYTES)
    nonce_prefix = os.urandom(main.NONCE_PREFIX_BYTES)
    header = {
        "version": main.LEGACY_FORMAT_VERSION,
        "kind": kind,
        "name": source.name,
        "cipher": "AES-256-GCM-stream",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 100_000,
        "chunk_size": main.CHUNK_SIZE,
        "salt": main.b64_encode(salt),
        "nonce_prefix": main.b64_encode(nonce_prefix),
        "created_at": 1_700_000_000,
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aad = main.LEGACY_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=header["iterations"],
    ).derive(password.encode("utf-8"))
    aead = AESGCM(key)

    with source.open("rb") as src, destination.open("wb") as dst:
        dst.write(main.LEGACY_MAGIC)
        dst.write(struct.pack(">I", len(header_bytes)))
        dst.write(header_bytes)
        index = 0
        while True:
            chunk = src.read(main.CHUNK_SIZE)
            if not chunk:
                break
            ciphertext = aead.encrypt(nonce_prefix + index.to_bytes(4, "big"), chunk, aad)
            dst.write(struct.pack(">I", len(ciphertext)))
            dst.write(ciphertext)
            index += 1
        final_record = aead.encrypt(nonce_prefix + index.to_bytes(4, "big"), b"", aad)
        dst.write(struct.pack(">I", len(final_record)))
        dst.write(final_record)


def test_v2_file_roundtrip_and_metadata_is_encrypted(tmp_path):
    source = tmp_path / "private name.txt"
    source.write_bytes(b"secret payload" * 1000)
    locked = tmp_path / "private name.txt.locked"

    main.lock_path(source, locked, PASSWORD, force=False)

    assert not source.exists()
    locked_bytes = locked.read_bytes()
    assert locked_bytes.startswith(main.V2_MAGIC)
    assert b"private name.txt" not in locked_bytes
    assert b"secret payload" not in locked_bytes

    output = main.unlock_path(locked, None, PASSWORD, force=False)
    assert output.read_bytes() == b"secret payload" * 1000

    metadata = main.read_locked_metadata(locked, PASSWORD)
    assert metadata["version"] == main.V2_FORMAT_VERSION
    assert metadata["name"] == "private name.txt"
    assert metadata["cipher"] == main.AES_GCM_CIPHER


def test_key_file_chacha_and_compression_are_required_for_unlock(tmp_path):
    source = tmp_path / "video.bin"
    source.write_bytes((b"frame-data-" * 1024) * 20)
    key_file = tmp_path / "locker.key"
    key_file.write_bytes(b"key file material")
    locked = tmp_path / "video.bin.locked"

    main.lock_path(
        source,
        locked,
        PASSWORD,
        force=False,
        key_file=key_file,
        cipher=main.CHACHA20_POLY1305_CIPHER,
        compress=True,
    )

    with pytest.raises(main.LockError):
        main.unlock_path(locked, tmp_path / "wrong.bin", PASSWORD, force=False)
    assert not (tmp_path / "wrong.bin").exists()

    output = main.unlock_path(locked, tmp_path / "right.bin", PASSWORD, force=False, key_file=key_file)
    assert output.read_bytes() == (b"frame-data-" * 1024) * 20


def test_wrong_password_does_not_create_output(tmp_path):
    source = tmp_path / "secret.txt"
    source.write_text("hello", encoding="utf-8")
    locked = tmp_path / "secret.txt.locked"
    main.lock_path(source, locked, PASSWORD, force=False)

    output = tmp_path / "secret.txt"
    with pytest.raises(main.LockError):
        main.unlock_path(locked, output, "wrong password here", force=False)
    assert not output.exists()


def test_corrupted_locked_file_is_rejected_before_replace(tmp_path):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"important data" * 500)
    locked = tmp_path / "secret.txt.locked"
    main.lock_path(source, locked, PASSWORD, force=False)

    corrupt = tmp_path / "corrupt.locked"
    data = bytearray(locked.read_bytes())
    data[-20] ^= 0x80
    corrupt.write_bytes(data)

    output = tmp_path / "secret.txt"
    with pytest.raises(main.LockError):
        main.unlock_path(corrupt, output, PASSWORD, force=False)
    assert not output.exists()


def test_interrupted_lock_keeps_original_and_removes_temp_output(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc" * 1000)
    locked = tmp_path / "source.bin.locked"

    def fail_record(*args, **kwargs):
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(main, "write_encrypted_record", fail_record)

    with pytest.raises(RuntimeError):
        main.lock_path(source, locked, PASSWORD, force=False)

    assert source.exists()
    assert source.read_bytes() == b"abc" * 1000
    assert not locked.exists()
    assert not list(tmp_path.glob("*.tmp-*"))


def test_large_multichunk_file_roundtrip(tmp_path):
    source = tmp_path / "large.bin"
    data = bytes((index % 251 for index in range(1_000_000)))
    source.write_bytes(data)
    locked = tmp_path / "large.bin.locked"

    main.lock_path(source, locked, PASSWORD, force=False, compress=True)
    output = main.unlock_path(locked, None, PASSWORD, force=False)

    assert output.read_bytes() == data


def test_password_policy_is_enforced_for_new_locks(tmp_path):
    source = tmp_path / "short.txt"
    source.write_text("hello", encoding="utf-8")

    with pytest.raises(main.LockError):
        main.lock_path(source, tmp_path / "short.txt.locked", "short", force=False)

    assert source.exists()
    assert not (tmp_path / "short.txt.locked").exists()


def test_safe_extract_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.txt", "bad")

    with pytest.raises(main.LockError):
        main.safe_extract_zip(archive_path, tmp_path / "extract")


def test_legacy_v1_unlock_and_migration_to_v2(tmp_path):
    source = tmp_path / "legacy.txt"
    source.write_bytes(b"legacy payload")
    legacy_locked = tmp_path / "legacy.txt.locked"
    make_legacy_locked(source, legacy_locked, PASSWORD)

    restored = main.unlock_path(legacy_locked, tmp_path / "restored.txt", PASSWORD, force=False)
    assert restored.read_bytes() == b"legacy payload"

    migrated = main.migrate_locked_file(legacy_locked, tmp_path / "legacy-v2.locked", PASSWORD, force=False)
    assert migrated.read_bytes().startswith(main.V2_MAGIC)
    assert b"legacy.txt" not in migrated.read_bytes()

    restored_v2 = main.unlock_path(migrated, tmp_path / "restored-v2.txt", PASSWORD, force=False)
    assert restored_v2.read_bytes() == b"legacy payload"
