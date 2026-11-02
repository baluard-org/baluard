#!/usr/bin/env python3
"""Reference decryptor for baluard.backup v1 (.bldbak) containers.

Proves a third party can implement docs/adr/0099-encrypted-backup.md from the
spec alone — the format is only "open" if someone besides Baluard can read
it. Run it on the committed golden vector:

    python3 scripts/decrypt_backup.py crates/baluard-core/tests/golden/backup-v1.bldbak

Dependencies (declared, not hidden): `pip install argon2-cffi cryptography`
— Python's standard library has neither Argon2id nor AES-GCM. Everything
else (header parsing, HKDF, chunk framing, padding) is stdlib-only, so the
script doubles as a readable spec of the container's structure.

Exit codes: 0 = decrypted and verified; 1 = wrong password or damaged file;
2 = not a backup / unsupported parameters (needs a newer app).
"""

import hashlib
import hmac
import json
import os
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BLDBAK"
HEADER_LEN = 65
HKDF_SALT = b"baluard.backup.v1"
CHUNK = 65536
CHUNK_ON_DISK = CHUNK + 16
BUCKETS = [256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024, 256 * 1024 * 1024]


def die(msg, code):
    print(msg, file=sys.stderr)
    sys.exit(code)


def parse_header(buf):
    if len(buf) < HEADER_LEN or buf[:6] != MAGIC:
        die("not an encrypted Baluard backup", 2)
    version, kdf_id, aead_id, reserved = buf[6], buf[7], buf[8], buf[9]
    mem_kib, iters, parall = struct.unpack_from("<III", buf, 10)
    salt = buf[22:54]
    nonce_prefix = buf[54:61]
    chunk_size = struct.unpack_from("<I", buf, 61)[0]
    if version != 1 or kdf_id != 1 or aead_id != 1 or reserved != 0 or chunk_size != CHUNK:
        die("this backup needs a newer version of Baluard", 2)
    if mem_kib > 262144 or iters > 6 or parall > 4:
        die("this backup needs a newer version of Baluard", 2)
    return mem_kib, iters, parall, salt, nonce_prefix


def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def main():
    # argv = [script, backup.bldbak]
    if len(sys.argv) != 2:
        die(f"usage: {sys.argv[0]} <backup.bldbak>", 2)
    import getpass

    path = sys.argv[1]
    with open(path, "rb") as f:
        buf = f.read()

    mem_kib, iters, parall, salt, nonce_prefix = parse_header(buf)
    body = len(buf) - HEADER_LEN
    if body == 0 or body % CHUNK_ON_DISK != 0:
        die("wrong password or damaged file", 1)
    n_chunks = body // CHUNK_ON_DISK
    plaintext_len = n_chunks * CHUNK
    if plaintext_len not in BUCKETS:
        die("wrong password or damaged file", 1)

    passphrase = os.environ.get("BALUARD_BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
    norm = __import__("unicodedata").normalize("NFKC", passphrase)
    try:
        # Keyword args: hash_secret_raw's order is (time_cost, memory_cost),
        # the reverse of the header's (memory_kib, iterations) layout — the
        # first CI run caught this exact swap as a wrong-key AEAD failure.
        dk = hash_secret_raw(
            norm.encode(), salt, time_cost=iters, memory_cost=mem_kib,
            parallelism=parall, hash_len=32, type=Type.ID,
        )
    except Exception:
        # Over-cap or sub-floor parameters: treat like an undecryptable file
        # rather than dumping a library traceback.
        die("wrong password or damaged file", 1)
    key = hkdf_sha256(dk, HKDF_SALT, buf[:HEADER_LEN])

    aead = AESGCM(key)
    padded = b""
    for i in range(n_chunks):
        ct = buf[HEADER_LEN + i * CHUNK_ON_DISK : HEADER_LEN + (i + 1) * CHUNK_ON_DISK]
        nonce = nonce_prefix + struct.pack(">I", i) + (b"\x01" if i + 1 == n_chunks else b"\x00")
        try:
            padded += aead.decrypt(nonce, ct, buf[:HEADER_LEN])
        except Exception:
            die("wrong password or damaged file", 1)

    (payload_len,) = struct.unpack_from(">Q", padded, 0)
    if payload_len > len(padded) - 8 or any(padded[8 + payload_len :]):
        die("wrong password or damaged file", 1)
    payload = padded[8 : 8 + payload_len].decode("utf-8")

    doc = json.loads(payload)
    print(f"OK: format={doc['format']} version={doc['version']} "
          f"ciphers={doc['manifest']['cipher_count']} folders={doc['manifest']['folder_count']}")


if __name__ == "__main__":
    main()
