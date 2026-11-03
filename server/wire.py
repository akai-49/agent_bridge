"""Wire protocol helpers: token creation/parsing and HMAC signing/verification."""
from __future__ import annotations
import base64
import binascii
import hashlib
import hmac


def make_token(relay_url: str, invite_id: str, join_secret: str, e2e_key: str) -> str:
    """Create a pairing token in the format:
    brg1.<b64url(relay_url)>.<invite_id>.<join_secret>.<e2e_key>
    """
    if not all(isinstance(x, str) and x for x in (relay_url, invite_id, join_secret, e2e_key)):
        raise ValueError("All token components must be non-empty strings")
    if any("." in x for x in (invite_id, join_secret, e2e_key)):
        raise ValueError("Token components must not contain '.'")

    b64_url = base64.urlsafe_b64encode(relay_url.encode("utf-8")).decode("ascii").rstrip("=")
    return f"brg1.{b64_url}.{invite_id}.{join_secret}.{e2e_key}"


def parse_token(token: str) -> dict:
    """Parse a pairing token into its components.
    Returns dict with keys: relay_url, invite_id, join_secret, e2e_key.
    Raises ValueError on bad prefix or malformed shape.
    """
    if not isinstance(token, str):
        raise ValueError("Token must be a string")

    parts = token.split(".")
    if len(parts) != 5:
        raise ValueError(f"Invalid token shape: expected 5 parts, got {len(parts)}")

    prefix, b64_url, invite_id, join_secret, e2e_key = parts

    if prefix != "brg1":
        raise ValueError(f"Invalid token prefix: expected 'brg1', got {prefix!r}")

    if not b64_url or not invite_id or not join_secret or not e2e_key:
        raise ValueError("Token components cannot be empty")

    rem = len(b64_url) % 4
    padded = b64_url + ("=" * (4 - rem) if rem else "")
    try:
        relay_url = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"Invalid base64url relay_url in token: {e}") from e

    if not relay_url:
        raise ValueError("Decoded relay_url cannot be empty")

    return {
        "relay_url": relay_url,
        "invite_id": invite_id,
        "join_secret": join_secret,
        "e2e_key": e2e_key,
    }


def q_tag(asker: str) -> str:
    """Return signature tag for a question asked by asker ('q:' + asker)."""
    return f"q:{asker}"


def a_tag(asker: str, qid: str) -> str:
    """Return signature tag for an answer to a question asked by asker ('a:' + asker + ':' + qid)."""
    return f"a:{asker}:{qid}"


def other(role: str) -> str:
    """Return the peer role ('B' if role == 'A' else 'A')."""
    return "B" if role == "A" else "A"


def sign(key: str, qid: str, body: str) -> str:
    """Compute hex HMAC-SHA256 signature over qid + '\\n' + body."""
    msg = f"{qid}\n{body}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify(key: str, qid: str, body: str, sig: str) -> bool:
    """Verify hex HMAC-SHA256 signature using constant-time comparison."""
    if not isinstance(key, str) or not isinstance(qid, str) or not isinstance(body, str) or not isinstance(sig, str):
        return False
    expected = sign(key, qid, body)
    return hmac.compare_digest(expected, sig)


# --- End-to-end encryption of question/answer text -------------------------------------
# The relay must not read Q&A. The stdlib has no AES, so: HMAC-SHA256 in counter mode as the
# keystream (a PRF with a fresh random nonce per message) + encrypt-then-MAC. The tag (who asked,
# which qid) is bound into the MAC so a sealed question can never be replayed as an answer.
import os as _os


def _subkey(key: str, label: bytes) -> bytes:
    return hmac.new(key.encode("utf-8"), label, hashlib.sha256).digest()


def _keystream_xor(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 32):
        block = hmac.new(enc_key, nonce + (i // 32).to_bytes(8, "big"), hashlib.sha256).digest()
        out += bytes(a ^ b for a, b in zip(data[i:i + 32], block))
    return bytes(out)


def _mac(mac_key: bytes, tag: str, nonce: bytes, ct: bytes) -> bytes:
    return hmac.new(mac_key, tag.encode("utf-8") + b"\x00" + nonce + ct, hashlib.sha256).digest()


def seal(key: str, tag: str, plaintext: str) -> str:
    nonce = _os.urandom(16)
    ct = _keystream_xor(_subkey(key, b"enc"), nonce, plaintext.encode("utf-8"))
    mac = _mac(_subkey(key, b"mac"), tag, nonce, ct)
    return "e1." + base64.urlsafe_b64encode(nonce + ct + mac).decode("ascii").rstrip("=")


def open_sealed(key: str, tag: str, sealed: str):
    """Return plaintext, or None on any failure (bad format, wrong key/tag, tampering)."""
    try:
        if not (isinstance(key, str) and isinstance(tag, str) and isinstance(sealed, str)
                and sealed.startswith("e1.")):
            return None
        b64 = sealed[3:]
        raw = base64.urlsafe_b64decode((b64 + "=" * (-len(b64) % 4)).encode("ascii"))
        if len(raw) < 48:
            return None
        nonce, ct, mac = raw[:16], raw[16:-32], raw[-32:]
        if not hmac.compare_digest(mac, _mac(_subkey(key, b"mac"), tag, nonce, ct)):
            return None
        return _keystream_xor(_subkey(key, b"enc"), nonce, ct).decode("utf-8")
    except Exception:
        return None
