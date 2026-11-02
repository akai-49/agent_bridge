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
