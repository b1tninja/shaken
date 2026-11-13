"""The "msg" PASSporT type and "msgi", RFC 9475 sec. 3.2.

Provenance: the sec. 3.2 para 5 example value is copied from the text (through rfclib). Digests
for the algorithm vectors are computed here with ``hashlib`` from a fixed body, and the base64 is
checked by hand against RFC 4648; none is a vendor capture.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from shaken.claims import ClaimsError
from shaken.messaging import (
    msg_claims,
    msg_header,
    msgi_digest,
    msgi_matches,
    validate_msg_claims,
)

EXAMPLE = "sha256-H8BRh8j48O9oYatfu5AZzq6A9RINQZngK7T62em8MUt1FLm52t+eX6xO"
BASE = {
    "dest": {"uri": ["sip:alice@example.com"]},
    "iat": 1443208345,
    "orig": {"tn": "12155551212"},
}
BODY = b"Content-Type: text/plain\r\n\r\nhello"


def test_messaging():
    for name in ("sha256", "sha384", "sha512"):
        value = msgi_digest(BODY, name)
        digest = hashlib.new(name, BODY).digest()
        assert value == f"{name}-{base64.b64encode(digest).decode()}"
        assert msgi_matches(value, BODY)
        assert not msgi_matches(value, BODY + b"x")
    claims = msg_claims(BASE, body=BODY)
    assert claims["msgi"].startswith("sha256-")
    assert "msgi" not in msg_claims(BASE)  # OPTIONAL: absent when there is no body to hash
    assert msg_header("https://example.org/c")["ppt"] == "msg"
    # sec. 3.2 para 2: msgi means something only in "msg" PASSporTs, and is ignored elsewhere
    assert validate_msg_claims(claims, "msg") is True
    assert validate_msg_claims(claims, "shaken") is False
    assert validate_msg_claims(claims | {"msgi": 5}, "shaken") is False  # ignored, even malformed
    assert validate_msg_claims(BASE, "msg") is False
    for bad in (5, "sha256", "SHA256-AAAA", "sha256-", "-AAAA", "sha256-@@@@"):
        with pytest.raises(ClaimsError):
            validate_msg_claims(claims | {"msgi": bad}, "msg")
    with pytest.raises(ClaimsError):
        msgi_digest(BODY, "md5")
    with pytest.raises(ClaimsError):
        msgi_matches("sha1-" + base64.b64encode(hashlib.sha1(BODY).digest()).decode(), BODY)  # noqa: S324


def test_rfc9475_example_is_not_a_sha256_digest():
    """Finding: the sec. 3.2 para 5 example claims "sha256" but decodes to 42 octets, not 32."""
    algorithm, text = EXAMPLE.split("-", 1)
    assert algorithm == "sha256"
    assert len(base64.b64decode(text, validate=True)) == 42
    assert len(hashlib.sha256(b"").digest()) == 32
    assert validate_msg_claims({"msgi": EXAMPLE}, "msg") is True
    assert msgi_matches(EXAMPLE, BODY) is False
