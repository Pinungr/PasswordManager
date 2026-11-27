import base64
import hashlib
import json

from fastapi import HTTPException
from jwt import PyJWK, api_jws
from jwt.exceptions import PyJWTError


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(value):
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64url(data) != value:
        raise ValueError("Incorrect base64url encoding")
    return data


def thumbprint(jwk):
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode("ascii")
    return b64url(hashlib.sha256(canonical).digest())


def verify_grant(grant, sender, recipient, vault, epoch, *, signing, agreement):
    try:
        key = PyJWK(signing, algorithm="ES256").key
        signed = api_jws.decode_complete(grant, key, algorithms=["ES256"])
        if signed["header"] != {"typ": "pinaki-vault-grant+jws", "alg": "ES256"}:
            raise ValueError
        payload = json.loads(signed["payload"])
        recipient_key = thumbprint(agreement)
        if payload["binding"] != {
            "vault": vault,
            "epoch": epoch,
            "sender": sender,
            "recipient": recipient,
            "recipientKey": recipient_key,
        }:
            raise ValueError
        header, key_ciphertext, nonce, ciphertext, tag = payload["envelope"].split(".")
        header = json.loads(decode(header))
        if (
            key_ciphertext
            or header.get("typ") != "pinaki-vault-key+jwe"
            or (header.get("alg"), header.get("enc"), header.get("kid"))
            != ("ECDH-ES", "A256GCM", recipient_key)
        ):
            raise ValueError
        if (len(decode(nonce)), len(decode(ciphertext)), len(decode(tag))) != (12, 32, 16):
            raise ValueError
        if header["epk"]["crv"] != "P-256" or header["epk"]["kty"] != "EC":
            raise ValueError
    except (PyJWTError, KeyError, TypeError, ValueError, AttributeError):
        raise HTTPException(422, "The signed vault grant is invalid.") from None
