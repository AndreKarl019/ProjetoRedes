
import json
import base64
import hashlib

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric import ed25519

from security.key_manager import (
    get_signing_private_key,
    load_identity
)


def canonical_json(data):

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def sign_packet(identity_name, packet):

    private_key = get_signing_private_key(identity_name)

    unsigned_packet = dict(packet)

    unsigned_packet.pop("signature", None)

    signature = private_key.sign(
        canonical_json(unsigned_packet)
    )

    signed_packet = dict(unsigned_packet)

    signed_packet["signature"] = base64.b64encode(
        signature
    ).decode("ascii")

    return signed_packet


def verify_packet(packet, trusted_public_key):

    try:

        unsigned_packet = dict(packet)

        signature = base64.b64decode(
            unsigned_packet.pop("signature"),
            validate=True
        )

        public_bytes = base64.b64decode(
            trusted_public_key,
            validate=True
        )

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            public_bytes
        )

        public_key.verify(
            signature,
            canonical_json(unsigned_packet)
        )

        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError
    ):
        return False


def public_key_fingerprint(public_key):

    raw = base64.b64decode(
        public_key,
        validate=True
    )

    digest = hashlib.sha256(raw).hexdigest()

    return ":".join(
        digest[i:i + 4]
        for i in range(0, len(digest), 4)
    )
