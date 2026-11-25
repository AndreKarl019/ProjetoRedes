
import base64
import json
import re

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import (
    x25519,
    ed25519
)

from cryptography.hazmat.primitives import serialization

from config.settings import IDENTITIES_DIR


def _identity_path(name):

    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", name):
        raise ValueError("Nome de identidade inválido.")

    return IDENTITIES_DIR / f"{name}.json"


def _public_bytes(key):

    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def generate_identity(name):

    path = _identity_path(name)

    if path.exists():
        raise FileExistsError(
            f"A identidade {name} já existe."
        )

    encryption_private = x25519.X25519PrivateKey.generate()
    signing_private = ed25519.Ed25519PrivateKey.generate()

    encryption_private_bytes = encryption_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    signing_private_bytes = signing_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    identity = {
        "version": 1,
        "name": name,

        "encryption_private": base64.b64encode(
            encryption_private_bytes
        ).decode("ascii"),

        "signing_private": base64.b64encode(
            signing_private_bytes
        ).decode("ascii"),

        "encryption_public": base64.b64encode(
            _public_bytes(encryption_private.public_key())
        ).decode("ascii"),

        "signing_public": base64.b64encode(
            _public_bytes(signing_private.public_key())
        ).decode("ascii")
    }

    path.write_text(
        json.dumps(identity, indent=4),
        encoding="utf-8"
    )

    return export_identity(name)


def load_identity(name):

    path = _identity_path(name)

    if not path.exists():
        raise FileNotFoundError(
            f"Identidade {name} não encontrada."
        )

    identity = json.loads(
        path.read_text(encoding="utf-8")
    )

    if identity.get("version") != 1:
        raise ValueError("Versão de identidade incompatível.")

    return identity


def get_encryption_private_key(name):

    identity = load_identity(name)

    raw = base64.b64decode(
        identity["encryption_private"],
        validate=True
    )

    return x25519.X25519PrivateKey.from_private_bytes(raw)


def get_signing_private_key(name):

    identity = load_identity(name)

    raw = base64.b64decode(
        identity["signing_private"],
        validate=True
    )

    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def export_identity(name):

    identity = load_identity(name)

    return {
        "name": name,
        "encryption_public": identity["encryption_public"],
        "signing_public": identity["signing_public"]
    }


def list_identities():

    IDENTITIES_DIR.mkdir(parents=True, exist_ok=True)

    return [
        path.stem
        for path in IDENTITIES_DIR.glob("*.json")
    ]


def delete_identity(name):

    path = _identity_path(name)

    if path.exists():
        path.unlink()
