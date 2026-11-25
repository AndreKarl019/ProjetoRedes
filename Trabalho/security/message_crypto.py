
import os
import base64

from cryptography.hazmat.primitives.asymmetric import x25519

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security.key_manager import (
    get_encryption_private_key,
    load_identity
)


def derive_shared_key(local_name, remote_public_key):

    local_private = get_encryption_private_key(local_name)

    remote_bytes = base64.b64decode(
        remote_public_key,
        validate=True
    )

    remote_public = x25519.X25519PublicKey.from_public_bytes(
        remote_bytes
    )

    shared_secret = local_private.exchange(remote_public)

    local_public = base64.b64decode(
        load_identity(local_name)["encryption_public"],
        validate=True
    )

    ordered_keys = sorted([
        local_public,
        remote_bytes
    ])

    context = (
        b"SecurePeer-v1"
        + b"".join(ordered_keys)
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context
    ).derive(shared_secret)


def encrypt_message(message, shared_key, associated_data):

    if not isinstance(message, str):
        raise TypeError("A mensagem precisa ser texto.")

    nonce = os.urandom(12)

    aes = AESGCM(shared_key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        associated_data
    )

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }


def decrypt_message(packet, shared_key, associated_data):

    nonce = base64.b64decode(
        packet["nonce"],
        validate=True
    )

    ciphertext = base64.b64decode(
        packet["ciphertext"],
        validate=True
    )

    if len(nonce) != 12:
        raise ValueError("Nonce inválido.")

    aes = AESGCM(shared_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        associated_data
    )

    return plaintext.decode("utf-8")
