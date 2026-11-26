import base64
import json
import re
import socket
import ipaddress
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

from config.settings import IDENTITIES_DIR, MESSAGE_PORT


def _identity_path(name):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", name):
        raise ValueError("Nome de identidade inválido.")
    return IDENTITIES_DIR / f"{name}.json"


def _public_bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def discover_local_addresses():
    """Enumera IPv4 de todas as interfaces; mantém fallback sem psutil."""
    found = set()
    try:
        import psutil
        for interface, entries in psutil.net_if_addrs().items():
            for entry in entries:
                if entry.family != socket.AF_INET:
                    continue
                try:
                    ip = ipaddress.ip_address(entry.address)
                except ValueError:
                    continue
                if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                    continue
                found.add((str(ip), interface))
    except ImportError:
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                found.add((item[4][0], "hostname"))
        except OSError:
            pass
        # UDP connect apenas seleciona a rota/interface; não envia datagrama.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))
            found.add((sock.getsockname()[0], "route"))
        except OSError:
            pass
        finally:
            sock.close()
    return [
        {"address": address, "port": MESSAGE_PORT, "interface": interface}
        for address, interface in sorted(found)
    ]


def load_identity(name):
    path = _identity_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Identidade {name} não encontrada.")
    identity = json.loads(path.read_text(encoding="utf-8"))
    if identity.get("version") != 1:
        raise ValueError("Versão de identidade incompatível.")
    identity.setdefault("addresses", [])
    return identity


def save_identity(identity):
    path = _identity_path(identity["name"])
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(identity, indent=4, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def update_local_addresses(name):
    identity = load_identity(name)
    known = {(x.get("address"), int(x.get("port", MESSAGE_PORT)), x.get("interface", "")) for x in identity.get("addresses", [])}
    changed = False
    for item in discover_local_addresses():
        key = (item["address"], int(item["port"]), item.get("interface", ""))
        if key not in known:
            identity.setdefault("addresses", []).append(item)
            known.add(key)
            changed = True
    if changed:
        save_identity(identity)
    return identity.get("addresses", [])


def generate_identity(name):
    path = _identity_path(name)
    if path.exists():
        raise FileExistsError(f"A identidade {name} já existe.")
    encryption_private = x25519.X25519PrivateKey.generate()
    signing_private = ed25519.Ed25519PrivateKey.generate()
    identity = {
        "version": 1,
        "name": name,
        "encryption_private": base64.b64encode(encryption_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )).decode("ascii"),
        "signing_private": base64.b64encode(signing_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )).decode("ascii"),
        "encryption_public": base64.b64encode(_public_bytes(encryption_private.public_key())).decode("ascii"),
        "signing_public": base64.b64encode(_public_bytes(signing_private.public_key())).decode("ascii"),
        "addresses": []
    }
    save_identity(identity)
    update_local_addresses(name)
    return export_identity(name)


def get_encryption_private_key(name):
    raw = base64.b64decode(load_identity(name)["encryption_private"], validate=True)
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def get_signing_private_key(name):
    raw = base64.b64decode(load_identity(name)["signing_private"], validate=True)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def export_identity(name):
    identity = load_identity(name)
    return {
        "version": 1,
        "name": name,
        "encryption_public": identity["encryption_public"],
        "signing_public": identity["signing_public"],
        "addresses": list(identity.get("addresses", []))
    }


def list_identities():
    IDENTITIES_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(path.stem for path in IDENTITIES_DIR.glob("*.json"))


def delete_identity(name):
    path = _identity_path(name)
    if path.exists():
        path.unlink()
