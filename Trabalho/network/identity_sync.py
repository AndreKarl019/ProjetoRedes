import ipaddress
import time
import uuid

from security.key_manager import export_identity
from security.peer_auth import sign_packet, verify_packet


def create_identity_packet(identity_name, packet_type="identity_sync"):
    return sign_packet(identity_name, {
        "version": 1,
        "type": packet_type,
        "sender": identity_name,
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "identity": export_identity(identity_name)
    })


def validate_identity_packet(packet, peer, expected_type="identity_sync"):
    if packet.get("version") != 1 or packet.get("type") != expected_type:
        raise ValueError("Pacote de sincronização inválido.")
    if packet.get("sender") != peer[1]:
        raise PermissionError("Nome da identidade não corresponde ao peer cadastrado.")
    if abs(time.time() - int(packet.get("timestamp", 0))) > 300:
        raise ValueError("Pacote de identidade expirado.")
    identity = packet.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("Identidade pública ausente.")
    if identity.get("name") != peer[1]:
        raise PermissionError("Nome da identidade incompatível.")
    if identity.get("encryption_public") != peer[5] or identity.get("signing_public") != peer[6]:
        raise PermissionError("As chaves públicas recebidas não correspondem ao peer confiável.")
    if not verify_packet(packet, peer[6]):
        raise PermissionError("Prova de posse da chave Ed25519 inválida.")
    addresses = identity.get("addresses", [])
    if not isinstance(addresses, list) or len(addresses) > 100:
        raise ValueError("Lista de endereços inválida.")
    clean = []
    for item in addresses:
        if not isinstance(item, dict):
            continue
        try:
            address = str(ipaddress.ip_address(item.get("address", "")))
            port = int(item.get("port", 8765))
            if not 1 <= port <= 65535:
                continue
            ip = ipaddress.ip_address(address)
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                continue
            interface = item.get("interface", "")
            if not isinstance(interface, str):
                interface = ""
            clean.append({"address": address, "port": port, "interface": interface[:64]})
        except (ValueError, TypeError):
            continue
    return clean
