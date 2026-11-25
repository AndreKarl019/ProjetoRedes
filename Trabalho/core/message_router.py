
import time
import uuid

from security.message_crypto import (
    derive_shared_key,
    encrypt_message,
    decrypt_message
)

from security.peer_auth import (
    sign_packet,
    verify_packet,
    canonical_json
)

import database

from core.debug_logger import debug

MAX_CLOCK_DIFFERENCE = 300


class MessageRouter:

    def send(self, local_name, peer, message):

        peer_id = peer[0]
        peer_name = peer[1]
        peer_address = peer[2]
        peer_port = peer[3]
        encryption_public = peer[5]
        trusted = peer[7]

        if not trusted:
            raise PermissionError(
                "Peer ainda não foi marcado como confiável."
            )

        debug.info(
            f"[A] Mensagem recebida para {peer_name}."
        )

        shared_key = derive_shared_key(
            local_name,
            encryption_public
        )

        message_id = str(uuid.uuid4())

        header = {
            "version": 1,
            "type": "message",
            "message_id": message_id,
            "sender": local_name,
            "recipient": peer_name,
            "timestamp": int(time.time())
        }

        associated_data = canonical_json(header)

        debug.info(
            "[A] Criptografando mensagem com AES-256-GCM."
        )

        payload = encrypt_message(
            message,
            shared_key,
            associated_data
        )

        packet = {
            **header,
            "payload": payload
        }

        debug.info(
            "[A] Assinando pacote com Ed25519."
        )

        packet = sign_packet(
            local_name,
            packet
        )

        debug.info(
            f"[A] Destino selecionado: {peer_address}:{peer_port}"
        )

        database.register_message(
            peer_id,
            "OUT",
            "PREPARED",
            len(message.encode("utf-8"))
        )

        return {
            "host": peer_address,
            "port": peer_port,
            "packet": packet,
            "peer_id": peer_id
        }

    def receive(self, local_name, peer, packet):

        peer_id = peer[0]
        peer_name = peer[1]
        signing_public = peer[6]
        trusted = peer[7]

        if not trusted:
            raise PermissionError(
                "O remetente não é um peer confiável."
            )

        debug.info("[B] Pacote recebido.")

        if packet.get("version") != 1:
            raise ValueError("Versão de protocolo incompatível.")

        if packet.get("type") != "message":
            raise ValueError("Tipo de pacote inválido.")

        if packet.get("sender") != peer_name:
            raise PermissionError(
                "Identidade do remetente incompatível."
            )

        if packet.get("recipient") != local_name:
            raise PermissionError(
                "Mensagem destinada a outra identidade."
            )

        timestamp = packet.get("timestamp")

        if not isinstance(timestamp, int):
            raise ValueError("Timestamp inválido.")

        if abs(time.time() - timestamp) > MAX_CLOCK_DIFFERENCE:
            raise ValueError("Mensagem fora da janela de tempo.")

        message_id = packet.get("message_id")

        if not isinstance(message_id, str) or len(message_id) != 36:
            raise ValueError("Identificador de mensagem inválido.")

        if database.nonce_already_received(
            peer_id,
            message_id
        ):
            raise PermissionError(
                "Mensagem repetida detectada."
            )

        debug.info("[B] Verificando assinatura Ed25519.")

        if not verify_packet(packet, signing_public):
            raise PermissionError(
                "Assinatura inválida."
            )

        debug.info("[B] Assinatura válida.")

        database.register_nonce(
            peer_id,
            message_id
        )

        header = {
            "version": packet["version"],
            "type": packet["type"],
            "message_id": message_id,
            "sender": packet["sender"],
            "recipient": packet["recipient"],
            "timestamp": timestamp
        }

        associated_data = canonical_json(header)

        shared_key = derive_shared_key(
            local_name,
            peer[5]
        )

        debug.info(
            "[B] Descriptografando AES-256-GCM."
        )

        message = decrypt_message(
            packet["payload"],
            shared_key,
            associated_data
        )

        debug.info(
            "[B] Integridade verificada e mensagem descriptografada."
        )

        database.register_message(
            peer_id,
            "IN",
            "RECEIVED",
            len(message.encode("utf-8"))
        )

        return message
