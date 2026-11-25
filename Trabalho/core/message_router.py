import time
import uuid

import database
from core.debug_logger import debug
from security.message_crypto import derive_shared_key, encrypt_message, decrypt_message
from security.peer_auth import sign_packet, verify_packet, canonical_json

MAX_CLOCK_DIFFERENCE = 300


class MessageRouter:
    def send(self, local_name, peer, message):
        if not peer[7]:
            raise PermissionError("Peer ainda não foi marcado como confiável.")
        message_id = str(uuid.uuid4())
        header = {
            "version": 1, "type": "message", "message_id": message_id,
            "sender": local_name, "recipient": peer[1], "timestamp": int(time.time())
        }
        shared_key = derive_shared_key(local_name, peer[5])
        payload = encrypt_message(message, shared_key, canonical_json(header))
        packet = sign_packet(local_name, {**header, "payload": payload})
        database.register_message(peer[0], "OUT", "PREPARED", len(message.encode("utf-8")))
        return {"packet": packet, "peer_id": peer[0], "message_id": message_id}

    def receive(self, local_name, peer, packet):
        if not peer[7]:
            raise PermissionError("O remetente não é um peer confiável.")
        if packet.get("version") != 1 or packet.get("type") != "message":
            raise ValueError("Pacote de mensagem inválido.")
        # Primeiro valida quem assinou o pacote; só então usa os campos
        # sender/recipient para diagnosticar o vínculo entre as identidades.
        if packet.get("sender") != peer[1]:
            raise PermissionError(
                f"Identidade do remetente incompatível: recebido {packet.get('sender')!r}; "
                f"peer cadastrado {peer[1]!r}."
            )
        if not verify_packet(packet, peer[6]):
            raise PermissionError("Assinatura Ed25519 inválida: o pacote não foi autenticado pelo peer cadastrado.")
        if packet.get("recipient") != local_name:
            raise PermissionError(
                f"Destinatário incompatível: a mensagem foi endereçada a "
                f"{packet.get('recipient')!r}, mas a identidade ativa neste receptor é {local_name!r}. "
                "Confira se o nome da identidade local corresponde exatamente ao cadastrado na outra máquina."
            )
        timestamp = packet.get("timestamp")
        if not isinstance(timestamp, int) or abs(time.time() - timestamp) > MAX_CLOCK_DIFFERENCE:
            raise ValueError("Mensagem fora da janela de tempo.")
        message_id = packet.get("message_id")
        if not isinstance(message_id, str) or len(message_id) != 36:
            raise ValueError("Identificador de mensagem inválido.")
        # A assinatura já foi validada antes de confiar nos campos do pacote.
        if database.nonce_already_received(peer[0], message_id):
            return None, message_id
        header = {k: packet[k] for k in ("version", "type", "message_id", "sender", "recipient", "timestamp")}
        shared_key = derive_shared_key(local_name, peer[5])
        message = decrypt_message(packet["payload"], shared_key, canonical_json(header))
        if not database.register_nonce(peer[0], message_id):
            return None, message_id
        database.register_message(peer[0], "IN", "RECEIVED", len(message.encode("utf-8")))
        database.register_chat_message(peer[0], message_id, "IN", message, "RECEIVED")
        debug.info(f"Mensagem recebida de {peer[1]}.")
        return message, message_id
