import threading
import time
import uuid

import database
from config.settings import MESSAGE_HOST, MESSAGE_PORT
from core.debug_logger import debug
from core.message_router import MessageRouter
from network.identity_sync import create_identity_packet, validate_identity_packet
from network.message_transport import MessageServer, send_packet
from security.peer_auth import sign_packet, verify_packet


class ConnectionManager:
    def __init__(self, local_name):
        self.local_name = local_name
        self.router = MessageRouter()
        self.server = None
        self.server_thread = None
        self.running = False
        self.on_message = None
        self.on_identity_synced = None

    def start(self):
        if self.running:
            return
        self.server = MessageServer(MESSAGE_HOST, MESSAGE_PORT, self._handle_packet)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        if not self.server.ready_event.wait(5):
            self.stop()
            raise TimeoutError("Tempo esgotado ao iniciar receptor.")
        if self.server.startup_error:
            error = self.server.startup_error
            self.stop()
            raise RuntimeError(f"Não foi possível iniciar receptor: {error}")
        self.running = True

    def stop(self):
        if self.server:
            self.server.stop()
        if self.server_thread:
            self.server_thread.join(timeout=3)
        self.running = False
        self.server = None
        self.server_thread = None

    def _send_over_known_addresses(self, peer, packet, response_validator):
        addresses = database.get_peer_addresses(peer[0])
        if not addresses:
            addresses = [{"address": peer[2], "port": peer[3]}]
        errors = []
        for endpoint in addresses:
            try:
                response = send_packet(endpoint["address"], endpoint["port"], packet)
                response_validator(response)
                database.add_peer_address(peer[0], endpoint["address"], endpoint["port"],
                                          source=endpoint.get("source", "manual"), last_seen=True)
                database.update_peer_primary_address(peer[0], endpoint["address"], endpoint["port"])
                return response, endpoint
            except Exception as error:
                errors.append(f'{endpoint["address"]}:{endpoint["port"]} — {error}')
                debug.warning(f'Tentativa falhou em {endpoint["address"]}:{endpoint["port"]}: {error}')
        raise ConnectionError("Nenhum endereço do peer respondeu:\n" + "\n".join(errors))

    def send_identity(self, peer_id):
        if not self.running:
            raise RuntimeError("Inicie o receptor antes de enviar a identidade.")
        peer = database.get_peer(peer_id)
        if not peer or not peer[7]:
            raise PermissionError("Selecione um peer cadastrado e marcado como confiável.")
        packet = create_identity_packet(self.local_name)

        response_addresses = []

        def validate(response):
            nonce = response.get("nonce")
            if not isinstance(nonce, str) or len(nonce) != 36:
                raise ValueError("Nonce da resposta de identidade inválido.")
            if database.identity_nonce_already_received(peer_id, nonce):
                raise PermissionError("Resposta de identidade repetida.")
            response_addresses.extend(validate_identity_packet(
                response, peer, expected_type="identity_sync_response"
            ))
            database.register_identity_nonce(peer_id, nonce)

        response, endpoint = self._send_over_known_addresses(peer, packet, validate)
        for item in response_addresses:
            database.add_peer_address(peer_id, item["address"], item["port"], source="identity", interface=item.get("interface"), last_seen=False)
        debug.info(f'Identidade de {peer[1]} sincronizada por {endpoint["address"]}:{endpoint["port"]}.')
        return len(response.get("identity", {}).get("addresses", []))

    def send(self, peer_id, message):
        if not self.running:
            raise RuntimeError("Inicie o receptor antes de enviar.")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("Mensagem vazia ou inválida.")
        peer = database.get_peer(peer_id)
        if not peer:
            raise ValueError("Peer não encontrado.")
        result = self.router.send(self.local_name, peer, message)
        packet = result["packet"]

        def validate(response):
            if response.get("type") != "message_ack" or response.get("message_id") != result["message_id"] or response.get("ok") is not True:
                raise ValueError("ACK de aplicação inválido.")
            if response.get("sender") != peer[1] or not verify_packet(response, peer[6]):
                raise PermissionError("ACK não autenticado pelo peer.")
            if abs(time.time() - int(response.get("timestamp", 0))) > 300:
                raise ValueError("ACK expirado.")

        try:
            self._send_over_known_addresses(peer, packet, validate)
        except Exception:
            database.register_message(peer_id, "OUT", "FAILED", len(message.encode("utf-8")))
            database.register_chat_message(peer_id, result["message_id"], "OUT", message, "FAILED")
            raise
        database.register_message(peer_id, "OUT", "DELIVERED", len(message.encode("utf-8")))
        database.register_chat_message(peer_id, result["message_id"], "OUT", message, "DELIVERED")
        return result["message_id"]

    def _handle_packet(self, packet, address):
        sender_name = packet.get("sender")
        peer = database.get_peer_by_name(sender_name)
        if not peer:
            debug.warning(f"Peer desconhecido: {sender_name}")
            return None
        if packet.get("type") == "identity_sync":
            if not peer[7]:
                raise PermissionError("Peer não confiável não pode sincronizar identidade.")
            nonce = packet.get("nonce")
            if not isinstance(nonce, str) or len(nonce) != 36:
                raise ValueError("Nonce de sincronização inválido.")
            if database.identity_nonce_already_received(peer[0], nonce):
                raise PermissionError("Pacote de sincronização repetido.")
            addresses = validate_identity_packet(packet, peer)
            database.register_identity_nonce(peer[0], nonce)
            for item in addresses:
                database.add_peer_address(peer[0], item["address"], item["port"], source="identity", interface=item.get("interface"), last_seen=False)
            # O IP observado é aprendido separadamente, sem confiar no endereço declarado.
            observed_ip = address[0]
            database.add_peer_address(peer[0], observed_ip, MESSAGE_PORT, source="observed", last_seen=True)
            response = create_identity_packet(self.local_name, "identity_sync_response")
            debug.info(f"Lista de endereços recebida de {sender_name}: {len(addresses)} endereço(s).")
            if self.on_identity_synced:
                self.on_identity_synced(peer[0], sender_name)
            return response
        if packet.get("type") == "message":
            message, message_id = self.router.receive(self.local_name, peer, packet)
            if message is not None and self.on_message:
                self.on_message(peer[0], peer[1], message, message_id)
            ack = {
                "version": 1, "type": "message_ack", "sender": self.local_name,
                "message_id": message_id, "ok": True, "timestamp": int(time.time())
            }
            return sign_packet(self.local_name, ack)
        raise ValueError("Tipo de pacote desconhecido.")
