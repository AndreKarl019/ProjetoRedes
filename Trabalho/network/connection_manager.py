
import threading

from network.message_transport import (
    MessageServer,
    send_packet
)

from core.message_router import MessageRouter

from core.debug_logger import debug

from config.settings import (
    MESSAGE_HOST,
    MESSAGE_PORT
)

import database


class ConnectionManager:

    def __init__(self, local_name):

        self.local_name = local_name

        self.router = MessageRouter()

        self.server = None
        self.server_thread = None

        self.running = False
        self.on_message = None

    def start(self):

        if self.running:
            return

        self.server = MessageServer(
            MESSAGE_HOST,
            MESSAGE_PORT,
            self._handle_packet
        )

        self.server_thread = threading.Thread(
            target=self.server.start,
            daemon=True
        )

        self.server_thread.start()

        if not self.server.ready_event.wait(5):

            self.stop()

            raise TimeoutError(
                "Tempo esgotado ao iniciar receptor."
            )

        if self.server.startup_error:

            error = self.server.startup_error

            self.stop()

            raise RuntimeError(
                f"Não foi possível iniciar receptor: {error}"
            )

        self.running = True

    def stop(self):

        if self.server:
            self.server.stop()

        if self.server_thread:
            self.server_thread.join(timeout=3)

        self.running = False
        self.server = None
        self.server_thread = None

        debug.info("[NETWORK] Receptor encerrado.")

    def send(self, peer_id, message):

        if not isinstance(message, str) or not message:
            raise ValueError("Mensagem vazia ou inválida.")

        peer = database.get_peer(peer_id)

        if not peer:
            raise ValueError("Peer não encontrado.")

        result = self.router.send(
            self.local_name,
            peer,
            message
        )

        try:

            send_packet(
                result["host"],
                result["port"],
                result["packet"]
            )

        except Exception:

            database.register_message(
                peer_id,
                "OUT",
                "FAILED",
                len(message.encode("utf-8"))
            )

            raise

        database.register_message(
            peer_id,
            "OUT",
            "SENT",
            len(message.encode("utf-8"))
        )

    def _handle_packet(self, packet, address):

        sender_name = packet.get("sender")

        peer = database.get_peer_by_name(
            sender_name
        )

        if not peer:

            debug.warning(
                f"[B] Peer desconhecido: {sender_name}"
            )

            return

        try:

            message = self.router.receive(
                self.local_name,
                peer,
                packet
            )

            debug.info(
                f"[B] Mensagem recebida de {sender_name}."
            )

            if self.on_message:
                self.on_message(sender_name, message)

            else:
                print(
                    f"\nMensagem de {sender_name}: {message}\n"
                )

        except Exception as error:

            debug.error(
                f"[B] Mensagem rejeitada: {error}"
            )
