import json
import socket
import struct
import threading

from config.settings import MAX_MESSAGE_SIZE, SOCKET_TIMEOUT
from core.debug_logger import debug


def _send_json(sock, packet):
    data = json.dumps(packet, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("Pacote excede o tamanho permitido.")
    sock.sendall(struct.pack("!I", len(data)) + data)


def send_packet(host, port, packet, expect_response=True):
    with socket.create_connection((host, int(port)), timeout=SOCKET_TIMEOUT) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        _send_json(sock, packet)
        if not expect_response:
            return None
        return receive_packet(sock)


def receive_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("Conexão encerrada.")
        result.extend(chunk)
    return bytes(result)


def receive_packet(sock):
    header = receive_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError("Tamanho de pacote inválido.")
    packet = json.loads(receive_exact(sock, size).decode("utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("Pacote inválido.")
    return packet


class MessageServer:
    def __init__(self, host, port, callback):
        self.host, self.port, self.callback = host, port, callback
        self.server = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.startup_error = None

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(10)
            self.server.settimeout(1)
            self.ready_event.set()
            debug.info(f"[NETWORK] Receptor iniciado em {self.host}:{self.port}.")
            while not self.stop_event.is_set():
                try:
                    conn, address = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                threading.Thread(target=self._handle_client, args=(conn, address), daemon=True).start()
        except Exception as error:
            self.startup_error = error
            self.ready_event.set()
            debug.error(f"[NETWORK] Erro no servidor: {error}")
        finally:
            if self.server:
                self.server.close()
                self.server = None

    def _handle_client(self, conn, address):
        with conn:
            try:
                conn.settimeout(SOCKET_TIMEOUT)
                packet = receive_packet(conn)
                response = self.callback(packet, address)
                if response is not None:
                    _send_json(conn, response)
            except Exception as error:
                debug.error(f"[NETWORK] Falha no recebimento de {address}: {error}")

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.server.close()
