
import logging
import threading
from datetime import datetime


class DebugLogger:

    def __init__(self):

        self.logger = logging.getLogger("SecurePeer")
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:

            handler = logging.StreamHandler()

            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(message)s",
                    datefmt="%H:%M:%S"
                )
            )

            self.logger.addHandler(handler)

        self.callbacks = []
        self.lock = threading.Lock()

    def subscribe(self, callback):

        with self.lock:
            self.callbacks.append(callback)

    def unsubscribe(self, callback):

        with self.lock:
            if callback in self.callbacks:
                self.callbacks.remove(callback)

    def log(self, level, message):

        timestamp = datetime.now().strftime("%H:%M:%S")

        if level == "ERROR":
            self.logger.error(message)

        elif level == "WARNING":
            self.logger.warning(message)

        else:
            self.logger.info(message)

        with self.lock:
            callbacks = list(self.callbacks)

        for callback in callbacks:
            try:
                callback(timestamp, level, message)
            except Exception:
                self.logger.exception(
                    "Erro ao notificar observador DEBUG."
                )

    def info(self, message):
        self.log("INFO", message)

    def warning(self, message):
        self.log("WARNING", message)

    def error(self, message):
        self.log("ERROR", message)


debug = DebugLogger()
