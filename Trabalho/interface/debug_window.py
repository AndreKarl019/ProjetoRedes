
import tkinter as tk
from tkinter import ttk

import queue

from core.debug_logger import debug


class DebugWindow:

    def __init__(self, parent):

        self.parent = parent
        self.window = None

        self.events = queue.Queue()

        self._callback = self._receive_event

    def open(self):

        if self.window and self.window.winfo_exists():

            self.window.lift()
            return

        self.window = tk.Toplevel(self.parent)

        self.window.title("SecurePeer - Monitor DEBUG")
        self.window.geometry("850x550")

        self.window.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

        toolbar = ttk.Frame(self.window, padding=10)
        toolbar.pack(fill="x")

        ttk.Label(
            toolbar,
            text="Monitor de comunicação",
            font=("Segoe UI", 14, "bold")
        ).pack(side="left")

        ttk.Button(
            toolbar,
            text="Limpar",
            command=self.clear
        ).pack(side="right")

        columns = (
            "time",
            "level",
            "message"
        )

        self.table = ttk.Treeview(
            self.window,
            columns=columns,
            show="headings"
        )

        self.table.heading("time", text="Horário")
        self.table.heading("level", text="Nível")
        self.table.heading("message", text="Evento")

        self.table.column("time", width=90)
        self.table.column("level", width=90)
        self.table.column("message", width=620)

        self.table.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        debug.subscribe(self._callback)

        self.window.after(
            100,
            self._process_events
        )

    def _receive_event(self, timestamp, level, message):

        self.events.put(
            (timestamp, level, message)
        )

    def _process_events(self):

        if not self.window or not self.window.winfo_exists():
            return

        while not self.events.empty():

            timestamp, level, message = self.events.get()

            self.table.insert(
                "",
                "end",
                values=(
                    timestamp,
                    level,
                    message
                )
            )

        self.window.after(
            100,
            self._process_events
        )

    def clear(self):

        for item in self.table.get_children():
            self.table.delete(item)

    def close(self):

        debug.unsubscribe(self._callback)

        self.window.destroy()
        self.window = None
