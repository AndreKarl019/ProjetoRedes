import tkinter as tk
from tkinter import ttk, messagebox

import database


class ChatWindow:
    def __init__(self, app, peer):
        self.app = app
        self.peer_id = peer[0]
        self.peer_name = peer[1]
        self.window = tk.Toplevel(app.root)
        self.window.title(f"SecurePeer — {self.peer_name}")
        self.window.geometry("700x580")
        self.window.minsize(500, 400)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.create_interface()
        self.refresh_history()

    def create_interface(self):
        header = ttk.Frame(self.window, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=self.peer_name, font=("Segoe UI", 16, "bold")).pack(side="left")
        self.state_label = ttk.Label(header, text="Mensagens protegidas")
        self.state_label.pack(side="right")

        body = ttk.Frame(self.window, padding=(12, 0, 12, 8))
        body.pack(fill="both", expand=True)
        self.history = tk.Text(body, wrap="word", state="disabled", font=("Segoe UI", 10))
        scrollbar = ttk.Scrollbar(body, command=self.history.yview)
        self.history.configure(yscrollcommand=scrollbar.set)
        self.history.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        compose = ttk.LabelFrame(self.window, text="Mensagem", padding=10)
        compose.pack(fill="x", padx=12, pady=(0, 12))
        self.entry = tk.Text(compose, height=4, wrap="word", font=("Segoe UI", 10), undo=True)
        self.entry.pack(fill="x", expand=True, pady=(0, 8))
        # Enter envia; Shift+Enter insere uma nova linha; Ctrl+Enter também envia.
        self.entry.bind("<Return>", self._enter_sends)
        self.entry.bind("<Control-Return>", self._control_enter_sends)
        self.entry.bind("<Shift-Return>", self._shift_enter_newline)

        buttons = ttk.Frame(compose)
        buttons.pack(fill="x")
        ttk.Label(buttons, text="Enter: enviar  •  Shift+Enter: nova linha").pack(side="left")
        self.send_button = ttk.Button(buttons, text="Enviar mensagem", command=self.send)
        self.send_button.pack(side="right")

    def _enter_sends(self, event=None):
        self.send()
        return "break"

    def _control_enter_sends(self, event=None):
        self.send()
        return "break"

    def _shift_enter_newline(self, event=None):
        self.entry.insert("insert", "\n")
        return "break"

    def refresh_history(self):
        if not self.window.winfo_exists():
            return
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        for item in database.get_chat_history(self.peer_id):
            direction = "Você" if item["direction"] == "OUT" else self.peer_name
            status = item["status"]
            self.history.insert("end", f'{item["created_at"]}  |  {direction}  |  {status}\n', "meta")
            self.history.insert("end", item["content"] + "\n\n")
        self.history.tag_configure("meta", foreground="#55708a", font=("Segoe UI", 8))
        self.history.configure(state="disabled")
        self.history.see("end")

    def send(self):
        message = self.entry.get("1.0", "end-1c").strip()
        if not message:
            return
        if not self.app.manager or not self.app.manager.running:
            messagebox.showwarning("SecurePeer", "Inicie o receptor na janela principal antes de enviar.", parent=self.window)
            return
        self.send_button.configure(state="disabled")
        try:
            self.app.manager.send(self.peer_id, message)
            self.entry.delete("1.0", "end")
            self.refresh_history()
        except Exception as error:
            messagebox.showerror("Falha no envio", str(error), parent=self.window)
            self.refresh_history()
        finally:
            if self.window.winfo_exists():
                self.send_button.configure(state="normal")
                self.entry.focus_set()

    def append_received(self):
        if self.window.winfo_exists():
            self.refresh_history()

    def close(self):
        self.app.chat_windows.pop(self.peer_id, None)
        self.window.destroy()
