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
        self.window.geometry("680x560")
        self.window.minsize(480, 360)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.create_interface()
        self.refresh_history()

    def create_interface(self):
        header = ttk.Frame(self.window, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=self.peer_name, font=("Segoe UI", 16, "bold")).pack(side="left")
        self.state_label = ttk.Label(header, text="Mensagens protegidas • receptor conforme status da janela principal")
        self.state_label.pack(side="right")

        body = ttk.Frame(self.window, padding=(12, 0, 12, 8))
        body.pack(fill="both", expand=True)
        self.history = tk.Text(body, wrap="word", state="disabled", font=("Segoe UI", 10))
        scrollbar = ttk.Scrollbar(body, command=self.history.yview)
        self.history.configure(yscrollcommand=scrollbar.set)
        self.history.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        compose = ttk.Frame(self.window, padding=12)
        compose.pack(fill="x")
        self.entry = tk.Text(compose, height=3, wrap="word")
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry.bind("<Control-Return>", lambda event: self.send())
        ttk.Button(compose, text="Enviar", command=self.send).pack(side="right", anchor="s")

    def refresh_history(self):
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
        message = self.entry.get("1.0", "end").strip()
        if not message:
            return
        if not self.app.manager or not self.app.manager.running:
            messagebox.showwarning("SecurePeer", "Inicie o receptor na janela principal antes de enviar.", parent=self.window)
            return
        try:
            self.app.manager.send(self.peer_id, message)
            self.entry.delete("1.0", "end")
            self.refresh_history()
        except Exception as error:
            messagebox.showerror("Falha no envio", str(error), parent=self.window)
            self.refresh_history()

    def append_received(self):
        if self.window.winfo_exists():
            self.refresh_history()

    def close(self):
        self.app.chat_windows.pop(self.peer_id, None)
        self.window.destroy()
