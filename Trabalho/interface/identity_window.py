
import tkinter as tk

from tkinter import ttk, filedialog, messagebox

import json

from security.key_manager import (
    export_identity
)

from security.peer_auth import (
    public_key_fingerprint
)


class IdentityWindow:

    def __init__(self, parent, identity_name):

        self.parent = parent
        self.identity_name = identity_name

        self.identity = export_identity(identity_name)

        self.window = tk.Toplevel(parent)

        self.window.title("SecurePeer - Minha identidade")
        self.window.geometry("650x560")
        self.window.resizable(False, False)

        self.create_interface()

    def create_field(self, parent, title, value):

        frame = ttk.LabelFrame(
            parent,
            text=title,
            padding=10
        )

        frame.pack(fill="x", padx=15, pady=8)

        text = tk.Text(
            frame,
            height=3,
            wrap="word",
            font=("Consolas", 9)
        )

        text.pack(fill="x")

        text.insert("1.0", value)
        text.configure(state="disabled")

        ttk.Button(
            frame,
            text="Copiar",
            command=lambda: self.copy(value)
        ).pack(anchor="e", pady=5)

    def copy(self, value):

        self.window.clipboard_clear()
        self.window.clipboard_append(value)
        self.window.update()

        messagebox.showinfo(
            "SecurePeer",
            "Copiado para a área de transferência."
        )

    def create_interface(self):

        header = ttk.Frame(
            self.window,
            padding=15
        )

        header.pack(fill="x")

        ttk.Label(
            header,
            text="Identidade criptográfica",
            font=("Segoe UI", 17, "bold")
        ).pack(anchor="w")

        ttk.Label(
            header,
            text=f"Identidade: {self.identity_name}"
        ).pack(anchor="w", pady=5)

        self.create_field(
            self.window,
            "Chave pública X25519",
            self.identity["encryption_public"]
        )

        self.create_field(
            self.window,
            "Chave pública Ed25519",
            self.identity["signing_public"]
        )

        encryption_fp = public_key_fingerprint(
            self.identity["encryption_public"]
        )

        signing_fp = public_key_fingerprint(
            self.identity["signing_public"]
        )

        fingerprint_frame = ttk.LabelFrame(
            self.window,
            text="Fingerprints",
            padding=10
        )

        fingerprint_frame.pack(
            fill="x",
            padx=15,
            pady=8
        )

        ttk.Label(
            fingerprint_frame,
            text="X25519:"
        ).pack(anchor="w")

        ttk.Label(
            fingerprint_frame,
            text=encryption_fp,
            font=("Consolas", 9)
        ).pack(anchor="w", pady=3)

        ttk.Label(
            fingerprint_frame,
            text="Ed25519:"
        ).pack(anchor="w", pady=(8, 0))

        ttk.Label(
            fingerprint_frame,
            text=signing_fp,
            font=("Consolas", 9)
        ).pack(anchor="w", pady=3)

        ttk.Button(
            self.window,
            text="Exportar identidade pública (.json)",
            command=self.export
        ).pack(pady=15)

    def export(self):

        path = filedialog.asksaveasfilename(
            parent=self.window,
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json")
            ],
            initialfile=f"{self.identity_name}_public.json"
        )

        if not path:
            return

        try:

            with open(path, "w", encoding="utf-8") as file:

                json.dump(
                    self.identity,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

            messagebox.showinfo(
                "SecurePeer",
                "Identidade pública exportada com sucesso."
            )

        except OSError as error:

            messagebox.showerror(
                "Erro",
                str(error)
            )
