
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

import base64
import ipaddress

import database

from security.key_manager import (
    generate_identity,
    list_identities
)

from security.peer_auth import public_key_fingerprint

from network.connection_manager import ConnectionManager

from interface.debug_window import DebugWindow
from interface.identity_window import IdentityWindow

from core.debug_logger import debug


class SecurePeerApp:

    def __init__(self, root):

        self.root = root
        self.root.title("SecurePeer")
        self.root.geometry("1050x700")
        self.root.minsize(850, 550)

        database.initialize_database()

        self.local_name = None
        self.manager = None

        self.debug_window = DebugWindow(root)

        self.create_interface()
        self.refresh_identities()
        self.refresh_peers()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

    def create_interface(self):

        header = tk.Frame(
            self.root,
            bg="#17243A",
            height=85
        )

        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="SecurePeer",
            font=("Segoe UI", 23, "bold"),
            fg="white",
            bg="#17243A"
        ).pack(side="left", padx=25, pady=20)

        tk.Label(
            header,
            text="ENCRYPTED P2P COMMUNICATION",
            font=("Segoe UI", 9),
            fg="#54D6A0",
            bg="#17243A"
        ).pack(side="right", padx=25)

        content = ttk.Frame(
            self.root,
            padding=20
        )

        content.pack(fill="both", expand=True)

        # IDENTIDADE LOCAL

        identity_frame = ttk.LabelFrame(
            content,
            text="Identidade local",
            padding=10
        )

        identity_frame.pack(fill="x", pady=5)

        self.identity_var = tk.StringVar()

        self.identity_select = ttk.Combobox(
            identity_frame,
            textvariable=self.identity_var,
            state="readonly",
            width=25
        )

        self.identity_select.pack(side="left", padx=5)

        self.identity_select.bind(
            "<<ComboboxSelected>>",
            self.select_identity
        )

        ttk.Button(
            identity_frame,
            text="Criar identidade",
            command=self.create_identity
        ).pack(side="left", padx=5)

        ttk.Button(
            identity_frame,
            text="Minha identidade",
            command=self.open_identity
        ).pack(side="left", padx=5)

        # TABELA DE PEERS

        peer_frame = ttk.LabelFrame(
            content,
            text="Tabela de conexões",
            padding=10
        )

        peer_frame.pack(
            fill="both",
            expand=True,
            pady=10
        )

        columns = (
            "id",
            "name",
            "address",
            "port",
            "tunnel",
            "trust"
        )

        self.peer_table = ttk.Treeview(
            peer_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "id": "ID",
            "name": "Peer",
            "address": "Endereço",
            "port": "Porta",
            "tunnel": "IP virtual",
            "trust": "Confiança"
        }

        widths = {
            "id": 40,
            "name": 140,
            "address": 160,
            "port": 70,
            "tunnel": 130,
            "trust": 140
        }

        for column, heading in headings.items():

            self.peer_table.heading(
                column,
                text=heading
            )

            self.peer_table.column(
                column,
                anchor="center",
                width=widths[column]
            )

        self.peer_table.pack(
            fill="both",
            expand=True
        )

        peer_buttons = ttk.Frame(peer_frame)
        peer_buttons.pack(fill="x", pady=8)

        ttk.Button(
            peer_buttons,
            text="Adicionar peer",
            command=self.add_peer_window
        ).pack(side="left", padx=4)

        ttk.Button(
            peer_buttons,
            text="Verificar fingerprint",
            command=self.verify_peer
        ).pack(side="left", padx=4)

        ttk.Button(
            peer_buttons,
            text="Remover peer",
            command=self.remove_peer
        ).pack(side="left", padx=4)

        # COMUNICAÇÃO

        message_frame = ttk.LabelFrame(
            content,
            text="Comunicação",
            padding=10
        )

        message_frame.pack(fill="x", pady=5)

        self.message_entry = ttk.Entry(message_frame)

        self.message_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )

        self.message_entry.bind(
            "<Return>",
            lambda event: self.send_message()
        )

        ttk.Button(
            message_frame,
            text="Enviar mensagem",
            command=self.send_message
        ).pack(side="left", padx=5)

        self.received_label = ttk.Label(
            content,
            text="Última mensagem recebida: nenhuma",
            wraplength=950
        )

        self.received_label.pack(
            anchor="w",
            pady=5
        )

        # CONTROLES

        controls = ttk.Frame(content)
        controls.pack(fill="x", pady=10)

        ttk.Button(
            controls,
            text="Iniciar receptor",
            command=self.start_receiver
        ).pack(side="left", padx=4)

        ttk.Button(
            controls,
            text="Parar receptor",
            command=self.stop_receiver
        ).pack(side="left", padx=4)

        ttk.Button(
            controls,
            text="Monitor DEBUG",
            command=self.debug_window.open
        ).pack(side="right", padx=4)

        self.status_label = ttk.Label(
            content,
            text="Receptor parado"
        )

        self.status_label.pack(anchor="w")

    # IDENTIDADES

    def refresh_identities(self):

        identities = list_identities()

        self.identity_select["values"] = identities

        if self.local_name not in identities:

            self.local_name = None
            self.identity_var.set("")

        if identities and not self.identity_var.get():

            self.identity_var.set(identities[0])
            self.select_identity()

    def create_identity(self):

        name = simpledialog.askstring(
            "Nova identidade",
            "Nome da identidade:",
            parent=self.root
        )

        if not name:
            return

        name = name.strip()

        try:

            generate_identity(name)

            self.refresh_identities()

            self.identity_var.set(name)
            self.select_identity()

            messagebox.showinfo(
                "SecurePeer",
                f"Identidade {name} criada."
            )

        except Exception as error:

            messagebox.showerror(
                "Erro",
                str(error)
            )

    def select_identity(self, event=None):

        name = self.identity_var.get()

        if not name:
            return

        if self.manager:
            self.stop_receiver()

        self.local_name = name

        self.status_label.config(
            text=f"Identidade ativa: {name} | Receptor parado"
        )

        debug.info(
            f"Identidade selecionada: {name}"
        )

    def open_identity(self):

        if not self.local_name:

            messagebox.showwarning(
                "Atenção",
                "Selecione uma identidade primeiro."
            )

            return

        try:

            IdentityWindow(
                self.root,
                self.local_name
            )

        except Exception as error:

            messagebox.showerror(
                "Erro",
                str(error)
            )

    # PEERS

    def refresh_peers(self):

        for item in self.peer_table.get_children():
            self.peer_table.delete(item)

        for peer in database.get_peers():

            self.peer_table.insert(
                "",
                "end",
                values=(
                    peer[0],
                    peer[1],
                    peer[2],
                    peer[3],
                    peer[4],
                    "Confiável" if peer[7] else "Não verificado"
                )
            )

    def add_peer_window(self):

        window = tk.Toplevel(self.root)

        window.title("Adicionar peer")
        window.geometry("540x590")
        window.transient(self.root)

        fields = {}

        labels = [
            ("Nome do peer", "name"),
            ("Endereço IP", "address"),
            ("Porta TCP", "port"),
            ("IP virtual", "tunnel_ip"),
            ("Chave pública X25519", "encryption_public"),
            ("Chave pública Ed25519", "signing_public")
        ]

        for label, key in labels:

            ttk.Label(
                window,
                text=label
            ).pack(
                anchor="w",
                padx=20,
                pady=(10, 2)
            )

            entry = ttk.Entry(window, width=65)
            entry.pack(padx=20, fill="x")

            fields[key] = entry

        trusted_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            window,
            text="Já verifiquei as fingerprints por canal independente",
            variable=trusted_var
        ).pack(anchor="w", padx=20, pady=15)

        def save():

            try:

                values = {
                    key: entry.get().strip()
                    for key, entry in fields.items()
                }

                if not all(values.values()):
                    raise ValueError("Preencha todos os campos.")

                ipaddress.ip_address(values["address"])
                ipaddress.ip_address(values["tunnel_ip"])

                port = int(values["port"])

                if not 1 <= port <= 65535:
                    raise ValueError("Porta inválida.")

                encryption_bytes = base64.b64decode(
                    values["encryption_public"],
                    validate=True
                )

                signing_bytes = base64.b64decode(
                    values["signing_public"],
                    validate=True
                )

                if len(encryption_bytes) != 32:
                    raise ValueError("Chave pública X25519 inválida.")

                if len(signing_bytes) != 32:
                    raise ValueError("Chave pública Ed25519 inválida.")

                database.add_peer(
                    values["name"],
                    values["address"],
                    port,
                    values["tunnel_ip"],
                    values["encryption_public"],
                    values["signing_public"],
                    trusted_var.get()
                )

                self.refresh_peers()

                debug.info(
                    f"Peer cadastrado: {values['name']}"
                )

                window.destroy()

                messagebox.showinfo(
                    "SecurePeer",
                    "Peer cadastrado com sucesso."
                )

            except Exception as error:

                messagebox.showerror(
                    "Erro",
                    str(error),
                    parent=window
                )

        ttk.Button(
            window,
            text="Cadastrar peer",
            command=save
        ).pack(pady=15)

    def get_selected_peer(self):

        selected = self.peer_table.selection()

        if not selected:
            return None

        values = self.peer_table.item(
            selected[0],
            "values"
        )

        return database.get_peer(int(values[0]))

    def verify_peer(self):

        peer = self.get_selected_peer()

        if not peer:

            messagebox.showwarning(
                "Atenção",
                "Selecione um peer."
            )

            return

        encryption_fp = public_key_fingerprint(peer[5])
        signing_fp = public_key_fingerprint(peer[6])

        confirmed = messagebox.askyesno(
            "Verificar identidade",
            f"Peer: {peer[1]}\n\n"
            f"Fingerprint X25519:\n{encryption_fp}\n\n"
            f"Fingerprint Ed25519:\n{signing_fp}\n\n"
            "Você confirmou essas fingerprints por "
            "um canal independente?",
            parent=self.root
        )

        if confirmed:

            database.set_peer_trust(peer[0], True)

            self.refresh_peers()

            messagebox.showinfo(
                "SecurePeer",
                "Peer marcado como confiável."
            )

    def remove_peer(self):

        peer = self.get_selected_peer()

        if not peer:
            return

        confirmed = messagebox.askyesno(
            "Confirmar remoção",
            f"Deseja remover o peer {peer[1]}?",
            parent=self.root
        )

        if confirmed:

            database.delete_peer(peer[0])
            self.refresh_peers()

            debug.info(
                f"Peer removido: {peer[1]}"
            )

    # COMUNICAÇÃO

    def start_receiver(self):

        if not self.local_name:

            messagebox.showwarning(
                "Atenção",
                "Selecione uma identidade."
            )

            return

        if self.manager:
            return

        try:

            manager = ConnectionManager(self.local_name)

            manager.on_message = self.message_received

            manager.start()

            self.manager = manager

            self.status_label.config(
                text="Receptor iniciado"
            )

        except Exception as error:

            self.manager = None

            messagebox.showerror(
                "Erro",
                str(error)
            )

    def stop_receiver(self):

        if self.manager:

            manager = self.manager
            self.manager = None

            manager.stop()

            self.status_label.config(
                text="Receptor parado"
            )

    def send_message(self):

        if not self.manager:

            messagebox.showwarning(
                "Atenção",
                "Inicie o receptor antes de enviar."
            )

            return

        peer = self.get_selected_peer()

        if not peer:

            messagebox.showwarning(
                "Atenção",
                "Selecione um peer."
            )

            return

        message = self.message_entry.get()

        if not message:
            return

        try:

            self.manager.send(peer[0], message)

            self.message_entry.delete(0, "end")

        except Exception as error:

            messagebox.showerror(
                "Erro de envio",
                str(error)
            )

    def message_received(self, sender, message):

        self.root.after(
            0,
            lambda: self.received_label.config(
                text=f"Última mensagem de {sender}: {message}"
            )
        )

    # ENCERRAMENTO

    def close(self):

        self.stop_receiver()
        self.root.destroy()
