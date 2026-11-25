import base64
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

import database
from config.settings import MESSAGE_PORT
from core.debug_logger import debug
from interface.chat_window import ChatWindow
from interface.debug_window import DebugWindow
from interface.identity_window import IdentityWindow
from network.connection_manager import ConnectionManager
from security.key_manager import generate_identity, list_identities, update_local_addresses
from security.peer_auth import public_key_fingerprint


class SecurePeerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePeer")
        self.root.geometry("1050x680")
        self.root.minsize(850, 520)
        database.initialize_database()
        self.local_name = None
        self.manager = None
        self.chat_windows = {}
        self.debug_window = DebugWindow(root)
        self.create_interface()
        self.refresh_identities()
        self.refresh_peers()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def create_interface(self):
        header = tk.Frame(self.root, bg="#17243A", height=82)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="SecurePeer", font=("Segoe UI", 23, "bold"), fg="white", bg="#17243A").pack(side="left", padx=25, pady=18)
        tk.Label(header, text="ENCRYPTED P2P COMMUNICATION", font=("Segoe UI", 9), fg="#54D6A0", bg="#17243A").pack(side="right", padx=25)

        content = ttk.Frame(self.root, padding=20)
        content.pack(fill="both", expand=True)

        identity_frame = ttk.LabelFrame(content, text="Identidade local", padding=10)
        identity_frame.pack(fill="x", pady=5)
        self.identity_var = tk.StringVar()
        self.identity_select = ttk.Combobox(identity_frame, textvariable=self.identity_var, state="readonly", width=25)
        self.identity_select.pack(side="left", padx=5)
        self.identity_select.bind("<<ComboboxSelected>>", self.select_identity)
        ttk.Button(identity_frame, text="Criar identidade", command=self.create_identity).pack(side="left", padx=5)
        ttk.Button(identity_frame, text="Minha identidade", command=self.open_identity).pack(side="left", padx=5)

        peer_frame = ttk.LabelFrame(content, text="Tabela de conexões", padding=10)
        peer_frame.pack(fill="both", expand=True, pady=10)
        columns = ("id", "name", "address", "port", "tunnel", "trust")
        self.peer_table = ttk.Treeview(peer_frame, columns=columns, show="headings", height=14)
        headings = {"id": "ID", "name": "Peer", "address": "Endereço principal", "port": "Porta", "tunnel": "IP virtual", "trust": "Confiança"}
        widths = {"id": 40, "name": 140, "address": 190, "port": 70, "tunnel": 130, "trust": 140}
        for column, heading in headings.items():
            self.peer_table.heading(column, text=heading)
            self.peer_table.column(column, anchor="center", width=widths[column])
        self.peer_table.pack(fill="both", expand=True)
        self.peer_table.bind("<Double-1>", lambda event: self.open_chat())

        actions = ttk.Frame(peer_frame)
        actions.pack(fill="x", pady=8)
        left = ttk.Frame(actions)
        left.pack(side="left")
        ttk.Button(left, text="Adicionar peer", command=self.add_peer_window).pack(side="left", padx=4)
        ttk.Button(left, text="Verificar fingerprint", command=self.verify_peer).pack(side="left", padx=4)
        ttk.Button(left, text="Remover peer", command=self.remove_peer).pack(side="left", padx=4)
        ttk.Button(actions, text="Enviar identidade", command=self.send_identity).pack(side="right", padx=4)
        ttk.Button(actions, text="Abrir conversa", command=self.open_chat).pack(side="right", padx=4)

        controls = ttk.Frame(content)
        controls.pack(fill="x", pady=8)
        ttk.Button(controls, text="Iniciar receptor", command=self.start_receiver).pack(side="left", padx=4)
        ttk.Button(controls, text="Parar receptor", command=self.stop_receiver).pack(side="left", padx=4)
        ttk.Button(controls, text="Monitor DEBUG", command=self.debug_window.open).pack(side="right", padx=4)
        self.status_label = ttk.Label(content, text="Receptor parado")
        self.status_label.pack(anchor="w")

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
        name = simpledialog.askstring("Nova identidade", "Nome da identidade:", parent=self.root)
        if not name:
            return
        try:
            generate_identity(name.strip())
            self.identity_var.set(name.strip())
            self.refresh_identities()
            self.select_identity()
            messagebox.showinfo("SecurePeer", f"Identidade {name.strip()} criada.")
        except Exception as error:
            messagebox.showerror("Erro", str(error), parent=self.root)

    def select_identity(self, event=None):
        name = self.identity_var.get()
        if not name:
            return
        if self.manager:
            self.stop_receiver()
        self.local_name = name
        try:
            addresses = update_local_addresses(name)
            debug.info(f"Identidade {name}: {len(addresses)} endereço(s) local(is) acumulado(s).")
        except Exception as error:
            messagebox.showerror("Atualização de endereços", str(error), parent=self.root)
        self.status_label.config(text=f"Identidade ativa: {name} | Receptor parado")

    def open_identity(self):
        if not self.local_name:
            messagebox.showwarning("Atenção", "Selecione uma identidade primeiro.", parent=self.root)
            return
        IdentityWindow(self.root, self.local_name)

    def refresh_peers(self):
        for item in self.peer_table.get_children():
            self.peer_table.delete(item)
        for peer in database.get_peers():
            addresses = database.get_peer_addresses(peer[0])
            address_text = peer[2] if not addresses else f'{addresses[0]["address"]} (+{max(0, len(addresses)-1)})'
            self.peer_table.insert("", "end", values=(peer[0], peer[1], address_text, peer[3], peer[4], "Confiável" if peer[7] else "Não verificado"))

    def add_peer_window(self):
        window = tk.Toplevel(self.root)
        window.title("Adicionar peer")
        window.geometry("540x590")
        window.transient(self.root)
        fields = {}
        for label, key in [("Nome da identidade do peer (exatamente como criada na outra máquina)", "name"), ("Endereço IP", "address"), ("Porta TCP", "port"), ("IP virtual", "tunnel_ip"), ("Chave pública X25519", "encryption_public"), ("Chave pública Ed25519", "signing_public")]:
            ttk.Label(window, text=label).pack(anchor="w", padx=20, pady=(10, 2))
            entry = ttk.Entry(window, width=65)
            entry.pack(padx=20, fill="x")
            fields[key] = entry
        trusted_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(window, text="Já verifiquei as fingerprints por canal independente", variable=trusted_var).pack(anchor="w", padx=20, pady=15)

        def save():
            try:
                values = {key: entry.get().strip() for key, entry in fields.items()}
                if not all(values.values()):
                    raise ValueError("Preencha todos os campos.")
                ipaddress.ip_address(values["address"])
                ipaddress.ip_address(values["tunnel_ip"])
                port = int(values["port"])
                if not 1 <= port <= 65535:
                    raise ValueError("Porta inválida.")
                encryption = base64.b64decode(values["encryption_public"], validate=True)
                signing = base64.b64decode(values["signing_public"], validate=True)
                if len(encryption) != 32 or len(signing) != 32:
                    raise ValueError("As chaves públicas devem ter 32 bytes.")
                database.add_peer(values["name"], values["address"], port, values["tunnel_ip"], values["encryption_public"], values["signing_public"], trusted_var.get())
                self.refresh_peers()
                window.destroy()
                messagebox.showinfo("SecurePeer", "Peer cadastrado com sucesso.", parent=self.root)
            except Exception as error:
                messagebox.showerror("Erro", str(error), parent=window)
        ttk.Button(window, text="Cadastrar peer", command=save).pack(pady=15)

    def get_selected_peer(self):
        selected = self.peer_table.selection()
        if not selected:
            return None
        values = self.peer_table.item(selected[0], "values")
        return database.get_peer(int(values[0]))

    def verify_peer(self):
        peer = self.get_selected_peer()
        if not peer:
            messagebox.showwarning("Atenção", "Selecione um peer.", parent=self.root)
            return
        text = (f"Peer: {peer[1]}\n\nFingerprint X25519:\n{public_key_fingerprint(peer[5])}\n\nFingerprint Ed25519:\n{public_key_fingerprint(peer[6])}\n\nVocê confirmou essas fingerprints por um canal independente?")
        if messagebox.askyesno("Verificar identidade", text, parent=self.root):
            database.set_peer_trust(peer[0], True)
            self.refresh_peers()
            messagebox.showinfo("SecurePeer", "Peer marcado como confiável.", parent=self.root)

    def remove_peer(self):
        peer = self.get_selected_peer()
        if peer and messagebox.askyesno("Confirmar remoção", f"Deseja remover o peer {peer[1]}?", parent=self.root):
            database.delete_peer(peer[0])
            chat = self.chat_windows.pop(peer[0], None)
            if chat:
                chat.close()
            self.refresh_peers()

    def start_receiver(self):
        if not self.local_name:
            messagebox.showwarning("Atenção", "Selecione uma identidade.", parent=self.root)
            return
        if self.manager:
            return
        try:
            manager = ConnectionManager(self.local_name)
            manager.on_message = self.message_received
            manager.on_identity_synced = self.identity_synced
            manager.start()
            self.manager = manager
            self.status_label.config(text=f"Receptor iniciado em TCP {MESSAGE_PORT}")
        except Exception as error:
            self.manager = None
            messagebox.showerror("Erro", str(error), parent=self.root)

    def stop_receiver(self):
        if self.manager:
            self.manager.stop()
            self.manager = None
        self.status_label.config(text="Receptor parado")

    def send_identity(self):
        peer = self.get_selected_peer()
        if not peer:
            messagebox.showwarning("Atenção", "Selecione um peer.", parent=self.root)
            return
        if not self.manager:
            messagebox.showwarning("Atenção", "Inicie o receptor antes de enviar a identidade.", parent=self.root)
            return
        try:
            update_local_addresses(self.local_name)
            count = self.manager.send_identity(peer[0])
            self.refresh_peers()
            messagebox.showinfo("SecurePeer", f"Identidade sincronizada com {peer[1]}.\nForam recebidos {count} endereço(s) anunciados pelo peer.", parent=self.root)
        except Exception as error:
            messagebox.showerror("Falha na sincronização", str(error), parent=self.root)

    def open_chat(self):
        peer = self.get_selected_peer()
        if not peer:
            messagebox.showwarning("Atenção", "Selecione um peer.", parent=self.root)
            return
        existing = self.chat_windows.get(peer[0])
        if existing and existing.window.winfo_exists():
            existing.window.lift()
            return
        self.chat_windows[peer[0]] = ChatWindow(self, peer)

    def identity_synced(self, peer_id, sender):
        self.root.after(0, self.refresh_peers)

    def message_received(self, peer_id, sender, message, message_id):
        def update_ui():
            self.refresh_peers()
            chat = self.chat_windows.get(peer_id)
            if chat:
                chat.append_received()
        self.root.after(0, update_ui)

    def close(self):
        self.stop_receiver()
        for chat in list(self.chat_windows.values()):
            try:
                chat.window.destroy()
            except tk.TclError:
                pass
        self.chat_windows.clear()
        self.root.destroy()
