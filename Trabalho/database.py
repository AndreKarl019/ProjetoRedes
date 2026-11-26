import sqlite3
from contextlib import contextmanager

from config.settings import DATABASE_PATH


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with get_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                tunnel_ip TEXT NOT NULL,
                encryption_public TEXT NOT NULL,
                signing_public TEXT NOT NULL,
                trusted INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id INTEGER,
                direction TEXT NOT NULL,
                status TEXT NOT NULL,
                message_size INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(peer_id) REFERENCES peers(id)
                ON DELETE SET NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS received_nonces (
                peer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(peer_id, message_id),
                FOREIGN KEY(peer_id) REFERENCES peers(id)
                ON DELETE CASCADE
            )
        """)

        # Um peer pode possuir vários endereços simultaneamente.
        db.execute("""
            CREATE TABLE IF NOT EXISTS peer_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                interface TEXT NOT NULL DEFAULT '',
                last_seen TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(peer_id, address, port, source, interface),
                FOREIGN KEY(peer_id) REFERENCES peers(id)
                ON DELETE CASCADE
            )
        """)

        # Histórico de conversa por peer. O conteúdo fica no banco local.
        db.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL UNIQUE,
                direction TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(peer_id) REFERENCES peers(id)
                ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS identity_nonces (
                peer_id INTEGER NOT NULL,
                nonce TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(peer_id, nonce),
                FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
            )
        """)

        # Migração compatível: cada endereço já cadastrado vira um endpoint.
        db.execute("""
            INSERT OR IGNORE INTO peer_addresses
                (peer_id, address, port, source)
            SELECT id, address, port, 'manual'
            FROM peers
        """)


def add_peer(name, address, port, tunnel_ip,
             encryption_public, signing_public, trusted=False):
    if not name.strip():
        raise ValueError("Nome do peer inválido.")

    if not 1 <= int(port) <= 65535:
        raise ValueError("Porta inválida.")

    with get_connection() as db:
        cursor = db.execute("""
            INSERT INTO peers (
                name, address, port, tunnel_ip,
                encryption_public, signing_public, trusted
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name, address, int(port), tunnel_ip,
            encryption_public, signing_public, int(trusted)
        ))
        peer_id = cursor.lastrowid

        db.execute("""
            INSERT OR IGNORE INTO peer_addresses
                (peer_id, address, port, source)
            VALUES (?, ?, ?, 'manual')
        """, (peer_id, address, int(port)))


def get_peers():
    with get_connection() as db:
        rows = db.execute("""
            SELECT id, name, address, port, tunnel_ip,
                   encryption_public, signing_public, trusted
            FROM peers
            ORDER BY name
        """).fetchall()
        return [tuple(row) for row in rows]


def get_peer(peer_id):
    with get_connection() as db:
        row = db.execute("""
            SELECT id, name, address, port, tunnel_ip,
                   encryption_public, signing_public, trusted
            FROM peers WHERE id = ?
        """, (peer_id,)).fetchone()
        return tuple(row) if row else None


def get_peer_by_name(name):
    with get_connection() as db:
        row = db.execute("""
            SELECT id, name, address, port, tunnel_ip,
                   encryption_public, signing_public, trusted
            FROM peers WHERE name = ?
        """, (name,)).fetchone()
        return tuple(row) if row else None


def get_peer_by_public_keys(encryption_public, signing_public):
    with get_connection() as db:
        row = db.execute("""
            SELECT id, name, address, port, tunnel_ip,
                   encryption_public, signing_public, trusted
            FROM peers
            WHERE encryption_public = ? AND signing_public = ?
        """, (encryption_public, signing_public)).fetchone()
        return tuple(row) if row else None


def delete_peer(peer_id):
    with get_connection() as db:
        db.execute("DELETE FROM peers WHERE id = ?", (peer_id,))


def set_peer_trust(peer_id, trusted):
    with get_connection() as db:
        db.execute(
            "UPDATE peers SET trusted = ? WHERE id = ?",
            (int(trusted), peer_id)
        )


def add_peer_address(peer_id, address, port, source="identity",
                     interface=None, last_seen=True):
    if not 1 <= int(port) <= 65535:
        raise ValueError("Porta inválida.")

    interface = interface or ''
    with get_connection() as db:
        # A mesma combinação IP/porta é um único endpoint, mesmo que tenha
        # sido aprendida por fontes diferentes. A origem mais forte fica registrada.
        existing = db.execute("""
            SELECT id, source FROM peer_addresses
            WHERE peer_id = ? AND address = ? AND port = ?
            ORDER BY id LIMIT 1
        """, (peer_id, address, int(port))).fetchone()

        if existing:
            chosen_source = source if source == "observed" else existing["source"]
            db.execute("""
                UPDATE peer_addresses
                SET source = ?,
                    interface = CASE WHEN interface = '' THEN ? ELSE interface END,
                    last_seen = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_seen END
                WHERE id = ?
            """, (chosen_source, interface, int(last_seen), existing["id"]))
            return

        db.execute("""
            INSERT INTO peer_addresses
                (peer_id, address, port, source, interface, last_seen)
            VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END)
        """, (peer_id, address, int(port), source, interface, int(last_seen)))


def get_peer_addresses(peer_id):
    with get_connection() as db:
        rows = db.execute("""
            SELECT address, port, source, interface, last_seen, created_at
            FROM peer_addresses
            WHERE peer_id = ?
            ORDER BY
                CASE source WHEN 'observed' THEN 0 WHEN 'manual' THEN 1 ELSE 2 END,
                last_seen DESC,
                id ASC
        """, (peer_id,)).fetchall()
        return [dict(row) for row in rows]


def update_peer_primary_address(peer_id, address, port):
    with get_connection() as db:
        db.execute("""
            UPDATE peers SET address = ?, port = ? WHERE id = ?
        """, (address, int(port), peer_id))


def register_message(peer_id, direction, status, size):
    with get_connection() as db:
        db.execute("""
            INSERT INTO messages (peer_id, direction, status, message_size)
            VALUES (?, ?, ?, ?)
        """, (peer_id, direction, status, size))


def register_chat_message(peer_id, message_id, direction, content, status):
    with get_connection() as db:
        db.execute("""
            INSERT OR IGNORE INTO chat_messages
                (peer_id, message_id, direction, content, status)
            VALUES (?, ?, ?, ?, ?)
        """, (peer_id, message_id, direction, content, status))


def update_chat_message_status(message_id, status):
    with get_connection() as db:
        db.execute("""
            UPDATE chat_messages SET status = ? WHERE message_id = ?
        """, (status, message_id))


def get_chat_history(peer_id, limit=500):
    with get_connection() as db:
        rows = db.execute("""
            SELECT message_id, direction, content, status, created_at
            FROM chat_messages
            WHERE peer_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (peer_id, limit)).fetchall()
        return [dict(row) for row in reversed(rows)]


def register_nonce(peer_id, message_id):
    with get_connection() as db:
        cursor = db.execute("""
            INSERT OR IGNORE INTO received_nonces (peer_id, message_id)
            VALUES (?, ?)
        """, (peer_id, message_id))
        return cursor.rowcount == 1


def nonce_already_received(peer_id, message_id):
    with get_connection() as db:
        result = db.execute("""
            SELECT 1 FROM received_nonces
            WHERE peer_id = ? AND message_id = ?
        """, (peer_id, message_id)).fetchone()
        return result is not None


def get_message_history(limit=100):
    with get_connection() as db:
        rows = db.execute("""
            SELECT messages.id, peers.name, messages.direction,
                   messages.status, messages.message_size,
                   messages.created_at
            FROM messages
            LEFT JOIN peers ON messages.peer_id = peers.id
            ORDER BY messages.id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [tuple(row) for row in rows]


def identity_nonce_already_received(peer_id, nonce):
    with get_connection() as db:
        return db.execute(
            "SELECT 1 FROM identity_nonces WHERE peer_id = ? AND nonce = ?",
            (peer_id, nonce)
        ).fetchone() is not None


def register_identity_nonce(peer_id, nonce):
    with get_connection() as db:
        db.execute(
            "INSERT INTO identity_nonces (peer_id, nonce) VALUES (?, ?)",
            (peer_id, nonce)
        )
