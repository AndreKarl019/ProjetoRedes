
import sqlite3
from contextlib import contextmanager

from config.settings import DATABASE_PATH


@contextmanager
def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    try:
        connection.execute("PRAGMA foreign_keys = ON")
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


def add_peer(
    name,
    address,
    port,
    tunnel_ip,
    encryption_public,
    signing_public,
    trusted=False
):

    if not name.strip():
        raise ValueError("Nome do peer inválido.")

    if not 1 <= int(port) <= 65535:
        raise ValueError("Porta inválida.")

    with get_connection() as db:

        db.execute("""
            INSERT INTO peers (
                name,
                address,
                port,
                tunnel_ip,
                encryption_public,
                signing_public,
                trusted
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            address,
            int(port),
            tunnel_ip,
            encryption_public,
            signing_public,
            int(trusted)
        ))


def get_peers():

    with get_connection() as db:

        return db.execute("""
            SELECT
                id,
                name,
                address,
                port,
                tunnel_ip,
                encryption_public,
                signing_public,
                trusted
            FROM peers
            ORDER BY name
        """).fetchall()


def get_peer(peer_id):

    with get_connection() as db:

        return db.execute("""
            SELECT
                id,
                name,
                address,
                port,
                tunnel_ip,
                encryption_public,
                signing_public,
                trusted
            FROM peers
            WHERE id = ?
        """, (peer_id,)).fetchone()


def get_peer_by_name(name):

    with get_connection() as db:

        return db.execute("""
            SELECT
                id,
                name,
                address,
                port,
                tunnel_ip,
                encryption_public,
                signing_public,
                trusted
            FROM peers
            WHERE name = ?
        """, (name,)).fetchone()


def delete_peer(peer_id):

    with get_connection() as db:

        db.execute(
            "DELETE FROM peers WHERE id = ?",
            (peer_id,)
        )


def set_peer_trust(peer_id, trusted):

    with get_connection() as db:

        db.execute("""
            UPDATE peers
            SET trusted = ?
            WHERE id = ?
        """, (int(trusted), peer_id))


def register_message(peer_id, direction, status, size):

    with get_connection() as db:

        db.execute("""
            INSERT INTO messages (
                peer_id,
                direction,
                status,
                message_size
            )
            VALUES (?, ?, ?, ?)
        """, (
            peer_id,
            direction,
            status,
            size
        ))


def register_nonce(peer_id, message_id):

    with get_connection() as db:

        db.execute("""
            INSERT INTO received_nonces (
                peer_id,
                message_id
            )
            VALUES (?, ?)
        """, (
            peer_id,
            message_id
        ))


def nonce_already_received(peer_id, message_id):

    with get_connection() as db:

        result = db.execute("""
            SELECT 1
            FROM received_nonces
            WHERE peer_id = ? AND message_id = ?
        """, (
            peer_id,
            message_id
        )).fetchone()

        return result is not None


def get_message_history(limit=100):

    with get_connection() as db:

        return db.execute("""
            SELECT
                messages.id,
                peers.name,
                messages.direction,
                messages.status,
                messages.message_size,
                messages.created_at
            FROM messages
            LEFT JOIN peers
                ON messages.peer_id = peers.id
            ORDER BY messages.id DESC
            LIMIT ?
        """, (limit,)).fetchall()
