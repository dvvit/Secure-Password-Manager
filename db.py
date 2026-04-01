import sqlite3
from datetime import datetime
from typing import Optional


DB_FILE = "vaults.db"


def get_connection(db_file: str = DB_FILE) -> sqlite3.Connection:
    return sqlite3.connect(db_file)


def init_db(db_file: str = DB_FILE) -> None:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vaults (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_name  TEXT    UNIQUE NOT NULL,
            salt        BLOB    NOT NULL,
            created_at  TEXT    NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_id           INTEGER NOT NULL,
            service_name       TEXT    NOT NULL,
            username           TEXT    NOT NULL,
            encrypted_password TEXT    NOT NULL,
            notes              TEXT,
            created_at         TEXT    NOT NULL,
            modified_at        TEXT    NOT NULL,
            FOREIGN KEY (vault_id) REFERENCES vaults (id),
            UNIQUE (vault_id, service_name)
        )
    """)
    conn.commit()
    conn.close()


# ---------- vault queries ----------

def vault_exists(name: str, db_file: str = DB_FILE) -> bool:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT id FROM vaults WHERE vault_name = ?", (name,))
    found = cur.fetchone() is not None
    conn.close()
    return found


def create_vault(name: str, salt: bytes, db_file: str = DB_FILE) -> int:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO vaults (vault_name, salt, created_at) VALUES (?, ?, ?)",
        (name, salt, datetime.now().isoformat()),
    )
    vault_id = cur.lastrowid
    conn.commit()
    conn.close()
    return vault_id


def list_vaults(db_file: str = DB_FILE) -> list:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT id, vault_name, created_at FROM vaults ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_vault_salt(vault_id: int, db_file: str = DB_FILE) -> Optional[bytes]:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute("SELECT salt FROM vaults WHERE id = ?", (vault_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# ---------- password queries ----------

def get_any_encrypted_password(vault_id: int, db_file: str = DB_FILE) -> Optional[str]:
    """Return one encrypted password from a vault, used to verify the master key."""
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        "SELECT encrypted_password FROM passwords WHERE vault_id = ? LIMIT 1",
        (vault_id,),
    )
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def service_exists(vault_id: int, service_name: str, db_file: str = DB_FILE) -> bool:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM passwords WHERE vault_id = ? AND service_name = ?",
        (vault_id, service_name),
    )
    found = cur.fetchone() is not None
    conn.close()
    return found


def insert_password(
    vault_id: int,
    service_name: str,
    username: str,
    encrypted_password: str,
    notes: str,
    db_file: str = DB_FILE,
) -> None:
    now = datetime.now().isoformat()
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO passwords
            (vault_id, service_name, username, encrypted_password, notes, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (vault_id, service_name, username, encrypted_password, notes, now, now),
    )
    conn.commit()
    conn.close()


def fetch_password(vault_id: int, service_name: str, db_file: str = DB_FILE) -> Optional[tuple]:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT username, encrypted_password, notes, created_at, modified_at
        FROM passwords
        WHERE vault_id = ? AND service_name = ?
        """,
        (vault_id, service_name),
    )
    row = cur.fetchone()
    conn.close()
    return row


def fetch_all_passwords(vault_id: int, db_file: str = DB_FILE) -> list:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT service_name, username, encrypted_password, notes, created_at, modified_at
        FROM passwords
        WHERE vault_id = ?
        ORDER BY service_name
        """,
        (vault_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def search_services(vault_id: int, query: str, db_file: str = DB_FILE) -> list:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT service_name, username
        FROM passwords
        WHERE vault_id = ? AND LOWER(service_name) LIKE ?
        ORDER BY service_name
        """,
        (vault_id, f"%{query.lower()}%"),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def update_password(
    vault_id: int,
    service_name: str,
    username: str,
    encrypted_password: str,
    notes: str,
    db_file: str = DB_FILE,
) -> None:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE passwords
        SET username = ?, encrypted_password = ?, notes = ?, modified_at = ?
        WHERE vault_id = ? AND service_name = ?
        """,
        (username, encrypted_password, notes, datetime.now().isoformat(), vault_id, service_name),
    )
    conn.commit()
    conn.close()


def delete_password(vault_id: int, service_name: str, db_file: str = DB_FILE) -> bool:
    conn = get_connection(db_file)
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM passwords WHERE vault_id = ? AND service_name = ?",
        (vault_id, service_name),
    )
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected > 0
