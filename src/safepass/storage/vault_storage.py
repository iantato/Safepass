import sqlite3
from pathlib import Path
from safepass.storage.database import initialize_database
from safepass.models.password import PasswordEntry
from safepass.config.settings import DB_PATH

class VaultStorage:

    def __init__(self):
        if not Path(DB_PATH).exists():
            initialize_database()

    def save_password_entry(self, owner_username: str, website_url: str, website_name: str,
                            website_username: str, email: str, nonce: bytes, password: bytes) -> None:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO passwords (owner_username, website_url, website_name, website_username, email, nonce, encrypted_password)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (owner_username, website_url, website_name, website_username, email, nonce, password))

            conn.commit()

    def get_password_data(self, owner_username: str, website_name: str, email: str) -> PasswordEntry:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT *
                FROM passwords
                WHERE owner_username = ? AND website_name = ? AND email = ?
            ''', (owner_username, website_name, email))

            row = cursor.fetchone()

            if row is None:
                return None
            return PasswordEntry(*row[1:])