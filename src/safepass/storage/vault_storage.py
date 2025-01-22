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

    def update_password_entry(self, owner_username: str, email: str, **updates) -> None:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            update_query = 'UPDATE passwords SET '

            for key, value in updates.items():
                update_query += f'{key} = ?, '

            update_query = update_query[:-2]
            update_query += ' WHERE owner_username = ? AND email = ?'

            cursor.execute(update_query, list(updates.values()) + [owner_username, email])
            conn.commit()

    def delete_password(self, owner_username: str, website_name: str, email: str) -> None:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM passwords
                WHERE owner_username = ? AND website_name = ? AND email = ?
            ''', (owner_username, website_name, email))

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