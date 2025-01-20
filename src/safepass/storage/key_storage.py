import sqlite3
from pathlib import Path
from safepass.models.account import Account
from safepass.config.settings import DB_PATH

class KeyStorage:

    def __init__(self):
        if not Path(DB_PATH).exists():
            self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    nonce BLOB NOT NULL
                );
            ''')

    def save_account(self, username: str, encrypted_key: bytes, nonce: bytes) -> None:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO keys (username, encrypted_key, nonce)
                VALUES (?, ?, ?)
            ''', (username, encrypted_key, nonce))
            conn.commit()

    def get_account_data(self, username: str) -> Account:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT *
                FROM keys
                WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            if row is None:
                return None
            return Account(*row[1:])