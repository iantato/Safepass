import sqlite3
from safepass.config.settings import DB_PATH

def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_username TEXT NOT NULL,
                website_username TEXT NOT NULL,
                website_name TEXT NOT NULL,
                website_url TEXT NOT NULL,
                email TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                FOREIGN KEY (owner_username) REFERENCES keys (username)
            );
        ''')

        conn.commit()