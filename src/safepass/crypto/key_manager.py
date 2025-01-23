import os
import gc
from contextlib import contextmanager
from typing import Optional, Generator, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from safepass.storage.key_storage import KeyStorage
from safepass.config.settings import ITERATIONS, KEY_LENGTH

class KeyManager:

    def __init__(self):
        self.database = KeyStorage()
        self._symmetric_key: Optional[bytes] = None

    def validate_account(self, username: str) -> bool:
        return self.database.get_account_data(username) is not None

    def validate_master_password(self, username: str, master_password: str) -> bool:
        try:
            account = self.database.get_account_data(username)

            with self._temp_key(username, master_password) as _master_key:
                self._decrypt_symmetric_key(_master_key, account._encrypted_key, account._nonce)
            return True

        except Exception:
            return False

    @contextmanager
    def _temp_key(self, username: str, master_password: str) -> Generator[bytes, None, None]:
        _key = self._derive_key(username, master_password)
        try:
            yield _key
        finally:
            del _key
            gc.collect()

    def initialize_new_account(self, username: str, master_password: str) -> None:
        with self._temp_key(username, master_password) as _master_key:
            self._symmetric_key = os.urandom(32)
            self._symmetric_key_nonce = os.urandom(12)

            self.database.save_account(
                username,
                self._encrypt_symmetric_key(_master_key, self._symmetric_key, self._symmetric_key_nonce),
                self._symmetric_key_nonce
            )

    def load_account_keys(self, username: str, master_password: str) -> None:
        with self._temp_key(username, master_password) as _master_key:
            _account = self.database.get_account_data(username)
            self._symmetric_key = self._decrypt_symmetric_key(_master_key, _account._encrypted_key, _account._nonce)

    def encrypt_data(self, data: bytes) -> Tuple[bytes, bytes]:
        if not self._symmetric_key:
            raise ValueError("Symmetric key is not set.")

        _nonce = os.urandom(12)
        aesgcm = AESGCM(self._symmetric_key)
        return aesgcm.encrypt(_nonce, data, None), _nonce

    def decrypt_data(self, data: bytes, nonce: bytes) -> str:
        if not self._symmetric_key:
            raise ValueError("Symmetric key is not set.")

        aesgcm = AESGCM(self._symmetric_key)
        return aesgcm.decrypt(nonce, data, None).decode('utf-8')

    def clear_keys(self) -> None:
        del self._symmetric_key
        gc.collect()

    def _derive_key(self, username: str, master_password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=username.encode('utf-8'),
            iterations=ITERATIONS['SHA256']
        )

        return kdf.derive(master_password.encode('utf-8'))

    def _encrypt_symmetric_key(self, master_key: bytes, symmetric_key: bytes, nonce: bytes) -> bytes:
        aesgcm = AESGCM(master_key)
        return aesgcm.encrypt(nonce, symmetric_key, None)

    def _decrypt_symmetric_key(self, master_key: bytes, symmetric_key: bytes, nonce: bytes) -> bytes:
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(nonce, symmetric_key, None)