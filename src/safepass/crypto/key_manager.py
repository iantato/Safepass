import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from safepass.storage.key_storage import KeyStorage
from safepass.config.settings import ITERATIONS, KEY_LENGTH

class KeyManager:

    def __init__(self, master_password: str, username: str):
        self.database = KeyStorage()

        self._key: Optional[bytes] = None
        self._symmetric_key: Optional[bytes] = None
        self._symmetric_key_nonce: Optional[bytes] = None
        self._encrypted_symmetric_key: Optional[bytes] = None

        if not self.database.get_account_data(username):
            self._initialize(master_password, username)
        else:
            _account = self.database.get_account_data(username)
            self._key = self._derive_key(master_password.encode('utf-8'),
                                         username.encode('utf-8'))
            self._encrypt_symmetric_key = _account._encrypted_key
            self._symmetric_key_nonce = _account._nonce
            self._symmetric_key = self.decrypt_symmetric_key(self._key,
                                                             _account._encrypted_key,
                                                             _account._nonce)

            # Clear account data from memory.
            _account = None

        # Clear master password from memory.
        master_password = None

    def _initialize(self, master_password: str, username: str) -> None:
        self._key = self._derive_key(master_password.encode('utf-8'), username.encode('utf-8'))
        self._symmetric_key = os.urandom(32)
        self._symmetric_key_nonce = os.urandom(12)
        self._encrypt_symmetric_key(self._symmetric_key, self._symmetric_key_nonce)

        self.database.save_account(username, self._encrypted_symmetric_key, self._symmetric_key_nonce)

    def get_key(self) -> bytes:
        if not self._key:
            raise ValueError("Master key is not set.")
        return self._key

    def get_symmetric_nonce(self) -> bytes:
        if not self._symmetric_key_nonce:
            raise ValueError("Nonce for symmetric key is not set.")
        return self._symmetric_key_nonce

    def get_encrypted_key(self) -> bytes:
        if not self._encrypted_symmetric_key:
            raise ValueError("Encrypted symmetric key is not set.")
        return self._encrypted_symmetric_key

    def _derive_key(self, master_password: str, username: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=username,
            iterations=ITERATIONS['SHA256']
        )

        return kdf.derive(master_password)

    def _encrypt_symmetric_key(self, symmetric_key: bytes, nonce: bytes) -> bytes:
        aesgcm = AESGCM(self._key)
        self._encrypted_symmetric_key = aesgcm.encrypt(nonce, symmetric_key, None)

    def decrypt_symmetric_key(self, master_key: bytes, encrypted_key: bytes, nonce: bytes) -> bytes:
        if not self._key:
            raise ValueError("Master key is not set.")

        aesgcm = AESGCM(master_key)
        try:
            return aesgcm.decrypt(nonce, encrypted_key, None)
        except Exception as e:
            raise ValueError(f"Failed to decrypt symmetric key: {str(e)}") from e

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

    def destroy(self) -> None:
        self._key = None
        self._symmetric_key = None
        self._symmetric_key_nonce = None
        self._encrypted_symmetric_key = None