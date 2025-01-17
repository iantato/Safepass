import os
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from safepass.config.settings import ITERATIONS, KEY_LENGTH

class MasterKey:

    def __init__(self, master_password: str, username: str):
        self._key: Optional[bytes] = None
        self._symmetric_key: Optional[bytes] = None
        self._initialize(master_password, username)

    def _initialize(self, master_password: str, username: str) -> None:
        self._key = self._derive_key(master_password.encode('utf-8'), username.encode('utf-8'))
        self._symmetric_key = os.urandom(256)

    def get_key(self) -> Optional[bytes]:
        return self._key

    def _derive_key(self, master_password: str, username: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=username,
            iterations=ITERATIONS['SHA256']
        )

        return kdf.derive(master_password)

    def destroy(self) -> None:
        self._key = None
        self._symmetric_key = None