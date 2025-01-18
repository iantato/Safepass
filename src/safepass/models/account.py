from dataclasses import dataclass

@dataclass
class Account:
    username: str
    _encrypted_key: bytes
    _nonce: bytes