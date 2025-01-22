from dataclasses import dataclass

@dataclass
class PasswordEntry:
    owner_username: str
    website_url: str
    website_name: str
    website_username: str
    email: str
    nonce: bytes
    password: bytes