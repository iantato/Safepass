from dataclasses import dataclass
from typing import Optional

@dataclass
class PasswordEntry:
    owner_username: str = None
    website: str
    email: str
    password: bytes
    website_username: Optional[str] = None