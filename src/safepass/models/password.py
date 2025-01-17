from dataclasses import dataclass
from typing import Optional

@dataclass
class PasswordEntry:
    email: str
    username: Optional[str] = None
    website: str
    password: bytes