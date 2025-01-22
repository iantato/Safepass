from dataclasses import fields
from safepass.models.password import PasswordEntry
from safepass.crypto.key_manager import KeyManager
from safepass.storage.vault_storage import VaultStorage

class VaultManager:

    def __init__(self, key_manager: KeyManager):
        self.database = VaultStorage()
        self.key_manager = key_manager

    def add_password(self, owner_username: str, website_url: str,
                     website_name: str, website_username: str,
                     email: str, password: str) -> None:
        _encrypted_password, nonce = self.key_manager.encrypt_data(password.encode('utf-8'))

        self.database.save_password_entry(
            owner_username,
            website_url,
            website_name,
            website_username,
            email,
            nonce,
            _encrypted_password
        )

    def update_password_entry(self, owner_username: str, email: str, **updates) -> None:
        if 'password' in updates:
            _encrypted_password, _nonce = self.key_manager.encrypt_data(
               updates['password'].encode('utf-8')
            )
            updates['password'] = _encrypted_password
            updates['nonce'] = _nonce

        validated_fields = {key: val for key, val in updates.items()
                            if key in [field.name for field in fields(PasswordEntry)]}

        self.database.update_password_entry(owner_username, email, **validated_fields)


    def get_password(self, owner_username: str, website_name: str, email: str) -> str:
        entry = self.database.get_password_data(
            owner_username,
            website_name,
            email)

        if not entry:
            raise ValueError("Password not found.")

        return self.key_manager.decrypt_data(entry.password, entry.nonce).decode('utf-8')


    def destroy(self) -> None:
        self.database = None
        self.key_manager.destroy()
        self.key_manager = None