from dataclasses import fields
from safepass.session import SessionManager
from safepass.models.password import PasswordEntry
from safepass.storage.vault_storage import VaultStorage

class VaultManager:

    def __init__(self):
        self.session = SessionManager()
        self.vault_storage = VaultStorage()

    def login(self, username: str, master_password: str) -> None:
        self.session.login(username, master_password)

    def logout(self) -> None:
        self.session.logout()

    def get_password(self, website_name: str, email: str) -> str:
        self.session.validate_session()

        entry = self.vault_storage.get_password_data(
            self.session.username,
            website_name,
            email
        )

        return self.session.key_manager.decrypt_data(entry.password, entry.nonce).decode('utf-8')

    def add_password(self, website_url: str, website_name: str, website_username: str, email: str, password: str) -> None:
        self.session.validate_session()

        _encrypted_password, nonce = self.session.key_manager.encrypt_data(
            password.encode('utf-8')
        )

        self.vault_storage.save_password_entry(
            owner_username=self.session.username,
            website_url=website_url,
            website_name=website_name,
            website_username=website_username,
            email=email,
            nonce=nonce,
            password=_encrypted_password
        )

    def update_password_entry(self, email: str, **updates) -> None:
        self.session.validate_session()

        if 'password' in updates:
            _encrypted_password, _nonce = self.session.key_manager.encrypt_data(
                updates['password'].encode('utf-8')
            )
            updates['password'] = _encrypted_password
            updates['nonce'] = _nonce

        validated_fields = {key: val for key, val in updates.items()
                            if key in [field.name for field in fields(PasswordEntry)]}

        self.vault_storage.update_password_entry(
            owner_username=self.session.username,
            email=email,
            **validated_fields
        )

    def delete_password(self, website_name: str, email: str) -> None:
        self.session.validate_session()

        self.vault_storage.delete_password(
            owner_username=self.session.username,
            website_name=website_name,
            email=email
        )