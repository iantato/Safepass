from typing import Optional
from datetime import datetime, timedelta
from safepass.crypto.key_manager import KeyManager

class SessionManager:
    def __init__(self):
        self.key_manager = KeyManager()
        self.username: Optional[str] = None
        self.login_time: Optional[datetime] = None
        self.session_duration = timedelta(minutes=30)
        self._is_active = False

    def login(self, username: str, master_password: str) -> None:
        if not self.key_manager.validate_account(username):
            self.key_manager.initialize_new_account(username, master_password)
        else:
            if not self.key_manager.validate_master_password(username, master_password):
                raise ValueError('Invalid password')

            self.key_manager.load_account_keys(username, master_password)

        self.username = username
        self.login_time = datetime.now()
        self._is_active = True

    def logout(self) -> None:
        self.key_manager.clear_keys()
        self.username = None
        self.login_time = None
        self._is_active = False

    def validate_session(self) -> None:
        if not self._is_active or not self.login_time:
            raise ValueError('Session is not active')

        if datetime.now() - self.login_time > self.session_duration:
            self.logout()
            raise ValueError('Session has expired')