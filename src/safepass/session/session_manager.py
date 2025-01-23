from typing import Optional
from datetime import datetime
from threading import Thread, Event
from safepass.crypto.key_manager import KeyManager
from safepass.config.settings import SESSION_TIMEOUT

class SessionManager:
    def __init__(self):
        self.key_manager = KeyManager()
        self.username: Optional[str] = None
        self.login_time: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self._is_active = False
        self._stop_monitor = Event()
        self._monitor_thread: Optional[Thread] = None
        self.session_duration = SESSION_TIMEOUT

    def login(self, username: str, master_password: str) -> None:
        if not self.key_manager.validate_account(username):
            self.key_manager.initialize_new_account(username, master_password)
        else:
            if not self.key_manager.validate_master_password(username, master_password):
                raise ValueError('Invalid password')

            self.key_manager.load_account_keys(username, master_password)

        self.username = username
        self.login_time = datetime.now()
        self.last_activity = datetime.now()
        self._is_active = True
        self._start_monitor()

    def logout(self) -> None:
        self._stop_monitor.set()
        if self._monitor_thread:
            self._monitor_thread.join()
        self.key_manager.clear_keys()
        self.username = None
        self.login_time = None
        self.last_activity = None
        self._is_active = False

    def validate_session(self) -> None:
        if not self._is_active or not self.login_time:
            raise ValueError('Session is not active')

        if datetime.now() - self.login_time > self.session_duration:
            self.logout()
            raise ValueError('Session has expired')

    def _start_monitor(self) -> None:
        self._stop_monitor.clear()
        self._monitor_thread = Thread(target=self._monitor_session)
        self._monitor_thread.start()

    def _monitor_session(self) -> None:
        while not self._stop_monitor.is_set():
            if self._is_active and self.last_activity:
                time_idle = datetime.now() - self.last_activity
                if time_idle > self.session_duration:
                    self._handle_timeout()
            self._stop_monitor.wait(60)

    def _handle_timeout(self) -> None:
        self.logout()