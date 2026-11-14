from typing import Dict, Optional
from shared.crypto.models import RsaKeys, AesKey
import threading


class MemoryStorage:
    """In-memory storage for RSA key pairs and AES sessions."""

    def __init__(self):
        self._rsa_keys: Dict[int, RsaKeys] = {}
        self._sessions: Dict[str, AesKey] = {}
        self._next_rsa_id = 1
        self._lock = threading.Lock()

    def store_rsa_keys(self, keys: RsaKeys) -> int:
        with self._lock:
            key_id = self._next_rsa_id
            self._rsa_keys[key_id] = keys
            self._next_rsa_id += 1
            return key_id

    def get_rsa_keys(self, key_id: int) -> Optional[RsaKeys]:
        with self._lock:
            return self._rsa_keys.get(key_id)

    def get_rsa_public_key(self, key_id: int) -> Optional[str]:
        keys = self.get_rsa_keys(key_id)
        if keys is None:
            return None
        return keys.public_key

    def store_session(self, session_id: str, aes_key: AesKey) -> None:
        with self._lock:
            self._sessions[session_id] = aes_key

    def get_session(self, session_id: str) -> Optional[AesKey]:
        with self._lock:
            return self._sessions.get(session_id)

    def session_exists(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._sessions
