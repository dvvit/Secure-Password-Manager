from datetime import datetime, timedelta
from typing import Optional, Tuple


# Minutes of lockout keyed by how many failed sessions have occurred
_LOCKOUT_SCHEDULE = {1: 3, 2: 5, 3: 10, 4: 30, 5: 60}
_DEFAULT_LOCKOUT_MINUTES = 120


class LockoutTracker:
    def __init__(self):
        # vault_id -> {"sessions": int, "locked_until": Optional[datetime]}
        self._state: dict = {}

    def _ensure(self, vault_id: int) -> None:
        if vault_id not in self._state:
            self._state[vault_id] = {"sessions": 0, "locked_until": None}

    def is_locked(self, vault_id: int) -> Tuple[bool, Optional[Tuple[int, int]]]:
        self._ensure(vault_id)
        locked_until = self._state[vault_id]["locked_until"]
        if locked_until is None:
            return False, None
        remaining = locked_until - datetime.now()
        if remaining.total_seconds() <= 0:
            self._state[vault_id]["locked_until"] = None
            return False, None
        total_secs = int(remaining.total_seconds())
        return True, (total_secs // 60, total_secs % 60)

    def record_failed_session(self, vault_id: int) -> int:
        self._ensure(vault_id)
        self._state[vault_id]["sessions"] += 1
        sessions = self._state[vault_id]["sessions"]
        minutes = _LOCKOUT_SCHEDULE.get(sessions, _DEFAULT_LOCKOUT_MINUTES)
        self._state[vault_id]["locked_until"] = datetime.now() + timedelta(minutes=minutes)
        return minutes

    def failed_session_count(self, vault_id: int) -> int:
        self._ensure(vault_id)
        return self._state[vault_id]["sessions"]

    def reset(self, vault_id: int) -> None:
        self._state[vault_id] = {"sessions": 0, "locked_until": None}
