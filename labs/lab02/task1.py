import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SESSION_TIMEOUT_SEC = 900
HASH_ITERATIONS = 100_000


class User:
    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.email = email  # через сеттер у property
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self.__email

    @email.setter
    def email(self, value: str) -> None:
        # Проста валідація email: локальна частина (3-64 латинські літери, цифри, крапки, дефіси), потім @ та домен з крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self.__email = value

    def set_password(self, password: str) -> None:
        if len(password) < 6:
            raise ValueError("Пароль занадто короткий (мінімум 6 символів)")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, HASH_ITERATIONS
        )
        return hmac.compare_digest(test_hash, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, {self.email}, role={self.role}, status={status})"


class Admin(User):
    def __init__(self, username: str, email: str, permissions: set[str] | None = None):
        super().__init__(username, email, role="admin", active=True)
        self.permissions: set[str] = permissions if permissions is not None else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = (
            ", ".join(sorted(self.permissions))
            if self.permissions
            else "No permissions"
        )
        return f"Admin({self.username}, email={self.email}, permissions=[{perms}])"


class Session:
    def __init__(self, ip: str, timeout_sec: int = SESSION_TIMEOUT_SEC):
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії має бути додатнім числом")
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time
        self.timeout_sec = timeout_sec

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self) -> bool:
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed <= self.timeout_sec


@dataclass
class AuditRecord:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    username: str = ""
    action: str = ""


class AuditLog:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        record = AuditRecord(username=username, action=action)
        self._records.append(record)

    def show_all(self) -> list[AuditRecord]:
        return self._records


class UserAccount:
    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure_inactive")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure_bad_password")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if self.session.is_active():
            return True
        else:
            # Час вийшов
            self.session = None
            return False

    def logout(self) -> None:
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str) -> Any:
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ атрибута: {key}")

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення повинно бути екземпляром класу User")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення повинно бути екземпляром класу Session або None"
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення повинно бути екземпляром класу AuditLog")
            self.audit_log = value
        else:
            raise KeyError(f"Невідомий ключ атрибута або заборонено для зміни: {key}")
