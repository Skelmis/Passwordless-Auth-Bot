from __future__ import annotations

import base64

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey


class User:
    def __init__(
        self,
        username: str,
        public_key: str,
        private_key: str,
        base_domain: str,
        registered_for: int,
        _id=None,
    ):
        self._id = _id
        self.username: str = username
        self.public_key: RsaKey = self.key_from_str(public_key)
        self.private_key: RsaKey = self.key_from_str(private_key)
        self.base_domain: str = base_domain
        self.registered_for: int = registered_for

    @staticmethod
    def key_from_str(key_str) -> RsaKey:
        return RSA.import_key(base64.b64decode(key_str).decode("utf-8"))

    @staticmethod
    def key_as_str(key: RsaKey) -> str:
        return base64.b64encode(key.export_key()).decode("utf-8")

    @property
    def public_key_str(self) -> str:
        return self.key_as_str(self.public_key)

    @property
    def private_key_str(self) -> str:
        return self.key_as_str(self.private_key)

    @classmethod
    def new(cls, username, base_domain, registered_for) -> User:
        key_pair = RSA.generate(4096)
        return cls(
            username,
            cls.key_as_str(key_pair.public_key()),
            cls.key_as_str(key_pair),
            base_domain,
            registered_for,
        )

    def as_dict(self):
        data = {
            "username": self.username,
            "public_key": self.public_key_str,
            "private_key": self.private_key_str,
            "base_domain": self.base_domain,
            "registered_for": self.registered_for,
        }
        if self._id is not None:
            data["_id"] = self.username

        return data
