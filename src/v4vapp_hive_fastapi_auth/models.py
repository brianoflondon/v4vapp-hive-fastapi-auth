from datetime import datetime, timezone
from enum import Enum
from typing import List

from pydantic import BaseModel

from v4vapp_hive_fastapi_auth.random_words import generate_random_words


class SignatureError(Exception):
    """Base class for exceptions in this module."""

    pass


class SignatureTimeOut(SignatureError):
    """Exception raised for signature timeout."""

    pass


class SignatureFailure(SignatureError):
    """Exception raised for signature failure."""

    pass


class SignatureUserNotFound(SignatureError):
    """Exception raised for user not found."""

    pass


class SignatureClientIDFailure(SignatureError):
    """Exception raised for client ID failure."""

    pass


class Challenge(BaseModel):
    clientId: str
    hive_accname: str
    word_list: List[str]
    set_time: datetime

    def __init__(
        self,
        hive_accname: str,
        clientId: str | None = None,
        **data,
    ) -> None:
        parts = hive_accname.split(" ")
        if len(parts) == 6:
            word_list = parts[:3]
            hive_accname = parts[3]
            set_time = datetime.fromtimestamp(float(parts[4]), timezone.utc)
            clientId = parts[5]
            data.setdefault("word_list", word_list)
            data.setdefault("set_time", set_time)
        else:
            data.setdefault("word_list", generate_random_words(3, "en"))
            data.setdefault("set_time", datetime.now(timezone.utc))
        super().__init__(hive_accname=hive_accname, clientId=clientId, **data)

    def __str__(self) -> str:
        return (
            f"{' '.join(self.word_list)} {self.hive_accname}"
            f" {self.set_time.timestamp()} {self.clientId}"
        )


class HiveKeys(Enum):
    active = "active"
    posting = "posting"
    memo = "memo"


class KeychainData(BaseModel):
    type: str | None = None
    username: str
    message: str
    method: str | None = None
    rpc: str | None = None
    title: str | None = None
    key: HiveKeys


class KeychainSignedMessage(BaseModel):
    success: bool
    error: str | None = None
    result: str
    data: KeychainData
    message: str | None = None
    request_id: int | None = None
    publicKey: str | None = None

    @property
    def challenge_words(self) -> List[str]:
        return self.data.message.split(" ")[0:3]

    @property
    def challenge(self) -> Challenge:
        return Challenge(self.data.message)

    @property
    def clientId(self) -> str:
        return self.data.message.split(" ")[-1]

    @property
    def hive_accname(self) -> str:
        return self.data.message.split(" ")[3]


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    challenge: Challenge
    disabled: bool = False
