import json
import logging
import re
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta, timezone
from typing import Annotated, cast

from beem.account import Account  # type: ignore
from beemgraphenebase.account import PublicKey  # type: ignore
from beemgraphenebase.ecdsasig import verify_message  # type: ignore
from fastapi import Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError  # type: ignore
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from v4vapp_hive_fastapi_auth.config import AUTHENTICATION_APP_KEY, HIVE_ACCNAME_REGEX
from v4vapp_hive_fastapi_auth.models import (
    KeychainSignedMessage,
    SignatureClientIDFailure,
    SignatureError,
    SignatureFailure,
    SignatureTimeOut,
    SignatureUserNotFound,
    Token,
    TokenData,
    User,
)
from v4vapp_hive_fastapi_auth.redis_async import redis_get

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = AUTHENTICATION_APP_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 4

# How long between generating a challenge and getting it back do we allow?
SIGNATURE_TIMEOUT = 300


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def strip_lightning_and_at_symbol(input: str) -> str:
    """
    Removes lightning: from the start of a string if it is there.

    Args:
        input (str): The input string to be processed.

    Returns:
        str: The processed string with lightning: and @ symbols removed.
    """
    input = input.strip("⚡️").lower()
    # remove @ if it is at start
    input = input[1:] if input.startswith("@") else input
    input = input.encode("ascii", errors="ignore").decode("ascii")
    return input


def is_hive_accname(hive_accname: str) -> bool:
    """Returns True for a valid hive account name"""
    if re.match(HIVE_ACCNAME_REGEX, hive_accname):
        return True
    return False


def request_validate_hive_accname(hive_accname: str):
    """
    Raises a RequestValidationError for an invalid hive accname.

    Args:
        hive_accname (str): The hive account name to be validated.

    Raises:
        RequestValidationError: If the hive accname is invalid.

    """
    if not is_hive_accname(hive_accname):
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["hive_accname"],
                    "msg": "Invalid Hive account name",
                    "type": "value_error.str",
                }
            ],
            body=jsonable_encoder(hive_accname),
        )


async def validate_hivekeychain_ans(
    ans: KeychainSignedMessage, client_id: str = ""
) -> User:
    """
    Takes in the answer from hivekeychain and checks everything.
    Uses public key to verify the signature and then checks the user's challenge
    and the client ID. If everything is correct, the user is returned.

    Args:
        ans (KeychainSignedMessage): The answer from hivekeychain.
        client_id (str, optional): The client ID. Defaults to "".

    Returns:
        User: The user object if the validation is successful.

    Raises:
        SignatureClientIDFailure: If the client ID mismatch occurs.
        SignatureUserNotFound: If the user is not found.
        SignatureTimeOut: If the answer took too long.
        SignatureFailure: If the message was signed with a different key.
    """
    try:
        # This fails with Beem unless Beem is patched
        pubkey = PublicKey(ans.publicKey)
        acc_name = ans.data.username
        enc_msg = ans.data.message

        if client_id:
            if not ans.data.message.endswith(client_id):
                err = "ERROR: clientId mismatch"
                logging.warning(err)
                raise SignatureClientIDFailure(err)

        signature = ans.result

        user = await get_user(acc_name)
        if not user:
            err = "ERROR: User not found"
            logging.warning(err)
            raise SignatureUserNotFound(err)

        message_key = verify_message(enc_msg, unhexlify(signature))
        pk = PublicKey(hexlify(message_key).decode("ascii"))
        if str(pk) == str(pubkey):
            logging.info(f"{acc_name} SUCCESS: signature matches given pubkey")
            acc = Account(acc_name, lazy=True)
            match = False, 0
            for key in acc["posting"]["key_auths"]:
                match = match or ans["publicKey"] in key
            if match:
                logging.info(f"{acc_name} Matches public key from Hive")
                time_since = (
                    (datetime.now(timezone.utc) - user.challenge.set_time)
                    if user.challenge.set_time
                    else timedelta(seconds=0)
                )
                if time_since.seconds < SIGNATURE_TIMEOUT:
                    logging.info(f"{acc_name} SUCCESS: in {time_since}")
                    return user
                else:
                    err = f"ERROR: answer took too long {time_since}"
                    logging.warning(err)
                    raise SignatureTimeOut(err)
        else:
            err = "ERROR: message was signed with a different key"
            logging.warning(err)
            raise SignatureFailure(err)

    except SignatureError as e:
        raise e
    except Exception as e:
        err = f"ERROR: {e}"
        logging.warning(json.dumps(ans.dict(), indent=2, default=str))
        logging.error(e)
        # give me a full dump of e
        logging.exception(e)
        raise SignatureFailure(e)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Create an access token with the given data and expiration delta.

    Args:
        data (dict): The data to be encoded in the access token.
        expires_delta (timedelta | None, optional): The expiration delta for the access
        token.

            If None, a default expiration of 4 hours will be used. Defaults to None.

    Returns:
        str: The encoded access token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=4)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_token(user: User) -> Token:
    """This is where I need to generate a token and return it"""
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logging.info("User authenticated: " + user.username)
    return Token(access_token=access_token, token_type="bearer")


async def get_user(username: str) -> User | None:
    """
    Retrieve a user by their username.
    This uses the Redis database to retrieve the user data. If the user is not found,
    None is returned.

    This is only necessary during the Token generation part. The Client ID is matched
    with the user's challenge and the signature is verified. Signature verification
    is checked against the user's challenge, the clientId and the user's public key
    found on Hive (and also cross checked with the one returned in the challenge
    response).

    Args:
        username (str): The username of the user to retrieve.

    Returns:
        User | None: The user object if found, None otherwise.
    """
    user_data = await redis_get(username)
    if user_data:
        user = User.parse_obj(user_data)
        return user
    return None


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Get the current user based on the provided token.
    The token contains the username and expiry time. There is no need to check
    this against a local database as the token is signed and cannot be tampered
    with.

    Args:
        token (str): The JWT token for authentication.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the credentials are invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logging.info("JWT: Checking token")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = cast(str, payload.get("sub"))
        expiry = cast(int, payload.get("exp"))
        expiry_time = datetime.fromtimestamp(expiry, timezone.utc)
        time_to_expiry = expiry_time - datetime.now(timezone.utc)
        logging.warning(f"JWT: Token expires in {time_to_expiry}")
        if username is None or expiry_time < datetime.now(timezone.utc):
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        logging.warning("JWT: Error: JWT failed to decode")
        raise credentials_exception
    user = await get_user(username=token_data.username)  # type: ignore
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Get the current active user. This function is less complicated than in normal
    FastAPI because we are using JWTs alone and have no concept of a user database
    with passwords. Authentications is proven by the external signature which grants
    the JWT token.

    Args:
        current_user (User): The current user.

    Raises:
        HTTPException: If the user is inactive.

    Returns:
        User: The current active user.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
