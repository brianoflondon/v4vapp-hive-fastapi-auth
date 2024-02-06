import json
import logging
import traceback
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from fastapi.security import OAuth2PasswordRequestForm

from v4vapp_hive_fastapi_auth.helpers import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_current_active_user,
    request_validate_hive_accname,
    strip_lightning_and_at_symbol,
    validate_hivekeychain_ans,
)
from v4vapp_hive_fastapi_auth.models import (
    Challenge,
    KeychainSignedMessage,
    SignatureError,
    Token,
    User,
)
from v4vapp_hive_fastapi_auth.redis_async import redis_set

router = APIRouter()


@router.get("/auth/{hive_accname}", tags=["auth"])
async def get_authentication_challenge(
    hive_accname: str = Path(
        min_length=3,
        max_length=17,
        description="Hive name to challenge for authentication",
    ),
    # add a parameter for client token
    clientId: str = Query(
        ...,
        min_length=10,
        max_length=100,
        description="ClientId used for authentication",
    ),
) -> dict:
    """
    Returns a challenge for the given Hive account name to be used by
    Hive Keychain to sign and authenticate the user.

    The ClientID is optional and is used to identify the client that is
    requesting the challenge. This is useful for tracking the usage of
    the API.
    """

    hive_accname = strip_lightning_and_at_symbol(hive_accname)
    request_validate_hive_accname(hive_accname)
    challenge = Challenge(hive_accname, clientId)
    new_user = User(
        username=hive_accname,
        challenge=challenge,
    )
    await redis_set(hive_accname, new_user.dict(), 600)
    logging.info(f"Challenge: [{challenge}] for {hive_accname}")
    return {"challenge": str(challenge)}


@router.post("/auth/validate/", tags=["auth"])
async def post_authentication_challenge(
    clientId: str = Query(
        ...,
        min_length=10,
        max_length=100,
        description="ClientId used for authentication",
    ),
    ans: dict = Body(...),
) -> Token:
    """
    Receives the answer from Hive Keychain and validates it.
    """
    keychain_ans = KeychainSignedMessage.parse_obj(ans)
    logging.info(f"Keychain answer: {keychain_ans}")
    logging.info(f"ClientId: {clientId}")
    try:
        user = await validate_hivekeychain_ans(keychain_ans, client_id=clientId)
        return get_token(user)
    except SignatureError as e:
        logging.warning(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        logging.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication Failure",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/token", tags=["auth"], response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    username_data = json.loads(form_data.username)
    try:
        username = username_data["hiveAccName"]
        clientId = username_data["clientId"]

    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    password_data = json.loads(form_data.password)
    keychain_ans = KeychainSignedMessage.parse_obj(password_data)

    if username == keychain_ans.data.username:
        try:
            user = await validate_hivekeychain_ans(keychain_ans, client_id=clientId)
            return get_token(user)
        except SignatureError as e:
            logging.warning(e)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_token(user: User) -> Token:
    """This is where I need to generate a token and return it"""
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logging.info("User authenticated: " + user.username)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/auth/check/", tags=["auth"])
async def check_authentication(
    current_user: Annotated[User, Depends(get_current_active_user)]
) -> dict:
    logging.info(f"User is authenticated: {current_user.username}")
    return {"detail": "User is authenticated"}
