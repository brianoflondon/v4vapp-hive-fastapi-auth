import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from single_source import get_version

from v4vapp_hive_fastapi_auth import routes
from v4vapp_hive_fastapi_auth.helpers import get_current_active_user
from v4vapp_hive_fastapi_auth.models import User
from fastapi.middleware.cors import CORSMiddleware

__version__ = get_version(__name__, "", default_return="0.0.1")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Starting up")
    yield


app = FastAPI(
    lifespan=lifespan,
    title="V4VApp Authenticated Hive API",
    description="Authenticated API for Hive.",
)

app.include_router(routes.router)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["v4vapp"])
async def index():
    return {"message": "Hello World"}


@app.get("/secure/", tags=["v4vapp"])
async def secure(current_user: Annotated[User, Depends(get_current_active_user)]):

    return {
        "current_user": current_user.username,
        "challenge": current_user.challenge,
        "disabled": current_user.disabled,
    }
