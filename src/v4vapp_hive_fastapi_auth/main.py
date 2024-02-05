import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from single_source import get_version
from v4vapp_hive_fastapi_auth import routes

__version__ = get_version(__name__, "", default_return="0.0.1")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Starting up")
    yield


app = FastAPI(
    lifespan=lifespan,
    title="V4VApp Authenticated Hive API",
    description="Authenticated API for Hive.",
    # version=__version__,  # type: ignore
    # terms_of_service="http://example.com/terms/",
    # contact={
    #     "name": "Brian of London",
    #     "url": "http://x-force.example.com/contact/",
    #     "email": "dp@x-force.example.com",
    # },
    # license_info={
    #     "name": "MIT",
    #     "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    # },
)

app.include_router(routes.router)


@app.get("/", tags=["v4vapp"])
async def index():
    return {"message": "Hello World"}
