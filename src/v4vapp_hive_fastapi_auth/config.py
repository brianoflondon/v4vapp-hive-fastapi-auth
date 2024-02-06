import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(module)-14s %(lineno) 5d : %(message)s",
    stream=sys.stdout,
)
logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)

AUTHENTICATION_APP_KEY = os.getenv("AUTHENTICATION_APP_KEY", "No ENV found")

# Exclude the value "string"
HIVE_ACCNAME_REGEX = (
    r"^(?!string$)(?=.{3,16}$)[a-z]([0-9a-z]|[0-9a-z\-](?=[0-9a-z]))"
    r"{2,}([\.](?=[a-z][0-9a-z\-][0-9a-z\-])[a-z]([0-9a-z]"
    r"|[0-9a-z\-](?=[0-9a-z])){1,}){0,}$"
)
