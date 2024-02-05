import asyncio
import json
import logging
from typing import Dict

from redis.asyncio import Redis

REDIS_CONNECTION_DOCKER = {
    "host": "rds",
    "port": 6379,
    "encoding": "utf-8",
    "decode_responses": True,
    "socket_timeout": 0.01,
}


REDIS_CONNECTION_LOCALHOST = {
    "host": "localhost",
    "port": 6379,
    "encoding": "utf-8",
    "decode_responses": True,
    "socket_timeout": 0.01,
}

REDIS_URLS = ["redis://rds:6379/", "redis://localhost:6379/"]


class RedisException(Exception):
    pass


async def connect_to_redis(url) -> Redis | None:
    try:
        redis_conn = Redis.from_url(
            url, encoding="utf-8", decode_responses=True, socket_timeout=0.01
        )
        await redis_conn.ping()
        return redis_conn
    # except
    except ConnectionError as e:
        logging.warning(f"Redis not found on {url} {e}")
        raise asyncio.CancelledError
    except Exception as e:
        logging.warning(f"Redis not found on {url} {e}")
        return None


async def redis_setup(flush: bool = False) -> Redis | None:
    """Setup redis, flushes database if flush is true"""
    global REDIS_URLS
    tasks = [connect_to_redis(url) for url in REDIS_URLS]
    answer: Dict[str, Redis | None] = {}  # Specify the type of the answer dictionary

    async with asyncio.TaskGroup() as tg:
        for url, task in zip(REDIS_URLS, tasks):
            answer[url] = await tg.create_task(task)

    for url, redis_conn in answer.items():
        if redis_conn:
            logging.info(f"Redis found on {url}")
            if flush:
                await redis_conn.flushdb()
            return redis_conn
        else:
            logging.info(f"Removing {url} from list")
            REDIS_URLS.remove(url)
            if len(REDIS_URLS) == 0:
                REDIS_URLS = ["redis://rds:6379/", "redis://localhost:6379/"]

    raise RedisException("Redis not found on both rds and localhost")


async def redis_set(key: str, value: dict, expiry: int = 600) -> None:
    """Put the key and value into redis, default expiry 600s"""
    try:
        redis = await redis_setup()
        val = json.dumps(value, default=str)
        if redis:
            await redis.set(key, val, ex=expiry)
    except RedisException:
        logging.warning(f"Redis not found setting {key}")
        return None
    except Exception as ex:
        if key:
            logging.warning(f"Redis set failed for {key}")
            if val:
                logging.warning(f"Redis set failed for {key} {val}")
        logging.exception(ex)
        return None


async def redis_get(key: str) -> dict[str, object | dict[str, int]] | None:
    """get the key's value from redis"""
    try:
        redis = await redis_setup()
        if redis:
            val = await redis.get(key)
        if val is None:
            return None
        return json.loads(val)
    except RedisException:
        logging.warning(f"Redis not found getting {key}")
        return None
    except Exception as ex:
        if key:
            logging.warning(f"Redis get failed for {key}")
            if val:
                logging.warning(f"Redis get failed for {key} {val}")
        logging.exception(ex)
        return None
