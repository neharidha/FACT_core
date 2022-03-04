from configparser import ConfigParser
from math import ceil
from pickle import dumps, loads
from random import randint
from typing import Any, Optional, Union

from redis.client import Redis

REDIS_MAX_VALUE_SIZE = 512_000_000  # 512 MB (not to be confused with 512 MiB)
CHUNK_MAGIC = b'$CHUNKED$'
SEPARATOR = '#'


class RedisInterface:
    def __init__(self, config: ConfigParser, chunk_size=REDIS_MAX_VALUE_SIZE):
        self.config = config
        self.chunk_size = chunk_size
        redis_db = config.getint('data_storage', 'redis_fact_db')
        redis_host = config.get('data_storage', 'redis_host')
        redis_port = config.getint('data_storage', 'redis_port')
        self.redis = Redis(host=redis_host, port=redis_port, db=redis_db)

    def set(self, key: str, value: Any):
        self.redis.set(key, self._split_if_necessary(dumps(value)))

    def get(self, key: str, delete: bool = True) -> Any:
        value = self._redis_pop(key) if delete else self.redis.get(key)
        return self._combine_if_split(value)

    def queue_put(self, key: str, value: Any):
        self.redis.rpush(key, self._split_if_necessary(dumps(value)))

    def queue_get(self, key: str) -> Any:
        return self._combine_if_split(self.redis.lpop(key))

    def _split_if_necessary(self, value: bytes) -> Union[str, bytes]:
        if len(value) > self.chunk_size:
            value = self._store_chunks(value)
        return value

    def _store_chunks(self, value) -> str:
        meta_key = CHUNK_MAGIC.decode()
        for index in range(ceil(len(value) / self.chunk_size)):
            key = self._get_new_chunk_key()
            chunk = value[self.chunk_size * index:self.chunk_size * (index + 1)]
            self.redis.set(key, chunk)
            meta_key += SEPARATOR + key
        return meta_key

    def _get_new_chunk_key(self):
        while True:
            key = f'chunk_{randint(0, 9999)}'
            if not self.redis.exists(key):
                return key

    def _combine_if_split(self, value: Optional[bytes]) -> Any:
        if value is None:
            return None
        if value.startswith(CHUNK_MAGIC):
            value = self._combine_chunks(value.decode())
        return loads(value)

    def _combine_chunks(self, meta_key: str) -> bytes:
        return b''.join([
            self._redis_pop(chunk_key)
            for chunk_key in meta_key.split(SEPARATOR)[1:]
        ])

    def _redis_pop(self, key: str) -> Optional[bytes]:
        pipeline = self.redis.pipeline()
        pipeline.get(key)
        pipeline.delete(key)
        value, _ = pipeline.execute()
        return value