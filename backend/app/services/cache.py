import json
import logging
import time
from typing import Optional, Any
import redis

from app.config import settings

logger = logging.getLogger("soc_cache")

class CacheService:
    def __init__(self):
        self.redis_client = None
        self._in_memory_store = {}  # Fallback: {key: (data, expire_at)}
        self._init_redis()

    def _init_redis(self):
        try:
            client = redis.Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
                socket_connect_timeout=2
            )
            client.ping()
            self.redis_client = client
            logger.info("Successfully connected to Redis cache.")
        except Exception as e:
            logger.warning(
                f"Redis unavailable ({settings.REDIS_URL}). Error: {e}. "
                "Using high-performance in-memory cache with TTL fallback."
            )
            self.redis_client = None

    def get(self, key: str) -> Optional[Any]:
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    return json.loads(val)
                return None
            except Exception as e:
                logger.error(f"Redis get failed: {e}")
        
        # In-memory fallback
        if key in self._in_memory_store:
            data, expire_at = self._in_memory_store[key]
            if time.time() < expire_at:
                return data
            else:
                del self._in_memory_store[key]
        return None

    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        if ttl is None:
            ttl = settings.CACHE_TTL_SECONDS
            
        serialized = json.dumps(value)
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, serialized)
                return True
            except Exception as e:
                logger.error(f"Redis set failed: {e}")
        
        # In-memory fallback
        self._in_memory_store[key] = (value, time.time() + ttl)
        return True

    def is_healthy(self) -> bool:
        if self.redis_client:
            try:
                return self.redis_client.ping()
            except Exception:
                return False
        return True # In-memory cache is operational

cache_service = CacheService()
