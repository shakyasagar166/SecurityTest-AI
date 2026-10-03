import json
import logging
from typing import Optional, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

class SecurityMemoryStore:
    def __init__(self):
        self.redis_client = None
        self._local_cache = {}
        self._local_logs = {}

        try:
            import redis
            client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                socket_connect_timeout=1
            )
            client.ping()
            self.redis_client = client
            logger.info("Connected to Redis server successfully.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}). Using thread-safe in-memory cache.")

    def set(self, key: str, value: Any, expire_seconds: int = 3600):
        val_str = json.dumps(value) if not isinstance(value, str) else value
        if self.redis_client:
            try:
                self.redis_client.setex(key, expire_seconds, val_str)
                return
            except Exception as e:
                logger.error(f"Redis set failed: {e}")
        self._local_cache[key] = val_str

    def get(self, key: str) -> Optional[Any]:
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    val_str = val.decode('utf-8')
                    try:
                        return json.loads(val_str)
                    except Exception:
                        return val_str
            except Exception as e:
                logger.error(f"Redis get failed: {e}")

        val = self._local_cache.get(key)
        if val:
            try:
                return json.loads(val)
            except Exception:
                return val
        return None

    def append_log(self, scan_id: str, log_message: str):
        key = f"scan_logs:{scan_id}"
        if self.redis_client:
            try:
                self.redis_client.rpush(key, log_message)
                self.redis_client.expire(key, 86400)
                return
            except Exception as e:
                logger.error(f"Redis rpush failed: {e}")

        if key not in self._local_logs:
            self._local_logs[key] = []
        self._local_logs[key].append(log_message)

    def get_logs(self, scan_id: str) -> List[str]:
        key = f"scan_logs:{scan_id}"
        if self.redis_client:
            try:
                items = self.redis_client.lrange(key, 0, -1)
                return [i.decode('utf-8') for i in items]
            except Exception as e:
                logger.error(f"Redis lrange failed: {e}")

        return self._local_logs.get(key, [])

security_memory = SecurityMemoryStore()
