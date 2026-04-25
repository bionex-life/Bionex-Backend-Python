"""
Redis cache manager for cryptographic data.

Provides fast, distributed caching with automatic TTL management for:
- Public keys (90 days)
- Session key hashes (7 days, user-configurable)
- Access permissions (1 hour, sliding window)
"""

import json
import logging
from typing import Optional

import redis
from redis.exceptions import RedisError, ConnectionError, TimeoutError

logger = logging.getLogger(__name__)


class CacheError(Exception):
    """Base exception for cache operations."""

    pass


class CacheConnectionError(CacheError):
    """Raised when connection to cache fails."""

    pass


class CacheManager:
    """
    Redis cache operations for cryptographic data.

    Features:
    - Automatic TTL management
    - Connection pooling
    - Graceful error handling
    - Structured logging
    - Type-safe operations

    Thread-safe: Redis client library handles thread safety internally.
    """

    # Cache key prefixes (Redis namespacing convention)
    PREFIX_PUBLIC_KEY = "pubkey"
    PREFIX_SESSION_KEY = "session"
    PREFIX_PERMISSION = "perm"
    PREFIX_AUDIT_LOG = "audit"

    # Default TTL values (in seconds)
    DEFAULT_TTL_PUBLIC_KEY = 90 * 24 * 3600  # 90 days
    DEFAULT_TTL_SESSION_KEY = 7 * 24 * 3600  # 7 days
    DEFAULT_TTL_PERMISSION = 1 * 3600  # 1 hour

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        socket_connect_timeout: int = 5,
        socket_keepalive: bool = True,
        health_check_interval: int = 30,
    ):
        """
        Initialize cache manager with Redis connection.

        Args:
            redis_url: Redis connection string (e.g., redis://host:port/db).
            socket_connect_timeout: Connection timeout in seconds.
            socket_keepalive: Enable TCP keepalive.
            health_check_interval: Seconds between health checks.

        Raises:
            CacheConnectionError: If Redis connection fails.
        """
        try:
            # Parse Redis URL and create connection pool
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,  # Return strings instead of bytes
                socket_connect_timeout=socket_connect_timeout,
                socket_keepalive=socket_keepalive,
                health_check_interval=health_check_interval,
            )

            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache manager initialized successfully")

        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise CacheConnectionError(f"Redis connection failed: {e}") from e

    # ────────────────────────────────────────────────────────────────────────
    # Public Key Caching (90 days TTL)
    # ────────────────────────────────────────────────────────────────────────

    def cache_public_key(
        self,
        user_id: str,
        public_key: str,
        ttl_seconds: int = DEFAULT_TTL_PUBLIC_KEY,
    ) -> bool:
        """
        Cache user's public key in Redis.

        Args:
            user_id: User UUID.
            public_key: PEM-encoded public key string.
            ttl_seconds: Time-to-live in seconds (default: 90 days).

        Returns:
            True if cached successfully, False otherwise.
        """
        try:
            key = f"{self.PREFIX_PUBLIC_KEY}:{user_id}"
            self.redis_client.setex(key, ttl_seconds, public_key)
            logger.info(f"Cached public key for user {user_id} (TTL: {ttl_seconds}s)")
            return True

        except RedisError as e:
            logger.warning(f"Failed to cache public key for {user_id}: {e}")
            # Non-critical failure; system continues with DB lookups
            return False

    def get_public_key(self, user_id: str) -> Optional[str]:
        """
        Retrieve cached public key.

        Args:
            user_id: User UUID.

        Returns:
            Public key string if cached, None otherwise.
        """
        try:
            key = f"{self.PREFIX_PUBLIC_KEY}:{user_id}"
            public_key = self.redis_client.get(key)
            if public_key:
                logger.debug(f"Cache hit: public key for user {user_id}")
            return public_key

        except RedisError as e:
            logger.warning(f"Cache lookup failed for {user_id}: {e}")
            return None

    def invalidate_public_key(self, user_id: str) -> bool:
        """
        Remove public key from cache (e.g., after key rotation).

        Args:
            user_id: User UUID.

        Returns:
            True if deleted, False if key didn't exist or error.
        """
        try:
            key = f"{self.PREFIX_PUBLIC_KEY}:{user_id}"
            deleted = self.redis_client.delete(key)
            if deleted:
                logger.info(f"Invalidated cached public key for user {user_id}")
            return bool(deleted)

        except RedisError as e:
            logger.warning(f"Failed to invalidate public key for {user_id}: {e}")
            return False

    # ────────────────────────────────────────────────────────────────────────
    # Session Key Caching (7 days TTL, user-configurable)
    # ────────────────────────────────────────────────────────────────────────

    def cache_session_key_hash(
        self,
        session_key_hash: str,
        doctor_id: str,
        ttl_seconds: int = DEFAULT_TTL_SESSION_KEY,
    ) -> bool:
        """
        Cache session key hash for fast validation.

        Maps session_key_hash → doctor_id for O(1) lookup of valid sessions.

        Args:
            session_key_hash: SHA256 hash of session key (from DB).
            doctor_id: UUID of doctor who created this session.
            ttl_seconds: Time-to-live in seconds (default: 7 days).

        Returns:
            True if cached, False on error.
        """
        try:
            key = f"{self.PREFIX_SESSION_KEY}:{session_key_hash}"
            self.redis_client.setex(key, ttl_seconds, doctor_id)
            logger.debug(
                f"Cached session key for doctor {doctor_id} (TTL: {ttl_seconds}s)"
            )
            return True

        except RedisError as e:
            logger.warning(f"Failed to cache session key: {e}")
            return False

    def get_session_key_doctor(self, session_key_hash: str) -> Optional[str]:
        """
        Retrieve cached session key doctor ID (for validation).

        Args:
            session_key_hash: SHA256 hash of session key.

        Returns:
            Doctor UUID if cached and valid, None otherwise.
        """
        try:
            key = f"{self.PREFIX_SESSION_KEY}:{session_key_hash}"
            doctor_id = self.redis_client.get(key)
            if doctor_id:
                logger.debug(f"Cache hit: session key hash {session_key_hash[:8]}...")
            return doctor_id

        except RedisError as e:
            logger.warning(f"Cache lookup failed for session key: {e}")
            return None

    def invalidate_session(self, session_key_hash: str) -> bool:
        """
        Immediately invalidate a session key (revocation).

        Args:
            session_key_hash: SHA256 hash of session key.

        Returns:
            True if invalidated, False otherwise.
        """
        try:
            key = f"{self.PREFIX_SESSION_KEY}:{session_key_hash}"
            deleted = self.redis_client.delete(key)
            if deleted:
                logger.info(f"Revoked session key hash {session_key_hash[:8]}...")
            return bool(deleted)

        except RedisError as e:
            logger.warning(f"Failed to invalidate session: {e}")
            return False

    def invalidate_all_doctor_sessions(self, doctor_id: str) -> int:
        """
        Invalidate all sessions for a doctor (e.g., on logout).

        Args:
            doctor_id: Doctor UUID.

        Returns:
            Number of sessions invalidated.
        """
        try:
            # Find all sessions for this doctor
            pattern = f"{self.PREFIX_SESSION_KEY}:*"
            sessions_to_remove = []

            for key in self.redis_client.scan_iter(match=pattern):
                if self.redis_client.get(key) == doctor_id:
                    sessions_to_remove.append(key)

            if sessions_to_remove:
                count = self.redis_client.delete(*sessions_to_remove)
                logger.info(f"Invalidated {count} sessions for doctor {doctor_id}")
                return count
            return 0

        except RedisError as e:
            logger.warning(f"Failed to invalidate doctor sessions: {e}")
            return 0

    # ────────────────────────────────────────────────────────────────────────
    # Permission Caching (1 hour TTL, sliding window)
    # ────────────────────────────────────────────────────────────────────────

    def cache_permission(
        self,
        patient_id: str,
        doctor_id: str,
        permission_scope: str,
        ttl_seconds: int = DEFAULT_TTL_PERMISSION,
    ) -> bool:
        """
        Cache access permission (patient-doctor pair).

        Args:
            patient_id: Patient UUID.
            doctor_id: Doctor UUID.
            permission_scope: Permission type (e.g., "READ", "READ_WRITE").
            ttl_seconds: Time-to-live in seconds (default: 1 hour).

        Returns:
            True if cached, False on error.
        """
        try:
            key = f"{self.PREFIX_PERMISSION}:{patient_id}:{doctor_id}"
            self.redis_client.setex(key, ttl_seconds, permission_scope)
            logger.debug(f"Cached permission for {patient_id}:{doctor_id}")
            return True

        except RedisError as e:
            logger.warning(f"Failed to cache permission: {e}")
            return False

    def get_permission(self, patient_id: str, doctor_id: str) -> Optional[str]:
        """
        Retrieve cached permission scope.

        Args:
            patient_id: Patient UUID.
            doctor_id: Doctor UUID.

        Returns:
            Permission scope if cached, None otherwise.
        """
        try:
            key = f"{self.PREFIX_PERMISSION}:{patient_id}:{doctor_id}"
            scope = self.redis_client.get(key)
            if scope:
                logger.debug(
                    f"Cache hit: permission {patient_id[:8]}...:{doctor_id[:8]}..."
                )
            return scope

        except RedisError as e:
            logger.warning(f"Cache lookup failed for permission: {e}")
            return None

    def invalidate_permission(self, patient_id: str, doctor_id: str) -> bool:
        """
        Invalidate a specific permission (e.g., on revocation).

        Args:
            patient_id: Patient UUID.
            doctor_id: Doctor UUID.

        Returns:
            True if invalidated, False otherwise.
        """
        try:
            key = f"{self.PREFIX_PERMISSION}:{patient_id}:{doctor_id}"
            deleted = self.redis_client.delete(key)
            if deleted:
                logger.info(f"Revoked permission for {patient_id}:{doctor_id}")
            return bool(deleted)

        except RedisError as e:
            logger.warning(f"Failed to invalidate permission: {e}")
            return False

    def invalidate_all_patient_permissions(self, patient_id: str) -> int:
        """
        Invalidate all permissions for a patient (e.g., data deletion).

        Args:
            patient_id: Patient UUID.

        Returns:
            Number of permissions invalidated.
        """
        try:
            pattern = f"{self.PREFIX_PERMISSION}:{patient_id}:*"
            keys_to_remove = list(self.redis_client.scan_iter(match=pattern))

            if keys_to_remove:
                count = self.redis_client.delete(*keys_to_remove)
                logger.info(f"Invalidated {count} permissions for patient {patient_id}")
                return count
            return 0

        except RedisError as e:
            logger.warning(f"Failed to invalidate patient permissions: {e}")
            return 0

    # ────────────────────────────────────────────────────────────────────────
    # Health & Diagnostics
    # ────────────────────────────────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Check Redis connectivity and responsiveness.

        Returns:
            True if Redis is healthy, False otherwise.
        """
        try:
            self.redis_client.ping()
            logger.debug("Redis health check passed")
            return True

        except RedisError as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    def get_stats(self) -> dict:
        """
        Get cache statistics for monitoring.

        Returns:
            Dictionary with cache info (debug use only).
        """
        try:
            info = self.redis_client.info()
            return {
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "N/A"),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "keyspace": info.get("keyspace_stats", {}),
            }

        except RedisError as e:
            logger.warning(f"Failed to get Redis stats: {e}")
            return {"error": str(e)}

    def clear_all(self) -> bool:
        """
        Clear all cache (DANGER: Use only in development/testing).

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.redis_client.flushdb()
            logger.warning("Cleared all cache entries")
            return True

        except RedisError as e:
            logger.error(f"Failed to clear cache: {e}")
            return False


# Singleton instance for global use
try:
    from app.config import get_settings
    settings = get_settings()
    cache_manager = CacheManager(redis_url=settings.REDIS_URL)
except Exception as e:
    logger.warning(f"Failed to initialize cache_manager singleton: {e}")
    cache_manager = None
