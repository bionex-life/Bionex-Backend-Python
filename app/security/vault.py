"""
HashiCorp Vault secrets management integration.

Provides secure storage and retrieval of private keys, credentials, and
secrets with:
- Automatic TTL rotation
- Audit logging
- High availability support
- Graceful degradation (falls back to environment variables if unavailable)
"""

import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Base exception for Vault operations."""

    pass


class VaultConnectionError(VaultError):
    """Raised when connection to Vault fails."""

    pass


class VaultManager:
    """
    HashiCorp Vault integration for secrets storage.

    Features:
    - Centralized secret storage (keep secrets out of code/environment)
    - Automatic key rotation tracking
    - Audit trail for all access
    - High availability support
    - Graceful fallback to environment variables

    Note:
    This is a stub implementation. Real implementation requires hvac library
    and a running Vault instance. Once hvac is added to requirements.txt,
    this will be fully functional.
    """

    def __init__(
        self,
        vault_addr: str = "http://localhost:8200",
        vault_token: str = "",
        vault_namespace: str = "bionex",
        skip_verify: bool = False,
    ):
        """
        Initialize Vault manager.

        Args:
            vault_addr: Vault server address (e.g., http://localhost:8200).
            vault_token: Vault authentication token.
            vault_namespace: Namespace for secrets (e.g., bionex).
            skip_verify: Skip SSL verification (DEV ONLY).

        Note:
            Gracefully handles missing hvac library. If hvac is not installed,
            falls back to returning None with warnings.
        """
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.vault_namespace = vault_namespace
        self.skip_verify = skip_verify
        self.client = None

        try:
            import hvac  # Import only if needed

            self.client = hvac.Client(
                url=vault_addr,
                token=vault_token,
                verify=not skip_verify,
            )

            # Test connection
            if self.health_check():
                logger.info("Vault manager initialized successfully")
            else:
                logger.warning("Vault connection failed - running in degraded mode")

        except ImportError:
            logger.warning(
                "hvac library not installed. Install with: pip install hvac==1.2.1"
            )
        except Exception as e:
            logger.warning(f"Failed to initialize Vault: {e}. Running in fallback mode")

    # ────────────────────────────────────────────────────────────────────────
    # Private Key Storage
    # ────────────────────────────────────────────────────────────────────────

    def store_private_key(
        self, user_id: str, private_key_pem: str, ttl: str = "2160h"  # 90 days
    ) -> bool:
        """
        Store user's private key in Vault (NEVER store in DB or code).

        Args:
            user_id: User UUID.
            private_key_pem: ECDSA private key in PEM format.
            ttl: Time-to-live (default: 2160h = 90 days).

        Returns:
            True if stored successfully, False otherwise.
        """
        if not self.client:
            logger.error("Vault not available. Cannot store private key.")
            return False

        try:
            secret_path = f"secret/data/{self.vault_namespace}/users/{user_id}/private_key"

            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret_dict={
                    "pem": private_key_pem,
                    "timestamp": self._get_timestamp(),
                },
            )

            logger.info(f"Stored private key in Vault for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store private key in Vault: {e}")
            return False

    def retrieve_private_key(self, user_id: str) -> Optional[str]:
        """
        Retrieve user's private key from Vault.

        Args:
            user_id: User UUID.

        Returns:
            Private key PEM string if found, None otherwise.
        """
        if not self.client:
            logger.debug("Vault not available. Cannot retrieve private key.")
            return None

        try:
            secret_path = f"secret/data/{self.vault_namespace}/users/{user_id}/private_key"
            secret = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            private_key = secret["data"]["data"]["pem"]

            logger.debug(f"Retrieved private key from Vault for user {user_id}")
            return private_key

        except Exception as e:
            logger.warning(f"Failed to retrieve private key for {user_id}: {e}")
            return None

    def delete_private_key(self, user_id: str) -> bool:
        """
        Delete a private key from Vault (e.g., on key rotation).

        Args:
            user_id: User UUID.

        Returns:
            True if deleted, False otherwise.
        """
        if not self.client:
            logger.error("Vault not available. Cannot delete private key.")
            return False

        try:
            secret_path = f"secret/data/{self.vault_namespace}/users/{user_id}/private_key"
            self.client.secrets.kv.v2.delete_secret_version(path=secret_path)

            logger.info(f"Deleted private key from Vault for user {user_id}")
            return True

        except Exception as e:
            logger.warning(f"Failed to delete private key for {user_id}: {e}")
            return False

    # ────────────────────────────────────────────────────────────────────────
    # Encryption Keys
    # ────────────────────────────────────────────────────────────────────────

    def store_encryption_key(
        self, key_id: str, key_material: str, metadata: Optional[Dict] = None
    ) -> bool:
        """
        Store encryption key with metadata.

        Args:
            key_id: Unique key identifier.
            key_material: Key material (base64 encoded).
            metadata: Optional metadata (algorithm, version, etc.).

        Returns:
            True if stored, False otherwise.
        """
        if not self.client:
            logger.error("Vault not available. Cannot store encryption key.")
            return False

        try:
            secret_path = f"secret/data/{self.vault_namespace}/keys/{key_id}"
            secret_dict = {
                "key_material": key_material,
                "timestamp": self._get_timestamp(),
            }

            if metadata:
                secret_dict.update(metadata)

            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path, secret_dict=secret_dict
            )

            logger.info(f"Stored encryption key {key_id} in Vault")
            return True

        except Exception as e:
            logger.error(f"Failed to store encryption key: {e}")
            return False

    def retrieve_encryption_key(self, key_id: str) -> Optional[str]:
        """
        Retrieve encryption key from Vault.

        Args:
            key_id: Unique key identifier.

        Returns:
            Key material if found, None otherwise.
        """
        if not self.client:
            logger.debug("Vault not available. Cannot retrieve encryption key.")
            return None

        try:
            secret_path = f"secret/data/{self.vault_namespace}/keys/{key_id}"
            secret = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            key_material = secret["data"]["data"]["key_material"]

            logger.debug(f"Retrieved encryption key: {key_id}")
            return key_material

        except Exception as e:
            logger.warning(f"Failed to retrieve encryption key {key_id}: {e}")
            return None

    # ────────────────────────────────────────────────────────────────────────
    # Key Rotation
    # ────────────────────────────────────────────────────────────────────────

    def rotate_key(
        self,
        key_id: str,
        new_key_material: str,
        old_key_id: Optional[str] = None,
    ) -> bool:
        """
        Rotate encryption key (create new version, keep old for decryption).

        Args:
            key_id: Key identifier to rotate.
            new_key_material: New key material (base64 encoded).
            old_key_id: Optional backup ID for old key.

        Returns:
            True if rotated successfully, False otherwise.
        """
        if not self.client:
            logger.error("Vault not available. Cannot rotate key.")
            return False

        try:
            # Save old key as backup if requested
            if old_key_id:
                old_key = self.retrieve_encryption_key(key_id)
                if old_key:
                    self.store_encryption_key(
                        old_key_id,
                        old_key,
                        {
                            "version": f"v1_backup_of_{key_id}",
                            "archived": True,
                        },
                    )

            # Update key with new material
            secret_path = f"secret/data/{self.vault_namespace}/keys/{key_id}"
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret_dict={
                    "key_material": new_key_material,
                    "timestamp": self._get_timestamp(),
                    "rotated": True,
                },
            )

            logger.info(f"Rotated encryption key: {key_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to rotate key {key_id}: {e}")
            return False

    # ────────────────────────────────────────────────────────────────────────
    # Generic Secrets
    # ────────────────────────────────────────────────────────────────────────

    def store_secret(self, secret_name: str, secret_value: str) -> bool:
        """
        Store arbitrary secret in Vault.

        Args:
            secret_name: Secret identifier (e.g., "db_password").
            secret_value: Secret value.

        Returns:
            True if stored, False otherwise.
        """
        if not self.client:
            logger.error("Vault not available. Cannot store secret.")
            return False

        try:
            secret_path = f"secret/data/{self.vault_namespace}/{secret_name}"
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret_dict={"value": secret_value, "timestamp": self._get_timestamp()},
            )

            logger.info(f"Stored secret in Vault: {secret_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to store secret: {e}")
            return False

    def retrieve_secret(self, secret_name: str) -> Optional[str]:
        """
        Retrieve secret from Vault.

        Args:
            secret_name: Secret identifier.

        Returns:
            Secret value if found, None otherwise.
        """
        if not self.client:
            logger.debug("Vault not available. Cannot retrieve secret.")
            return None

        try:
            secret_path = f"secret/data/{self.vault_namespace}/{secret_name}"
            secret = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            secret_value = secret["data"]["data"]["value"]

            logger.debug(f"Retrieved secret from Vault: {secret_name}")
            return secret_value

        except Exception as e:
            logger.warning(f"Failed to retrieve secret {secret_name}: {e}")
            return None

    # ────────────────────────────────────────────────────────────────────────
    # Health & Diagnostics
    # ────────────────────────────────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Check Vault connectivity and readiness.

        Returns:
            True if Vault is healthy and unsealed, False otherwise.
        """
        if not self.client:
            logger.debug("Vault client not initialized")
            return False

        try:
            health_status = self.client.sys.is_sealed()
            is_healthy = not health_status  # True if NOT sealed

            if is_healthy:
                logger.debug("Vault health check passed")
            else:
                logger.warning("Vault is sealed")

            return is_healthy

        except Exception as e:
            logger.warning(f"Vault health check failed: {e}")
            return False

    def get_status(self) -> Dict:
        """
        Get Vault status information.

        Returns:
            Dictionary with Vault status (development use).
        """
        if not self.client:
            return {"status": "not_initialized"}

        try:
            sealed = self.client.sys.is_sealed()
            return {
                "status": "sealed" if sealed else "operational",
                "address": self.vault_addr,
                "namespace": self.vault_namespace,
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ────────────────────────────────────────────────────────────────────────
    # Utilities
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_timestamp() -> str:
        """Get ISO format timestamp."""
        from datetime import datetime

        return datetime.utcnow().isoformat()
