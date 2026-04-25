"""
Alembic migration utilities for automatic schema upgrades on startup.
"""

import logging
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from app.database import engine

logger = logging.getLogger(__name__)


def run_migrations() -> None:
    """
    Run Alembic migrations to upgrade the database schema to the latest version.
    This is called automatically on application startup.
    """
    try:
        # Get the path to alembic.ini
        project_root = Path(__file__).parent.parent
        alembic_ini_path = project_root / "alembic.ini"
        
        if not alembic_ini_path.exists():
            logger.warning(f"alembic.ini not found at {alembic_ini_path}")
            return
        
        # Set DATABASE_URL environment variable if not already set
        if not os.environ.get("DATABASE_URL"):
            from app.config import get_settings
            settings = get_settings()
            os.environ["DATABASE_URL"] = settings.DATABASE_URL
        
        # Configure Alembic
        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", os.environ.get("DATABASE_URL", ""))
        
        # Ensure schema exists
        with engine.connect() as connection:
            from app.database import SCHEMA
            connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
            connection.commit()
        
        # Run migrations
        logger.info("Running Alembic migrations...")
        command.upgrade(alembic_cfg, "head")
        logger.info("Migrations completed successfully")
        
    except Exception as e:
        logger.error(f"Error running migrations: {e}", exc_info=True)
        # Don't fail startup on migration error in production
        # but log it for debugging
        raise
