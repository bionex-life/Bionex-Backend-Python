from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import get_settings

settings = get_settings()

# All tables are placed in a dedicated PostgreSQL schema.
# PostgreSQL 15+ revokes CREATE on "public" from non-superusers by default,
# so using a named schema avoids permission issues and makes the schema
# clearly visible in pgAdmin / psql on PostgreSQL 18.
SCHEMA = "bionex"

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base(metadata=MetaData(schema=SCHEMA))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
