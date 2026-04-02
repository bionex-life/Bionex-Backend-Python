"""
Test configuration.

Requires a running PostgreSQL instance.
Set TEST_DATABASE_URL in your environment or .env.test before running.

  $env:TEST_DATABASE_URL = "postgresql://bionex_user:strong_password@localhost:5432/bionex_test"
  .\.venv\Scripts\pytest
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://bionex_user:strong_password@localhost:5432/bionex_test",
)

engine = create_engine(TEST_DB_URL, pool_pre_ping=True)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function", autouse=False)
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
