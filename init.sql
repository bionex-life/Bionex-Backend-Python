-- Initial database setup for Bionex
-- This file runs when the PostgreSQL container starts for the first time

-- The main database is created by POSTGRES_DB.
-- Create the test database used by pytest.
CREATE DATABASE bionex_test;

-- You can add any initial data setup here if needed
-- For example, create default admin user, etc.

-- Note: Database migrations will be run separately via Alembic