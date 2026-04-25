#!/bin/bash
set -e

echo "🔄 Waiting for PostgreSQL to be ready..."
while ! pg_isready -h postgres -U bionex -d bionex 2>/dev/null; do
    sleep 1
done
echo "✅ PostgreSQL is ready"

echo "🔄 Running database migrations..."
alembic upgrade head
echo "✅ Migrations completed"

echo "🚀 Starting application..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
