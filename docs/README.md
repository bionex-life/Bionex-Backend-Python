# Bionex-Backend-Python

A secure patient-centric digital health record API built with FastAPI.

## Quick Start with Docker

### Prerequisites
- Docker Desktop installed and running
- At least 4GB RAM available

### Setup
```bash
# Clone the repository
git clone <your-repo-url>
cd Bionex-Backend-Python

# Copy environment file
cp .env.example .env

# Start all services
docker-compose up -d

# Run database migrations
docker-compose exec app alembic upgrade head
```

### Access Points
- **API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **PgAdmin** (optional): http://localhost:5050 (admin@bionex.com / admin)
- **Redis Commander** (optional): http://localhost:8081

### Useful Commands
```bash
# View logs
docker-compose logs -f app

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up --build

# Run tests
docker-compose exec app pytest

# Access database directly
docker-compose exec postgres psql -U bionex -d bionex

# Run Alembic migrations
docker-compose exec app alembic upgrade head
```

## Manual Setup (without Docker)

See the full setup guide in the documentation for manual installation of Python, PostgreSQL, and Redis.

## Environment Configuration

Copy `.env.example` to `.env` and configure:

- `SECRET_KEY`: Change to a secure random key
- `FIELD_ENCRYPTION_KEY`: Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- `ALLOWED_ORIGINS`: Add your frontend URLs for CORS

## API Endpoints

- Authentication: `/api/v1/auth`
- Patients: `/api/v1/patients`
- Medical Records: `/api/v1/records`
- Medications: `/api/v1/medications`
- Lab Orders: `/api/v1/lab-orders`
- Admin: `/api/v1/admin`

## Development

```bash
# Run with hot reload
docker-compose up

# Run tests
docker-compose exec app pytest

# Generate new migration
docker-compose exec app alembic revision --autogenerate -m "description"
```