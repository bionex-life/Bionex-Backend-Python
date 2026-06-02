from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings
from app.middleware.security import CSRFProtectionMiddleware, RequestIDMiddleware, SecurityHeadersMiddleware
from app.routers import (
    admin,
    auth,
    doctor,
    documents,
    family,
    lab_orders,
    lab_tests,
    medical_records,
    medications,
    patients,
    payments,
    reminders,
    sharing,
)

settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: could add DB connectivity check here
    yield
    # Shutdown: clean up resources if needed


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Bionex — secure patient-centric digital health record API",
    # Hide docs in production; set DEBUG=true in .env to re-enable
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)


# ── Exception Handlers ────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    """Convert Pydantic validation errors to 400 Bad Request instead of 422."""
    # Extract error details properly for JSON serialization
    errors = []
    for error in exc.errors():
        error_dict = {
            "type": error.get("type", "value_error"),
            "loc": list(error.get("loc", [])),
            "msg": error.get("msg", "Validation error"),
        }
        errors.append(error_dict)
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": errors},
    )


# ── Middleware ────────────────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware (Enhanced Security #9, #10)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(CSRFProtectionMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Sharing-Token"],
)

# ── Health check ─────────────────────────────────────────────────────────────


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "ok", "version": settings.APP_VERSION}


# ── API Routers ───────────────────────────────────────────────────────────────

PREFIX = "/api/v1"

app.include_router(auth.router, prefix=f"{PREFIX}/auth", tags=["auth"])
app.include_router(patients.router, prefix=f"{PREFIX}/patients", tags=["patients"])
app.include_router(family.router, prefix=f"{PREFIX}/family", tags=["family"])
app.include_router(medical_records.router, prefix=f"{PREFIX}/records", tags=["medical-records"])
app.include_router(medications.router, prefix=f"{PREFIX}/medications", tags=["medications"])
app.include_router(reminders.router, prefix=f"{PREFIX}/reminders", tags=["reminders"])
app.include_router(lab_tests.router, prefix=f"{PREFIX}/lab-tests", tags=["lab-tests"])
app.include_router(lab_orders.router, prefix=f"{PREFIX}/lab-orders", tags=["lab-orders"])
app.include_router(payments.router, prefix=f"{PREFIX}/payments", tags=["payments"])
app.include_router(sharing.router, prefix=f"{PREFIX}/sharing", tags=["sharing"])
app.include_router(documents.router, prefix=f"{PREFIX}/documents", tags=["documents"])
app.include_router(doctor.router, prefix=f"{PREFIX}/doctor", tags=["doctor"])
app.include_router(admin.router, prefix=f"{PREFIX}/admin", tags=["admin"])

