"""FastAPI application entry point, lifecycle management, and router inclusion."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.v1 import events, simulator
from .config import settings
from .database import init_db
from .logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Initializing Sentinel database...")
    init_db()
    logger.info("Sentinel backend startup complete.")
    yield
    logger.info("Sentinel backend shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Sentinel AI-Powered Identity Threat Detection Platform API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "sentinel-backend", "version": "1.0.0"}


# Mount routers under /api/v1
app.include_router(events.router, prefix=settings.API_V1_PREFIX)
app.include_router(simulator.router, prefix=settings.API_V1_PREFIX)

# Also mount /events directly at root to strictly support docs/API_CONTRACTS.md specification
app.include_router(events.router, prefix="", include_in_schema=False)

