import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database.mysql import init_db
from app.api import security, vulnerabilities, scans, reports

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SecurityTest-AI")

app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous Multi-Agent Security Testing, Vulnerability Discovery & Automated Remediation Platform.",
    version="1.0.0"
)

# Enable CORS for frontend applications
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(security.router)
app.include_router(vulnerabilities.router)
app.include_router(scans.router)
app.include_router(reports.router)

@app.on_event("startup")
def on_startup():
    logger.info("Initializing SecurityTest-AI database and tables...")
    init_db()
    logger.info("SecurityTest-AI is live and listening.")

@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "status": "operational",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "app_env": settings.APP_ENV,
        "debug": settings.DEBUG
    }
