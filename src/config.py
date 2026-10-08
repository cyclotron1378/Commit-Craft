"""Configuration management for GitSentry-AI."""
import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project Root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# API Keys
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Gemini Models
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
AVAILABLE_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
]

# AI Audit Parameters
DEFAULT_TEMPERATURE = 0.15  # Low temperature for deterministic code analysis
MAX_OUTPUT_TOKENS = 8192

# Health Score Weights (Penalty points per severity)
HEALTH_SCORE_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

# Supported File Extensions for Code Audit
AUDITABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp",
    ".cs", ".go", ".rs", ".php", ".rb", ".sql", ".sh", ".html", ".css", ".yaml", ".yml", ".json"
}
