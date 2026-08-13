import os

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "safe-link-ai-dev-secret")
    DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "safe_link_ai.db"))
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    REPORTS_FOLDER = os.path.join(os.path.dirname(__file__), "reports")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", os.getenv("SMTP_USERNAME", "safelink.ai@example.com"))
    EMAIL_OTP_ENABLED = os.getenv("EMAIL_OTP_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    
    # Optional Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
