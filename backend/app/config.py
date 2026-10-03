import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "SecurityTest-AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # MySQL Configuration
    MYSQL_HOST: str = "localhost"
    MYSQL_PORT: int = 3306
    MYSQL_USER: str = "sec_user"
    MYSQL_PASSWORD: str = "sec_password"
    MYSQL_DATABASE: str = "security_test_db"

    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # Groq LLM Configuration
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    # Scanner Settings
    MAX_CONCURRENT_SCANS: int = 4
    SCAN_TIMEOUT_SECONDS: int = 300
    DEFAULT_TARGET_PATH: str = "../target_samples/vulnerable_app.py"

    @property
    def mysql_url(self) -> str:
        return f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"

    @property
    def sqlite_url(self) -> str:
        # Local fallback SQLite database
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, "security_test.db")
        return f"sqlite:///{db_path}"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
