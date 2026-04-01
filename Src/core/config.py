import os
from dotenv import load_dotenv


load_dotenv()


class Settings:
    PROJECT_NAME: str = "TFG IA Ciberseguridad"

    # Seguridad
    SECRET_KEY: str = os.getenv("SECRET_KEY", "clave_por_defecto_insegura")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # Base de Datos
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/secureaudit.db")

    # Redis para Celery/WebSockets
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")


settings = Settings()
