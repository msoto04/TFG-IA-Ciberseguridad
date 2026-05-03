import os
from dotenv import load_dotenv

load_dotenv()

_SECRET_KEY_ENV = os.getenv("SECRET_KEY")


if not _SECRET_KEY_ENV:
    raise ValueError(
        "ERROR CRÍTICO DE SEGURIDAD: "
        "No se ha encontrado la variable 'SECRET_KEY' en el archivo .env. "
        "El servidor se detendrá por seguridad. Por favor, configura una clave robusta."
    )

class Settings:
    PROJECT_NAME: str = "TFG IA Ciberseguridad"

  
    SECRET_KEY: str = _SECRET_KEY_ENV
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/secureaudit.db")

  
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")


settings = Settings()