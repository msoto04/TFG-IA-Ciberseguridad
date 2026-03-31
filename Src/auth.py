from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from Src.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verificar_password(plain_password, hashed_password):
    """Comprueba si la contraseña plana coincide con el hash de la BD"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Convierte una contraseña plana en un hash indescifrable"""
    return pwd_context.hash(password)

def crear_token_acceso(data: dict):
    """Genera el Token JWT (la 'pulsera VIP')"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt