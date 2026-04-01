from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
import jwt

from Src.database import SessionLocal
from Src.models import Usuario
from Src.auth import get_password_hash, verificar_password, crear_token_acceso

from Src.config import settings

router = APIRouter(tags=["Autenticación"])


class UsuarioRegistro(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def obtener_usuario_actual(request: Request, db: Session = Depends(get_db)):
    """Extrae el usuario validando la cookie HttpOnly"""
    token = request.cookies.get("access_token")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]

    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token expirado o inválido")

    user = db.query(Usuario).filter(Usuario.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


@router.post("/registro", response_model=Token)
def registrar_usuario(usuario: UsuarioRegistro, db: Session = Depends(get_db)):
    db_user = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El email ya está registrado")

    hashed_password = get_password_hash(usuario.password)
    nuevo_usuario = Usuario(email=usuario.email, hashed_password=hashed_password)
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)

    access_token = crear_token_acceso(data={"sub": nuevo_usuario.email})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login")
def login(usuario: UsuarioRegistro, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    if not db_user or not verificar_password(usuario.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    access_token = crear_token_acceso(data={"sub": db_user.email})

    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {"mensaje": "Login exitoso", "email": db_user.email}


@router.post("/logout")
def logout(response: Response):

    response.delete_cookie(key="access_token", path="/", samesite="lax")
    return {"mensaje": "Sesión cerrada correctamente"}


@router.get("/me")
def read_users_me(current_user: Usuario = Depends(obtener_usuario_actual)):
    return {"email": current_user.email, "id": current_user.id}
