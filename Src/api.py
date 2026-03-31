import os
import shutil
import uuid
import zipfile
import logging
import aiofiles
import asyncio
import redis.asyncio as redis_async
from fastapi import WebSocket, WebSocketDisconnect
from Src.celery_worker import procesar_auditoria_task
from dotenv import load_dotenv

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel



from Src.sast_scanner import ejecutar_sast_profesional
from Src.orquestador import app as grafo_agentes

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


from sqlalchemy.orm import Session
from fastapi import Depends
from Src.database import engine, Base, SessionLocal
from Src.models import Usuario, Auditoria, Vulnerabilidad
from Src.auth import get_password_hash, verificar_password, crear_token_acceso
from Src.routers.auth_router import router as auth_router, obtener_usuario_actual
from Src.routers.audit_router import router as audit_router
from Src.routers.chat_router import router as chat_router
from Src.config import settings
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from Src.config import settings


class Token(BaseModel):
    access_token: str
    token_type: str


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


load_dotenv()
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
EXTRACT_DIR = os.getenv("EXTRACT_DIR", "/app/auditoria_temp")



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"), 
        logging.StreamHandler()         
    ]
)
logger = logging.getLogger("SecureAudit_API")


os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

app = FastAPI(title="Sistema Auditoría IA (ENS) - RAG FAISS")
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(chat_router)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:8000", "http://127.0.0.1", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def servir_interfaz():
    html_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(html_path):
        return {"error": "No se encuentra el archivo index.html en la carpeta frontend"}
    return FileResponse(html_path)


