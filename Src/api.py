import os
import logging
from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse


from Src.core.database import engine, Base, SessionLocal
from Src.routers.auth_router import router as auth_router
from Src.routers.audit_router import router as audit_router
from Src.routers.chat_router import router as chat_router


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
    handlers=[logging.FileHandler("data/app.log"), logging.StreamHandler()],
)
logger = logging.getLogger("SecureAudit_API")


os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

app = FastAPI(title="Sistema Auditoría IA (ENS) - RAG FAISS")
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(chat_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
   
    logger.error(f"Fallo no controlado en la ruta {request.url.path}: {exc}")

    return JSONResponse(
        status_code=500,
        content={"detail": "Se ha producido un error interno en el servidor. El incidente ha sido registrado."},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

os.makedirs(FRONTEND_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def servir_interfaz():
    html_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(html_path):
        return {"error": "No se encuentra el archivo index.html en la carpeta frontend"}
    return FileResponse(html_path)
