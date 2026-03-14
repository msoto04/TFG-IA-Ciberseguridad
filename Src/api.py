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

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langchain_community.chat_models import ChatOllama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain

from Src.sast_scanner import ejecutar_sast_profesional
from Src.orquestador import app as grafo_agentes

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


from sqlalchemy.orm import Session
from fastapi import Depends
from Src.database import engine, Base, SessionLocal
from Src.models import Usuario, Auditoria, Vulnerabilidad
from Src.auth import get_password_hash, verificar_password, crear_token_acceso


from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from Src.auth import SECRET_KEY, ALGORITHM

class UsuarioRegistro(BaseModel):
    email: str
    password: str

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
FAISS_PATH = os.getenv("FAISS_PATH", "/app/faiss_index")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")


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

@app.on_event("startup")
def crear_usuario_demo():
    db = SessionLocal()
   
    if not db.query(Usuario).first():
        usuario_demo = Usuario(email="auditor@empresa.com", hashed_password="123")
        db.add(usuario_demo)
        db.commit()
    db.close()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
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


class ChatRequest(BaseModel):
    mensaje: str
    temperature: float = 0.0
    modelo: str = "llama3.1:8b" 

@app.post("/chat")
async def chat_rag(request: ChatRequest):
    try:
        logger.info(f"Petición Chat RAG recibida. Modelo: {request.modelo}, Temperatura: {request.temperature}") 
        
        embeddings = OllamaEmbeddings(
            model="mxbai-embed-large",
            base_url=OLLAMA_URL  
        )
        
        try:
            vector_db = FAISS.load_local(
                FAISS_PATH, 
                embeddings, 
                allow_dangerous_deserialization=True
            )
        except Exception as e:
            logger.error(f"Error cargando FAISS: {e}")
            raise HTTPException(status_code=500, detail="Error: No encuentro la base de conocimientos (FAISS).")

        
        llm_dinamico = ChatOllama(
            model=request.modelo,  
            temperature=request.temperature,
            base_url=OLLAMA_URL 
        )

       
        prompt_template = ChatPromptTemplate.from_template("""
            Eres un Auditor IA Jefe experto en Ciberseguridad y normativas legales.

            CONTEXTO RECUPERADO DE LOS DOCUMENTOS:
            {context}

            REGLAS DE COMPORTAMIENTO:
            1. Tu objetivo es responder la pregunta del usuario basándote ÚNICAMENTE en el contexto proporcionado arriba.
            2. RESOLUCIÓN DE SIGLAS: Si el usuario usa siglas (como ENS, RGPD, OWASP, etc.), utiliza tu conocimiento técnico general para entender a qué se refiere, y busca ese concepto en el contexto.
            3. Si la respuesta está en el contexto, explícala con claridad y profesionalidad.
            4. Si el contexto NO contiene la respuesta, di explícitamente: "No encuentro esta información en la documentación normativa auditada."

            PREGUNTA DEL USUARIO:
            {input}
            """)
        
        document_chain = create_stuff_documents_chain(llm_dinamico, prompt_template)
        retriever = vector_db.as_retriever(search_kwargs={"k": 10})
        rag_chain = create_retrieval_chain(retriever, document_chain)

        
        respuesta = await asyncio.to_thread(rag_chain.invoke, {"input": request.mensaje})
        
        logger.info("Respuesta del chat generada con éxito.")
        
        return {"respuesta": respuesta["answer"]}

    except Exception as e:
        logger.error(f"Error inesperado en Chat: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


security = HTTPBearer()

def obtener_usuario_actual(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha caducado, haz login de nuevo")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token falso o modificado")
    
    user = db.query(Usuario).filter(Usuario.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="El usuario ya no existe")
        
    return user


@app.post("/auditar-zip")
async def auditar_zip(
    file: UploadFile = File(...), 
    current_user: Usuario = Depends(obtener_usuario_actual),
    db: Session = Depends(get_db)  
):
    audit_id = str(uuid.uuid4())
    zip_path = os.path.join(UPLOAD_DIR, f"{audit_id}.zip")
    work_dir = os.path.join(EXTRACT_DIR, audit_id)
    
    content = await file.read()
    async with aiofiles.open(zip_path, 'wb') as out_file:
        await out_file.write(content)

 
    nueva_auditoria = Auditoria(
        id=audit_id,
        nombre_archivo=file.filename,
        usuario_id=current_user.id,  
        puntuacion=0.0
    )
    db.add(nueva_auditoria)
    db.commit()

    procesar_auditoria_task.apply_async(
        args=[audit_id, zip_path, work_dir, file.filename, current_user.id],
        countdown=2
    )
  
    return {
        "estado": "Procesando",
        "audit_id": audit_id
    }


@app.post("/registro")
def registrar_usuario(user: UsuarioRegistro, db: Session = Depends(get_db)):
   
    db_user = db.query(Usuario).filter(Usuario.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    

    hashed_password = get_password_hash(user.password)
    
 
    nuevo_usuario = Usuario(email=user.email, hashed_password=hashed_password)
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)
    
    return {"mensaje": "Usuario creado exitosamente. ¡Ya puedes iniciar sesión!"}

@app.post("/login", response_model=Token)
def login(user: UsuarioRegistro, db: Session = Depends(get_db)):
   
    db_user = db.query(Usuario).filter(Usuario.email == user.email).first()
    
 
    if not db_user or not verificar_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    

    access_token = crear_token_acceso(data={"sub": str(db_user.id)})
    
    return {"access_token": access_token, "token_type": "bearer"}




@app.websocket("/ws/progreso/{audit_id}")
async def websocket_progreso(websocket: WebSocket, audit_id: str):
    await websocket.accept()
    redis_client = redis_async.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"progreso_{audit_id}")
    
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                datos = message["data"].decode("utf-8")
                await websocket.send_text(datos)
            
                if '"progreso": 100' in datos or '"progreso": -1' in datos:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe()
        await websocket.close()


@app.get("/auditoria/{audit_id}")
def obtener_resultado_auditoria(audit_id: str, db: Session = Depends(get_db)):
    auditoria = db.query(Auditoria).filter(Auditoria.id == audit_id).first()
    if not auditoria:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada")
    
    resultados = []
    for v in auditoria.vulnerabilidades:
        resultados.append({
            "vulnerabilidad": v.nombre,
            "archivo": v.archivo_afectado,
            "severidad": v.severidad,
            "analisis_legal": v.analisis_legal
        })
        
    return {
        "estado": "Finalizado",
        "total_vulnerabilidades": len(resultados),
        "resultados": resultados
    }

@app.get("/historial")
def obtener_historial(
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(obtener_usuario_actual)  
):

    auditorias = db.query(Auditoria)\
        .filter(Auditoria.usuario_id == current_user.id)\
        .order_by(Auditoria.fecha.desc())\
        .limit(5).all()
    
    resultados = []
    for a in auditorias:
        resultados.append({
            "id": a.id,
            "nombre_archivo": a.nombre_archivo,
            "fecha": a.fecha.strftime("%Y-%m-%d %H:%M:%S")
        })
    return resultados