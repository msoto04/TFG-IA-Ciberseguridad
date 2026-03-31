import os
import jwt
import asyncio
import redis.asyncio as redis_async
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from Src.database import SessionLocal
from Src.models import Usuario, Auditoria
from Src.routers.auth_router import obtener_usuario_actual
from Src.config import settings
from Src.orquestador import app as grafo_agentes



from langchain_community.chat_models import ChatOllama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from fastapi import HTTPException
from fastapi.security import HTTPBearer
import logging

logger = logging.getLogger(__name__)


FAISS_PATH = os.getenv("FAISS_PATH", "/app/faiss_index")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")

router = APIRouter(tags=["Chat y Progreso"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class ChatRequest(BaseModel):
    mensaje: str
    temperature: float = 0.0
    modelo: str = "llama3.1:8b" 

@router.websocket("/ws/progreso/{audit_id}")
async def websocket_endpoint(websocket: WebSocket, audit_id: str):
 
    token_cookie = websocket.cookies.get("access_token")
    
    token = None
    if token_cookie and token_cookie.startswith("Bearer "):
        token = token_cookie.split(" ")[1]

    if not token:
        await websocket.close(code=1008) 
        return
        
    try:
     
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        if email is None:
            await websocket.close(code=1008)
            return
            
    
        db = SessionLocal()
      
        user = db.query(Usuario).filter(Usuario.email == email).first()
        if not user:
            db.close()
            await websocket.close(code=1008)
            return
            

        auditoria = db.query(Auditoria).filter(Auditoria.id == audit_id).first()
        db.close()

   
        if auditoria and str(auditoria.usuario_id) != str(user.id):
            await websocket.close(code=1008)
            return

    except jwt.PyJWTError:
        await websocket.close(code=1008)
        return

    
    await websocket.accept()
    
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
    pubsub = redis_async.Redis.from_url(REDIS_URL).pubsub()
    await pubsub.subscribe(f"progreso_{audit_id}")

    try:
        async for mensaje in pubsub.listen():
            if mensaje["type"] == "message":
                datos = mensaje["data"].decode("utf-8")
                await websocket.send_text(datos)
                if '"progreso": 100' in datos or '"progreso": -1' in datos:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe()
        try:
            await websocket.close()
        except:
            pass



@router.post("/chat")
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
        
   
        fuentes_usadas = []
        if "context" in respuesta:
            for doc in respuesta["context"][:3]:
             
                nombre_archivo = doc.metadata.get("source", "Documento normativo")
           
                nombre_archivo = nombre_archivo.split("/")[-1].split("\\")[-1] 
                
                fuentes_usadas.append({
                    "origen": nombre_archivo,
                    "pagina": doc.metadata.get("page", "N/A"),
                    "fragmento": doc.page_content[:350] + "..." 
                })
    
        return {
            "respuesta": respuesta["answer"],
            "fuentes": fuentes_usadas
        }

    except Exception as e:
        logger.error(f"Error inesperado en Chat: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


security = HTTPBearer()
