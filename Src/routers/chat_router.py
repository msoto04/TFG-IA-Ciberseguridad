import os
import jwt
import asyncio
import redis.asyncio as redis_async
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi import Depends
from typing import List
from Src.routers.auth_router import obtener_usuario_actual
from Src.core.database import SessionLocal
from Src.db_models.models import Usuario, Auditoria
from Src.core.config import settings
from Src.ai_engine.orquestador import crear_llm
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


class MensajeHistorial(BaseModel):
    rol: str   # "usuario" o "asistente"
    texto: str


class ChatRequest(BaseModel):
    mensaje: str
    historial: List[MensajeHistorial] = []   # Conversación previa
    temperature: float = 0.0
    modelo: str = "deepseek-r1:8b"
    modo_inferencia: str = "local"


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
            await pubsub.aclose()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


def _construir_historial_texto(historial: List[MensajeHistorial]) -> str:
    """
    Convierte la lista de turnos anteriores en un bloque de texto plano
    que se inyecta en el prompt para dar contexto conversacional al LLM.
    Se limita a los últimos 6 turnos (3 intercambios) para no saturar
    la ventana de contexto del modelo.
    """
    if not historial:
        return ""

    turnos_recientes = historial[-6:]
    lineas = []
    for turno in turnos_recientes:
        prefijo = "Usuario" if turno.rol == "usuario" else "Asistente"
        lineas.append(f"{prefijo}: {turno.texto}")

    return "\n".join(lineas)


@router.post("/chat")
async def chat_rag(
    request: ChatRequest,
    current_user: Usuario = Depends(obtener_usuario_actual),
):
    try:
        logger.info(
            f"Petición Chat RAG recibida. Modelo: {request.modelo}, "
            f"Temperatura: {request.temperature}, "
            f"Turnos de historial: {len(request.historial)}"
        )

        embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=OLLAMA_URL)

        try:
            vector_db = FAISS.load_local(
                FAISS_PATH, embeddings, allow_dangerous_deserialization=True
            )
        except Exception as e:
            logger.error(f"Error cargando FAISS: {e}")
            raise HTTPException(
                status_code=500,
                detail="Error: No encuentro la base de conocimientos (FAISS).",
            )

        llm_dinamico = crear_llm(
            modelo=request.modelo,
            temperatura=request.temperature,
            modo=request.modo_inferencia,
        )

        historial_texto = _construir_historial_texto(request.historial)

        # El bloque de historial solo aparece en el prompt si hay turnos previos
        bloque_historial = ""
        if historial_texto:
            bloque_historial = f"""
            CONVERSACIÓN PREVIA (usa este contexto para responder preguntas de seguimiento):
            {historial_texto}
            """

        prompt_template = ChatPromptTemplate.from_template("""
            Eres un Auditor IA Jefe experto en Ciberseguridad y normativas legales.

            CONTEXTO RECUPERADO DE LOS DOCUMENTOS:
            {{context}}
            {bloque_historial}
            REGLAS DE COMPORTAMIENTO:
            1. Tu objetivo es responder la pregunta del usuario basándote ÚNICAMENTE en el contexto proporcionado arriba.
            2. Si hay conversación previa, tenla en cuenta para resolver referencias como "el artículo anterior", "lo que dijiste antes" o "¿y qué más?".
            3. RESOLUCIÓN DE SIGLAS: Si el usuario usa siglas (como ENS, RGPD, OWASP, etc.), utiliza tu conocimiento técnico general para entender a qué se refiere, y busca ese concepto en el contexto.
            4. Si la respuesta está en el contexto, explícala con claridad y profesionalidad.
            5. Si el contexto NO contiene la respuesta, di explícitamente: "No encuentro esta información en la documentación normativa auditada."

            PREGUNTA DEL USUARIO:
            {{input}}
            """.format(bloque_historial=bloque_historial))

        document_chain = create_stuff_documents_chain(llm_dinamico, prompt_template)
        retriever = vector_db.as_retriever(search_kwargs={"k": 10})
        rag_chain = create_retrieval_chain(retriever, document_chain)

        respuesta = await asyncio.to_thread(
            rag_chain.invoke, {"input": request.mensaje}
        )

        logger.info("Respuesta del chat generada con éxito.")

        fuentes_usadas = []
        if "context" in respuesta:
            for doc in respuesta["context"][:3]:
                nombre_archivo = doc.metadata.get("source", "Documento normativo")
                nombre_archivo = nombre_archivo.split("/")[-1].split("\\")[-1]
                fuentes_usadas.append(
                    {
                        "origen": nombre_archivo,
                        "pagina": doc.metadata.get("page", "N/A"),
                        "fragmento": doc.page_content[:350] + "...",
                    }
                )

        return {"respuesta": respuesta["answer"], "fuentes": fuentes_usadas}

    except Exception as e:
        logger.error(f"Error inesperado en Chat: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


security = HTTPBearer()