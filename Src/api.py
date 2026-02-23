import os
import shutil
import uuid
import zipfile
import logging
import aiofiles
import asyncio
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)


class ChatRequest(BaseModel):
    mensaje: str
    temperature: float = 0.0
    modelo: str = "llama3.1:8b" 

@app.post("/chat")
async def chat_rag(request: ChatRequest):
    try:
        logger.info(f"Petición Chat RAG recibida. Modelo: {request.modelo}, Temperatura: {request.temperature}") 
        
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text",
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
            Eres un Auditor Técnico de Ciberseguridad.
            Utiliza la información del siguiente <contexto> para construir tu respuesta.
            
            <contexto>
            {context}
            </contexto>

            Pregunta: {input}
            
            INSTRUCCIONES:
            1. Lee atentamente el contexto. Si contiene información relacionada con la pregunta, úsala para dar una respuesta clara y profesional.
            2. Si la documentación menciona OWASP, ENS o RGPD, cítalos en tu respuesta.
            3. Si el contexto NO habla en absoluto del tema, responde: "La documentación normativa auditada no especifica este detalle."
            4. NO inventes leyes, artículos ni acrónimos que no estén en el texto.
        """)
        
        document_chain = create_stuff_documents_chain(llm_dinamico, prompt_template)
        retriever = vector_db.as_retriever(search_kwargs={"k": 5})
        rag_chain = create_retrieval_chain(retriever, document_chain)

        
        respuesta = await asyncio.to_thread(rag_chain.invoke, {"input": request.mensaje})
        
        logger.info("Respuesta del chat generada con éxito.")
        
        return {"respuesta": respuesta["answer"]}

    except Exception as e:
        logger.error(f"Error inesperado en Chat: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.post("/auditar-zip")
async def auditar_zip(file: UploadFile = File(...)):
    audit_id = str(uuid.uuid4())
    zip_path = os.path.join(UPLOAD_DIR, f"{audit_id}.zip")
    work_dir = os.path.join(EXTRACT_DIR, audit_id)
    
    logger.info(f"Iniciando auditoría ID: {audit_id} para el archivo: {file.filename}")

    try:
        content = await file.read()
        async with aiofiles.open(zip_path, 'wb') as out_file:
            await out_file.write(content)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(work_dir)
            
        logger.info(f"Archivo descomprimido en {work_dir}. Iniciando escáner SAST.")
        
        
        hallazgos = await asyncio.to_thread(ejecutar_sast_profesional, work_dir)
        
        resultados_estructurados = []
        if hallazgos:
            logger.info(f"Se encontraron {len(hallazgos)} vulnerabilidades. Iniciando análisis IA.")
            for h in hallazgos:
                try:
                  
                    respuesta = await asyncio.to_thread(
                        grafo_agentes.invoke, 
                        {"hallazgos_tecnicos": [h], "tiempos": {}}
                    )
                    analisis = respuesta['veredicto_final']
                except Exception as e:
                    logger.error(f"Error en LangGraph analizando hallazgo: {e}", exc_info=True)
                    analisis = f"Error analizando con IA: {str(e)}"

                item = {
                    "vulnerabilidad": h['vulnerabilidad'],
                    "archivo": h['archivo'],
                    "severidad": h['severidad'],
                    "analisis_legal": analisis
                }
                resultados_estructurados.append(item)

        logger.info(f"Auditoría {audit_id} finalizada correctamente.")
        return {
            "estado": "Finalizado",
            "total_vulnerabilidades": len(hallazgos),
            "resultados": resultados_estructurados
        }

    except Exception as e:
        logger.error(f"Error crítico en la auditoría {audit_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        logger.info(f"Limpiando archivos temporales de la auditoría {audit_id}...")
        try:
            if os.path.exists(work_dir): 
                shutil.rmtree(work_dir)
            if os.path.exists(zip_path): 
                os.remove(zip_path)
        except Exception as cleanup_error:
            logger.error(f"Error al limpiar temporales: {cleanup_error}")