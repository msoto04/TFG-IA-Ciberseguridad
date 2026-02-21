import shutil
import os
import zipfile
import uuid
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

app = FastAPI(title="Sistema Auditoría IA (ENS) - RAG FAISS")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)


UPLOAD_DIR = "/app/uploads"
EXTRACT_DIR = "/app/auditoria_temp"
FAISS_PATH = "/app/faiss_index" 


OLLAMA_URL = "http://host.docker.internal:11434"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

class ChatRequest(BaseModel):
    mensaje: str
    temperature: float = 0.0
    modelo: str = "llama3.1:8b" 


@app.post("/chat")
async def chat_rag(request: ChatRequest):
    try:
        print(f"Chat RAG: {request.mensaje} | Modelo: {request.modelo}") 
        
      
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
            return {"respuesta": "Error: No encuentro la base de conocimientos (FAISS). ¿Has ejecutado la ingesta de vectores?"}

       
        llm = ChatOllama(
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
        
      
        document_chain = create_stuff_documents_chain(llm, prompt_template)
        retriever = vector_db.as_retriever(search_kwargs={"k": 5})
        rag_chain = create_retrieval_chain(retriever, document_chain)

     
        respuesta = rag_chain.invoke({"input": request.mensaje})
        
        return {"respuesta": respuesta["answer"]}

    except Exception as e:
        print(f"Error Chat: {e}")
        return {"respuesta": f"Error interno: {str(e)}"}

@app.post("/auditar-zip")
async def auditar_zip(file: UploadFile = File(...)):
    audit_id = str(uuid.uuid4())
    zip_path = os.path.join(UPLOAD_DIR, f"{audit_id}.zip")
    work_dir = os.path.join(EXTRACT_DIR, audit_id)
    
    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)   
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(work_dir)
            
        hallazgos = ejecutar_sast_profesional(work_dir)
        
        resultados_estructurados = []
        if hallazgos:
            for h in hallazgos:
                try:
                   
                    respuesta = grafo_agentes.invoke({
                        "hallazgos_tecnicos": [h],
                        "tiempos": {} 
                    })
                    analisis = respuesta['veredicto_final']
                except Exception as e:
                    print(f"Error Grafo: {e}")
                    analisis = f"Error analizando con IA: {str(e)}"

                item = {
                    "vulnerabilidad": h['vulnerabilidad'],
                    "archivo": h['archivo'],
                    "severidad": h['severidad'],
                    "analisis_legal": analisis
                }
                resultados_estructurados.append(item)

        return {
            "estado": "Finalizado",
            "total_vulnerabilidades": len(hallazgos),
            "resultados": resultados_estructurados
        }

    except Exception as e:
        return {"error": str(e)}
    finally:
        if os.path.exists(work_dir): shutil.rmtree(work_dir)
        if os.path.exists(zip_path): os.remove(zip_path)