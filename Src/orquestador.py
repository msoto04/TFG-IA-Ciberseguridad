import time
import os
import logging
from typing import TypedDict, List
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

from langchain_community.chat_models import ChatOllama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS


load_dotenv()
DB_PATH = os.getenv("FAISS_PATH", "/app/faiss_index")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
MODELO_ORQUESTADOR = os.getenv("MODELO_ORQUESTADOR", "llama3.2:3b")


logger = logging.getLogger("SecureAudit_LangGraph")


llm = ChatOllama(
    model=MODELO_ORQUESTADOR, 
    temperature=0,
    base_url=OLLAMA_URL  
)

embeddings = OllamaEmbeddings(
    model="nomic-embed-text",
    base_url=OLLAMA_URL 
)


class AuditoriaState(TypedDict):
    hallazgos_tecnicos: List[dict]
    explicacion_tecnica: str
    articulos_legales: str
    veredicto_final: str
    tiempos: dict 


def agente_tecnico(state: AuditoriaState):
    inicio = time.time()
    logger.info("--- [AGENTE TÉCNICO] Analizando fallo de código... ---")
    
    hallazgo = state['hallazgos_tecnicos'][0]
    
    prompt = f"Explica brevemente el riesgo técnico de la vulnerabilidad '{hallazgo['vulnerabilidad']}' encontrada en el archivo '{hallazgo['archivo']}'. Sé directo y técnico."
    
    try:
        respuesta = llm.invoke(prompt)
        explicacion = respuesta.content
        logger.info(f"Análisis técnico generado para {hallazgo['vulnerabilidad']}")
    except Exception as e:
        logger.error(f"Fallo críttico en Agente Técnico: {e}", exc_info=True)
        explicacion = f"Error generando explicación técnica: {str(e)}"

    fin = time.time()
    
    # Manejo seguro del diccionario de tiempos
    tiempos = state.get('tiempos', {})
    tiempos['tecnico'] = round(fin - inicio, 2)
    
    return {"explicacion_tecnica": explicacion, "tiempos": tiempos}


def agente_legal(state: AuditoriaState):
    inicio = time.time()
    logger.info("--- [AGENTE LEGAL] Consultando base de datos FAISS (ENS/OWASP)... ---")
    
    hallazgo = state['hallazgos_tecnicos'][0]
    
   
    try:
        vector_db = FAISS.load_local(DB_PATH, embeddings, allow_dangerous_deserialization=True)
        busqueda = f"{hallazgo['vulnerabilidad']} seguridad ENS normativa"
        documentos = vector_db.similarity_search(busqueda, k=3)
        contexto_ens = "\n\n".join([doc.page_content for doc in documentos])
        logger.info(f"Se recuperaron {len(documentos)} fragmentos normativos.")
    except Exception as e:
        logger.error(f"No se pudo acceder a FAISS en Agente Legal: {e}", exc_info=True)
        contexto_ens = "La documentación normativa no está disponible por un error de base de datos."

    prompt = f"""Eres un Auditor Experto en Ciberseguridad y Cumplimiento.
    
    FALLO TÉCNICO DETECTADO:
    {state['explicacion_tecnica']}
    
    DOCUMENTACIÓN RECUPERADA (OWASP, ENS, RGPD):
    {contexto_ens}
    
    TU TAREA:
    Genera una respuesta en formato tabla Markdown exacta con estos campos.
    
    | Campo | Detalle |
    | :--- | :--- |
    | **Vulnerabilidad** | {hallazgo['vulnerabilidad']} |
    | **Normativa / Incumplimiento** | (Extrae la norma aplicable de la DOCUMENTACIÓN RECUPERADA. NO inventes artículos. Si es de OWASP, cita OWASP) |
    | **Nivel de Riesgo** | {hallazgo['severidad']} |
    | **SOLUCIÓN TÉCNICA** | (Basado en la documentación recuperada, explica cómo solucionar esta vulnerabilidad en el código) |
    """
    
    try:
        respuesta = llm.invoke(prompt)
        veredicto = respuesta.content
        logger.info("Veredicto legal/técnico generado con éxito.")
    except Exception as e:
        logger.error(f"Fallo crítico en Agente Legal al invocar LLM: {e}", exc_info=True)
        veredicto = f"Error generando informe legal: {str(e)}"

    fin = time.time()
    
    tiempos = state.get('tiempos', {})
    tiempos['legal'] = round(fin - inicio, 2)
    
    return {"veredicto_final": veredicto, "tiempos": tiempos}


logger.info("Inicializando Grafo LangGraph de Auditoría...")
workflow = StateGraph(AuditoriaState)


workflow.add_node("agente_tecnico", agente_tecnico)
workflow.add_node("agente_legal", agente_legal)


workflow.set_entry_point("agente_tecnico")
workflow.add_edge("agente_tecnico", "agente_legal")
workflow.add_edge("agente_legal", END)


app = workflow.compile()