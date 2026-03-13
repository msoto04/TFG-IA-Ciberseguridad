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
    model="mxbai-embed-large",
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
        logger.error(f"Fallo crítico en Agente Técnico: {e}", exc_info=True)
        explicacion = f"Error generando explicación técnica: {str(e)}"

    fin = time.time()
    
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

 
    TRADUCTOR_VULNERABILIDADES = {
        "sqlalchemy-execute-raw-query": "Inyección SQL Clásica (SQLi) - CWE-89. El código concatena strings en lugar de usar parámetros seguros.",
        "insecure-hash-algorithm-md5": "Criptografía Débil (MD5) - CWE-327. Se está utilizando un algoritmo de hash obsoleto que es vulnerable a colisiones.",
        "hardcoded-secret": "Credenciales a Fuego (Hardcoded Secret) - CWE-798. Hay una contraseña, token o clave secreta escrita directamente en el código.",
        "hardcoded-password": "Credenciales a Fuego (Hardcoded Secret) - CWE-798. Contraseña escrita en texto plano en el código."
    }

    codigo_afectado = hallazgo.get('codigo_afectado', 'No disponible')
    codigo_completo = hallazgo.get('codigo_completo', 'No disponible')


    etiqueta_semgrep = hallazgo.get('vulnerabilidad', '').lower()
    vulnerabilidad_real = TRADUCTOR_VULNERABILIDADES.get(
        etiqueta_semgrep, 
        f"Vulnerabilidad técnica: {etiqueta_semgrep}"
    )

    prompt = f"""
    Eres un Auditor de Código Senior hiper-estricto. 
    REGLA DE ORO: NUNCA inventes frameworks, rutas web (Flask/Django) ni librerías que no existan en el archivo original.

    ARCHIVO ORIGINAL COMPLETO A ANALIZAR:
    {codigo_completo}

    VULNERABILIDAD A CORREGIR:
    - Tipo de fallo real: {vulnerabilidad_real}
    - Fragmento con el fallo: {codigo_afectado}

    INSTRUCCIONES DE RESPUESTA (Solo texto plano estructurado, sin Markdown):

    NORMATIVA E IMPACTO:
    Explica el impacto de este fallo ({vulnerabilidad_real}) basándote en el ARCHIVO ORIGINAL. Relaciónalo con el ENS (Esquema Nacional de Seguridad) o RGPD si es pertinente.

    SOLUCIÓN TÉCNICA:
    Muestra cómo reescribir el fragmento afectado para solucionar el problema. ESTÁS OBLIGADO a usar la misma base de datos y librerías importadas en el ARCHIVO ORIGINAL.
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