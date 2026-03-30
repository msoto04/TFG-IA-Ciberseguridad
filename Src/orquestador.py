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
    referencias_legales: str  
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
    logger.info("--- [AGENTE LEGAL / RAG] ---")
    
    h = state['hallazgos_tecnicos'][0]
    vulnerabilidad_real = h.get('vulnerabilidad', 'Desconocida')
    codigo_afectado = h.get('codigo_afectado', 'No disponible')
    linea = h.get('linea', 'Desconocida')
    archivo = h.get('archivo', 'Desconocido')
  
    contexto_texto = "No se encontraron referencias normativas."
    referencias_encontradas = []
    
    try:
        vectorstore = FAISS.load_local(DB_PATH, embeddings, allow_dangerous_deserialization=True)
        retriever = vectorstore.as_retriever(search_kwargs={"k": 3})
        docs = retriever.invoke(vulnerabilidad_real)
        
        if docs:
            contexto_fragmentos = []
            for i, doc in enumerate(docs):
               
                fuente = doc.metadata.get("source", "Documento desconocido")
                fuente_corta = os.path.basename(fuente)
                pagina = doc.metadata.get("page", "N/A")
                
                ref_str = f"Documento: {fuente_corta} (Pág {pagina})"
                referencias_encontradas.append(ref_str)
                
               
                contexto_fragmentos.append(f"--- REFERENCIA {i+1} ({ref_str}) ---\n{doc.page_content}")
            
            contexto_texto = "\n\n".join(contexto_fragmentos)
            referencias_encontradas = list(set(referencias_encontradas)) 
    except Exception as e:
        logger.error(f"Fallo al consultar FAISS: {e}")

  
    prompt = f"""Eres un auditor experto en ciberseguridad y normativas legales (ENS, RGPD).
    
[CONTEXTO NORMATIVO RECUPERADO]
{contexto_texto}

[CÓDIGO VULNERABLE REPORTADO]
Archivo: {archivo} (Línea: {linea})
Código:
{codigo_afectado}

[INSTRUCCIONES]
Analiza el fallo '{vulnerabilidad_real}' basándote ÚNICAMENTE en el contexto normativo recuperado y en el código.
Devuelve tu respuesta ESTRICTAMENTE en formato JSON válido con las siguientes claves, sin bloques markdown de código (no uses ```json):
{{
    "analisis_legal": "Explica el impacto relacionando el código con la normativa citada.",
    "solucion": "Ejemplo corto de cómo arreglar el código.",
    "citas": "Cita explícita de los documentos del contexto que has utilizado para esta respuesta."
}}
"""
    
 
    try:
        respuesta = llm.invoke(prompt)
        contenido = respuesta.content.strip()
        
    
        if contenido.startswith("```json"):
            contenido = contenido.replace("```json", "").replace("```", "").strip()
        elif contenido.startswith("```"):
            contenido = contenido.replace("```", "").strip()
            
        import json
        resultado_json = json.loads(contenido)
        
        veredicto = f"**Análisis:** {resultado_json.get('analisis_legal', '')}\n\n**Solución:** {resultado_json.get('solucion', '')}"
        
        texto_citas = resultado_json.get('citas', '')
        citas_finales = "Fuentes oficiales recuperadas:\n- " + "\n- ".join(referencias_encontradas) + f"\n\n*Extracto:* {texto_citas}"
        
    except Exception as e:
        logger.error(f"Fallo parseando JSON del LLM: {e}")
        veredicto = f"Análisis técnico: La vulnerabilidad {vulnerabilidad_real} requiere revisión."
        citas_finales = ", ".join(referencias_encontradas) if referencias_encontradas else "Sin referencias claras"

    fin = time.time()
    tiempos = state.get('tiempos', {})
    tiempos['legal'] = round(fin - inicio, 2)
    
    return {
        "veredicto_final": veredicto, 
        "referencias_legales": citas_finales,
        "tiempos": tiempos
    }


logger.info("Inicializando Grafo LangGraph de Auditoría...")
workflow = StateGraph(AuditoriaState)

workflow.add_node("agente_tecnico", agente_tecnico)
workflow.add_node("agente_legal", agente_legal)

workflow.set_entry_point("agente_tecnico")
workflow.add_edge("agente_tecnico", "agente_legal")
workflow.add_edge("agente_legal", END)

app = workflow.compile()