import time
import os
from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_community.vectorstores import FAISS


llm = ChatOllama(
    model="llama3.2:3b", 
    temperature=0,
    base_url="http://host.docker.internal:11434" 
)

embeddings = OllamaEmbeddings(
    model="nomic-embed-text",
    base_url="http://host.docker.internal:11434"
)
class AuditoriaState(TypedDict):
    hallazgos_tecnicos: List[dict]
    explicacion_tecnica: str
    articulos_legales: str
    veredicto_final: str
    tiempos: dict 


def agente_tecnico(state: AuditoriaState):
    inicio = time.time()
    print("\n--- [AGENTE TÉCNICO] Analizando fallo... ---")
    
    hallazgo = state['hallazgos_tecnicos'][0]
    prompt = f"Explica el riesgo técnico de {hallazgo['vulnerabilidad']} en {hallazgo['codigo_afectado']}. Sé directo."
    
    respuesta = llm.invoke(prompt)
    fin = time.time()
    
    tiempos = state.get('tiempos', {})
    tiempos['tecnico'] = round(fin - inicio, 2)
    
    return {"explicacion_tecnica": respuesta.content, "tiempos": tiempos}

def agente_legal(state: AuditoriaState):
    inicio = time.time()
    hallazgo = state['hallazgos_tecnicos'][0]
    
    print(f"--- [AGENTE LEGAL] Buscando solución y normativa para: {hallazgo['vulnerabilidad']} ---")
    

    if os.path.exists("/app/faiss_index"):
        ruta_db = "/app/faiss_index"
    else:
   
        ruta_db = "D:/TFG_Ciberseguridad/faiss_index"
    
    vector_db = FAISS.load_local(ruta_db, embeddings, allow_dangerous_deserialization=True)

  
    docs = vector_db.similarity_search(f"{hallazgo['vulnerabilidad']} validación datos integridad", k=4)
    contexto_ens = "\n".join([d.page_content for d in docs])


    prompt = f"""Eres un Auditor Técnico y Legal.
    
    PROBLEMA DETECTADO:
    {state['explicacion_tecnica']}
    
    CONTEXTO LEGAL (ENS):
    {contexto_ens}
    
    INSTRUCCIONES:
    1. Identifica qué artículo del ENS se incumple (busca sobre 'Validación de datos' o 'Protección').
    2. GENERA UNA SOLUCIÓN TÉCNICA: Explica cómo arreglar el código (ej. "Usar parámetros en lugar de concatenar string").
    
    Genera SOLO esta tabla Markdown:
    
    | Campo | Detalle |
    | :--- | :--- |
    | **Vulnerabilidad** | {hallazgo['vulnerabilidad']} |
    | **Incumplimiento ENS** | (Cita el artículo o principio de Validación/Integridad) |
    | **Nivel de Riesgo** | Alto |
    | **SOLUCIÓN TÉCNICA** | (Escribe aquí cómo corregir el código para que sea seguro) |
    """
    
    respuesta = llm.invoke(prompt)
    fin = time.time()
    
    tiempos = state['tiempos']
    tiempos['legal'] = round(fin - inicio, 2)
    
    return {"veredicto_final": respuesta.content, "tiempos": tiempos}


workflow = StateGraph(AuditoriaState)
workflow.add_node("tecnico", agente_tecnico)
workflow.add_node("legal", agente_legal)
workflow.set_entry_point("tecnico")
workflow.add_edge("tecnico", "legal")
workflow.add_edge("legal", END)
app = workflow.compile()