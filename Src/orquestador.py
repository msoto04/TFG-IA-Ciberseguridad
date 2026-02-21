import time
import os
from typing import TypedDict, List
from langgraph.graph import StateGraph, END


from langchain_community.chat_models import ChatOllama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

# Rutas
DB_PATH = "/app/faiss_index"


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
    
 
    prompt = f"Explica brevemente el riesgo técnico de la vulnerabilidad '{hallazgo['vulnerabilidad']}' encontrada en el archivo '{hallazgo['archivo']}'. Sé directo y técnico."
    
    try:
        respuesta = llm.invoke(prompt)
        explicacion = respuesta.content
    except Exception as e:
        explicacion = f"Error al analizar riesgo técnico: {str(e)}"
        
    fin = time.time()
    

    tiempos = state.get('tiempos', {})
    tiempos['tecnico'] = round(fin - inicio, 2)
    state['tiempos'] = tiempos
    state['explicacion_tecnica'] = explicacion
    
    return state


def agente_legal(state: AuditoriaState):
    inicio = time.time()
    print("\n--- [AGENTE LEGAL] Consultando normativa ENS (RAG)... ---")
    
    hallazgo = state['hallazgos_tecnicos'][0]
    contexto_ens = ""

   
    try:
        if os.path.exists(DB_PATH):
            vector_db = FAISS.load_local(
                DB_PATH, 
                embeddings, 
                allow_dangerous_deserialization=True
            )
            

            termino_busqueda = hallazgo['vulnerabilidad'].replace("-", " ")
            query = f"protección de la información, confidencialidad, integridad, {termino_busqueda}"
            
      
            docs = vector_db.similarity_search(query, k=5)
          
            contexto_ens = "\n\n".join([f"- {d.page_content}" for d in docs])
            print("Normativa recuperada de FAISS exitosamente.")
        else:
            print(f"AVISO: No encuentro la base de datos en {DB_PATH}. Usando conocimiento general.")
            contexto_ens = "No se pudo acceder a la normativa local (FAISS no montado). Se usará conocimiento general del ENS."
            
    except Exception as e:
        print(f"Error crítico leyendo FAISS: {e}")
        contexto_ens = "Error de lectura de base de datos."


    prompt = f"""Eres un Auditor Experto en Ciberseguridad.
    
    FALLO TÉCNICO DETECTADO:
    {state['explicacion_tecnica']}
    
    DOCUMENTACIÓN RECUPERADA (OWASP, ENS, RGPD):
    {contexto_ens}
    
    TU TAREA:
    Genera una respuesta en formato tabla Markdown exacta con estos campos.
    
    | Campo | Detalle |
    | :--- | :--- |
    | **Vulnerabilidad** | {hallazgo['vulnerabilidad']} |
    | **Normativa / Incumplimiento** | (Extrae la norma aplicable o la vulnerabilidad de la DOCUMENTACIÓN RECUPERADA. NO inventes artículos, si es de OWASP, cita OWASP) |
    | **Nivel de Riesgo** | {hallazgo['severidad']} |
    | **SOLUCIÓN TÉCNICA** | (Basado en la documentación recuperada, explica cómo solucionar esta vulnerabilidad en el código) |
    """
    
    try:
        respuesta = llm.invoke(prompt)
        veredicto = respuesta.content
    except Exception as e:
        veredicto = f"Error generando informe legal: {str(e)}"

    fin = time.time()
    
    tiempos = state['tiempos']
    tiempos['legal'] = round(fin - inicio, 2)
    state['tiempos'] = tiempos
    state['veredicto_final'] = veredicto
    
    return state


workflow = StateGraph(AuditoriaState)

workflow.add_node("tecnico", agente_tecnico)
workflow.add_node("legal", agente_legal)

workflow.set_entry_point("tecnico")
workflow.add_edge("tecnico", "legal")
workflow.add_edge("legal", END)

app = workflow.compile()