import os
from typing import TypedDict, List
from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

# 1. Configuración de los modelos
llm = ChatOllama(model="deepseek-r1:8b", temperature=0) # Temperature 0 para que no invente
embeddings = OllamaEmbeddings(model="nomic-embed-text")

# 2. Definición del Estado
class AuditoriaState(TypedDict):
    hallazgos_tecnicos: List[dict]
    explicacion_tecnica: str
    articulos_legales: str
    veredicto_final: str

# --- NODO 1: AGENTE TÉCNICO ---
def agente_tecnico(state: AuditoriaState):
    print("\n--- [AGENTE TÉCNICO] Analizando fallo de código... ---")
    hallazgo = state['hallazgos_tecnicos'][0] # Analizamos el primero para la prueba
    
    prompt = f"""Eres un experto en ciberseguridad. Analiza este fallo detectado por Semgrep:
    Vulnerabilidad: {hallazgo['vulnerabilidad']}
    Descripción: {hallazgo['descripcion']}
    Código afectado: {hallazgo['codigo_afectado']}
    
    Explica brevemente qué riesgo técnico real supone esto para la empresa."""
    
    respuesta = llm.invoke(prompt)
    return {"explicacion_tecnica": respuesta.content}

# --- NODO 2: AGENTE LEGAL (RAG) ---
def agente_legal(state: AuditoriaState):
    print("\n--- [AGENTE LEGAL] Buscando normativa en el ENS... ---")
    # Cargamos la base de datos que creamos en el Sprint 1
    vector_db = FAISS.load_local(
        "D:/TFG_Ciberseguridad/faiss_index", 
        embeddings, 
        allow_dangerous_deserialization=True
    )
    
    # Buscamos en el ENS usando la explicación técnica como consulta
    consulta = state['explicacion_tecnica']
    docs = vector_db.similarity_search(consulta, k=2)
    contexto_legal = "\n".join([d.page_content for d in docs])
    
    prompt = f"""Eres un Auditor Jefe del ENS. Basándote SOLO en este contexto legal:
    {contexto_legal}
    
    Justifica qué artículo o principio del ENS se está incumpliendo debido al riesgo técnico: 
    {state['explicacion_tecnica']}"""
    
    respuesta = llm.invoke(prompt)
    return {"veredicto_final": respuesta.content, "articulos_legales": contexto_legal}

# --- MONTAJE DEL FLUJO ---
workflow = StateGraph(AuditoriaState)
workflow.add_node("tecnico", agente_tecnico)
workflow.add_node("legal", agente_legal)

workflow.set_entry_point("tecnico")
workflow.add_edge("tecnico", "legal")
workflow.add_edge("legal", END)

app = workflow.compile()

if __name__ == "__main__":
    # Datos que vienen de tu sast_scanner.py
    hallazgo_real = [{
        "vulnerabilidad": "SQL Injection",
        "descripcion": "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query",
        "codigo_afectado": "query = 'SELECT * FROM users WHERE username = ' + user_input",
        "severidad": "High"
    }]
    
    final_state = app.invoke({"hallazgos_tecnicos": hallazgo_real})
    
    print("\n" + "="*50)
    print("VEREDICTO FINAL DE AUDITORÍA:")
    print("="*50)
    print(final_state['veredicto_final'])