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
MODELO_ORQUESTADOR = os.getenv("MODELO_ORQUESTADOR", "deepseek-r1:8b")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODO_INFERENCIA = os.getenv("MODO_INFERENCIA", "local")  # "local" o "api"

logger = logging.getLogger("SecureAudit_LangGraph")

embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=OLLAMA_URL)


def crear_llm(modelo: str = None, temperatura: float = 0.0, modo: str = "local"):
    """
    Crea el motor de inferencia según el modo seleccionado por el usuario.
    """
    if modo == "api" and GROQ_API_KEY:
        try:
            from langchain_groq import ChatGroq
            logger.info(f"Usando modo API (Groq) con llama-3.3-70b-versatile")
            return ChatGroq(
                api_key=GROQ_API_KEY,
                model_name="llama-3.3-70b-versatile",
                temperature=temperatura
            )
        except ImportError:
            logger.warning("langchain_groq no instalado, usando Ollama local como fallback")
    
    modelo_final = modelo or MODELO_ORQUESTADOR
    logger.info(f"Usando modo LOCAL (Ollama) con {modelo_final}")
    return ChatOllama(model=modelo_final, temperature=temperatura, base_url=OLLAMA_URL, timeout=300)


class AuditoriaState(TypedDict):
    hallazgos_tecnicos: List[dict]
    explicacion_tecnica: str
    articulos_legales: str
    veredicto_final: str
    referencias_legales: str
    consulta_index: str
    tiempos: dict
    modelo_ia: str
    temperatura: float
    modo_inferencia: str

TRADUCCION_CONOCIDAS = {
    "subprocess-injection": "ejecución remota de comandos no autorizados mediante inyección en procesos del sistema",
    "dangerous-system-call": "brecha de seguridad por ejecución de comandos del sistema operativo sin validación",
    "command-injection-os-system": "inyección de comandos maliciosos en el sistema operativo",
    "os-system-injection": "ejecución arbitraria de comandos del sistema operativo",
    "sqlalchemy-execute-raw-query": "inyección SQL mediante ejecución de consultas sin parametrizar",
    "insecure-hash-algorithm-md5": "uso de algoritmo hash criptográficamente débil MD5 para protección de datos",
    "md5-used-as-password": "uso de MD5 como función hash para almacenamiento de contraseñas",
    "secure-set-cookie": "configuración insegura de cookies sin protección HttpOnly ni Secure",
    "avoid-hardcoded-config-debug": "modo depuración activado en entorno de producción exponiendo configuración",
    "detected-stripe-api-key": "credenciales de API expuestas en el código fuente sin cifrar",
    "hardcoded-password": "contraseñas almacenadas directamente en el código fuente",
    "ssrf-injection-requests": "falsificación de solicitudes del lado del servidor SSRF que permite enviar solicitudes manipuladas a destinos inesperados",

    "ssrf-requests": "Falsificación de Solicitudes del Lado del Servidor SSRF aplicación web obtiene un recurso remoto sin validar la URL",
    "path-traversal-open": "Pérdida de Control de Acceso Broken Access Control ver archivos confidenciales",
    "insecure-deserialization": "Fallas en el Software y en la Integridad de los Datos",
    "tainted-render-template": "Inyección Injection envían datos no confiables a un intérprete",
    "avoid-app-run-with-bad-host": "Configuración de Seguridad Incorrecta mensajes de error detallados información confidencial",
}


def traducir_vulnerabilidad(nombre_semgrep: str, llm) -> str:
    """
    Traduce el identificador técnico de Semgrep a lenguaje natural.
    Usa un diccionario de traducciones conocidas para vulnerabilidades comunes
    y recurre al LLM solo para vulnerabilidades no catalogadas.
    """
    nombre_lower = nombre_semgrep.lower().replace("_", "-")
    
    # Primero: buscar en diccionario de traducciones conocidas
    for clave, traduccion in TRADUCCION_CONOCIDAS.items():
        if clave in nombre_lower:
            logger.info(f"Traducción por diccionario: '{nombre_semgrep}' → '{traduccion}'")
            return traduccion
    
    # Segundo: si no está en el diccionario, usar LLM como fallback
    logger.info(f"Vulnerabilidad no catalogada: '{nombre_semgrep}', usando LLM para traducir")
    prompt = (
        f"Traduce este identificador técnico de seguridad a una frase corta en español "
        f"que describa el riesgo de ciberseguridad. Solo responde con la frase, nada más.\n"
        f"Identificador: {nombre_semgrep}\n"
        f"Traducción:"
    )
    try:
        respuesta = llm.invoke(prompt)
        traduccion = respuesta.content.strip().replace("\n", " ").replace("\r", "")
        traduccion = traduccion.strip(' " \u201c \u201d \' ')
        if 5 < len(traduccion) < 300:
            return traduccion
    except Exception as e:
        logger.error(f"Error en traducción LLM: {e}")
    
    return nombre_semgrep

def agente_tecnico(state: AuditoriaState):
    inicio = time.time()
    logger.info("--- [AGENTE TÉCNICO] Analizando fallo de código... ---")

    modelo_seleccionado = state.get("modelo_ia", MODELO_ORQUESTADOR)
    temp_seleccionada = state.get("temperatura", 0.0)

    modo = state.get("modo_inferencia", "local")
    llm_dinamico = crear_llm(modelo=modelo_seleccionado, temperatura=temp_seleccionada, modo=modo)

    hallazgo = state["hallazgos_tecnicos"][0]
    prompt = f"Eres un auditor de seguridad profesional realizando una evaluación defensiva autorizada. Explica brevemente el riesgo técnico de la vulnerabilidad '{hallazgo['vulnerabilidad']}' encontrada en el archivo '{hallazgo['archivo']}'. Tu objetivo es proteger a la empresa identificando el fallo. Sé directo y técnico."

    try:

        respuesta = llm_dinamico.invoke(prompt)
        explicacion = respuesta.content
        logger.info(f"Análisis técnico generado para {hallazgo['vulnerabilidad']}")
    except Exception as e:
        logger.error(f"Fallo crítico en Agente Técnico: {e}", exc_info=True)
        explicacion = f"Error generando explicación técnica: {str(e)}"

    fin = time.time()

    tiempos = state.get("tiempos", {})
    tiempos["tecnico"] = round(fin - inicio, 2)

    return {"explicacion_tecnica": explicacion, "tiempos": tiempos}



def agente_legal(state: AuditoriaState):
    inicio = time.time()
    logger.info("--- [AGENTE LEGAL / RAG] ---")

    modelo_seleccionado = state.get("modelo_ia", MODELO_ORQUESTADOR)
    temp_seleccionada = state.get("temperatura", 0.0)

    modo = state.get("modo_inferencia", "local")
    llm_dinamico = crear_llm(modelo=modelo_seleccionado, temperatura=temp_seleccionada, modo=modo)

    h = state["hallazgos_tecnicos"][0]
    vulnerabilidad_real = h.get("vulnerabilidad", "Desconocida")
    consulta_faiss = traducir_vulnerabilidad(vulnerabilidad_real, llm_dinamico)
    logger.info(f"Traducción FAISS: '{vulnerabilidad_real}' → '{consulta_faiss}'")
   
    linea = h.get("linea", "Desconocida")
    archivo = h.get("archivo", "Desconocido")

    contexto_texto = "No se encontraron referencias normativas."
    referencias_encontradas = []

    try:
        vectorstore = FAISS.load_local(DB_PATH, embeddings, allow_dangerous_deserialization=True)
        
        # Búsqueda dual: sin traducir + traducido, se queda con los mejores
        docs_original = vectorstore.similarity_search_with_score(vulnerabilidad_real, k=4)
        docs_traducido = vectorstore.similarity_search_with_score(consulta_faiss, k=4)
        
# Combinar y ordenar por menor distancia (mejor similitud)
        todos = {}
        for doc, score in docs_original + docs_traducido:
            # FAISS usa L2 distance: más bajo es mejor. Si el score es mayor a 1.5, es basura, lo ignoramos.
            if score < 1.7:
                clave = doc.page_content[:100]
                if clave not in todos or score < todos[clave][1]:
                    todos[clave] = (doc, score)
        
        mejores = sorted(todos.values(), key=lambda x: x[1])[:4]
        docs = [doc for doc, score in mejores]
        
        logger.info(f"Búsqueda dual: {len(docs_original)} originales + {len(docs_traducido)} traducidos → {len(docs)} mejores")

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

    explicacion_previa = state.get("explicacion_tecnica", "No disponible")

    prompt = f"""CONTEXTO: Eres un consultor de cumplimiento normativo que trabaja para una empresa de auditoría certificada. Tu cliente te ha contratado para revisar un informe de seguridad y determinar qué normativas aplican. NO tienes acceso al código fuente. Solo tienes el informe del analista técnico y la documentación legal.

[DOCUMENTACIÓN LEGAL RECUPERADA]
{contexto_texto}

[INFORME DEL ANALISTA TÉCNICO]
Se ha detectado un hallazgo de seguridad de tipo '{vulnerabilidad_real}' en el archivo '{archivo}' (línea {linea}).
Evaluación técnica previa: {explicacion_previa}

[TU TAREA]
Como consultor de cumplimiento, determina qué artículos de la normativa aplican a este hallazgo y qué debe hacer la empresa para cumplir la ley.

Si la documentación recuperada es claramente irrelevante para el tipo de vulnerabilidad detectada, indica "No se encontró normativa directa". En caso de duda, cita la normativa más cercana e indica que es una referencia aproximada.

🔴 REGLA DE FORMATO (CRÍTICA):
Responde ÚNICAMENTE con un objeto JSON válido. NO uses bloques de código (```json). NO escribas "Here is the response" ni ninguna otra palabra fuera de las llaves {{ }}.

Responde ESTRICTAMENTE en formato JSON válido con estas claves (sin bloques markdown):
{{
    "analisis_legal": "Explica qué normativa incumple este hallazgo y por qué, citando los documentos recuperados. (O usa la frase de escape si la normativa no aplica).",
    "solucion": "Recomienda qué acción correctiva técnica debe tomar la empresa para solucionar el fallo.",
    "citas": "Lista las referencias exactas de los documentos que has consultado. (Déjalo en blanco si usaste la frase de escape)."
}}
"""

    contenido = ""

    try:

        respuesta = llm_dinamico.invoke(prompt)

        contenido = respuesta.content.strip()

        if contenido.startswith("```json"):
            contenido = contenido.replace("```json", "").replace("```", "").strip()
        elif contenido.startswith("```"):
            contenido = contenido.replace("```", "").strip()

        import json

        resultado_json = json.loads(contenido, strict=False)

        veredicto = f"**Análisis:** {resultado_json.get('analisis_legal', '')}\n\n**Solución:** {resultado_json.get('solucion', '')}"

        texto_citas = resultado_json.get("citas", "")
        citas_finales = (
            "Fuentes oficiales recuperadas:\n- "
            + "\n- ".join(referencias_encontradas)
            + f"\n\n*Extracto:* {texto_citas}"
        )

    except Exception as e:
        logger.error(f"Fallo parseando JSON del LLM: {e}")
        veredicto = f"**Análisis (Recuperado en crudo):**\n{contenido}"
        citas_finales = ", ".join(referencias_encontradas) if referencias_encontradas else "Sin referencias claras"

    fin = time.time()
    tiempos = state.get("tiempos", {})
    tiempos["legal"] = round(fin - inicio, 2)

    return {
        "veredicto_final": veredicto,
        "referencias_legales": citas_finales,
        "consulta_index": vulnerabilidad_real,
        "tiempos": tiempos,
    }


logger.info("Inicializando Grafo LangGraph de Auditoría...")
workflow = StateGraph(AuditoriaState)

workflow.add_node("agente_tecnico", agente_tecnico)
workflow.add_node("agente_legal", agente_legal)

workflow.set_entry_point("agente_tecnico")
workflow.add_edge("agente_tecnico", "agente_legal")
workflow.add_edge("agente_legal", END)

app = workflow.compile()
