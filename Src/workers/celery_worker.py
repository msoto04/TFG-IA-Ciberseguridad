import os
import pathlib         
import subprocess  
import sys



if sys.argv and 'celery' in sys.argv[0]:
    if not pathlib.Path('/app/faiss_index/index.faiss').exists():
        print("================================================================")
        print("Iniciando ingesta de vectores automática...")
        print("⚠️ ESTO PUEDE TARDAR VARIOS MINUTOS DEPENDIENDO DE TU PC ⚠️")
        print("================================================================")
        try:
            subprocess.run(['python', 'Src/ai_engine/ingesta_vectores.py'], check=True)
            print("Vectores creados correctamente. Arrancando el sistema...")
        except Exception as e:
            print(f"Error crítico creando vectores: {e}")


import shutil
import zipfile
import json
import redis
    

from celery import Celery
from celery.utils.log import get_task_logger

from Src.core.database import SessionLocal
from Src.db_models.models import Vulnerabilidad, Auditoria
from Src.security_tools.sast_scanner import ejecutar_sast_profesional
from Src.ai_engine.orquestador import app as grafo_agentes



logger = get_task_logger(__name__)


REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
celery_app = Celery("auditor_tasks", broker=REDIS_URL, backend=REDIS_URL)
redis_client = redis.Redis.from_url(REDIS_URL)


def emitir_progreso(audit_id, mensaje, progreso):
    """Envía un evento en tiempo real a través de Redis"""
    try:
        evento = json.dumps({"mensaje": mensaje, "progreso": progreso})
        redis_client.publish(f"progreso_{audit_id}", evento)
    except Exception as e:
        logger.error(f"[{audit_id}] Error emitiendo progreso a Redis: {e}")

def deduplicar_hallazgos(hallazgos: list) -> list:
    """
    Agrupa vulnerabilidades que apuntan al mismo archivo y línea,
    combinando las reglas de Semgrep en un solo hallazgo para evitar
    llamadas redundantes al LLM.
    """
    vistos = {}
    for h in hallazgos:
        clave = f"{h.get('archivo', '')}:{h.get('linea', 0)}"
        if clave in vistos:
            regla_existente = vistos[clave].get("regla_semgrep", "")
            regla_nueva = h.get("regla_semgrep", "")
            if regla_nueva not in regla_existente:
                vistos[clave]["regla_semgrep"] = f"{regla_existente} | {regla_nueva}"
            sev_actual = str(vistos[clave].get("severidad", "")).upper()
            sev_nueva = str(h.get("severidad", "")).upper()
            if "ERROR" in sev_nueva and "ERROR" not in sev_actual:
                vistos[clave]["severidad"] = h["severidad"]
        else:
            vistos[clave] = dict(h)
    return list(vistos.values())


def calcular_puntuacion(hallazgos: list) -> float:
    """
    Calcula una puntuación de seguridad (0-100) basada en los hallazgos SAST.
    Parte de 100 y descuenta puntos según la severidad de cada vulnerabilidad.
    """
    puntuacion = 100.0
    for h in hallazgos:
        sev = str(h.get("severidad", "INFO")).upper()
        if any(k in sev for k in ["ERROR", "ALTA", "ALTO", "HIGH", "CRIT"]):
            puntuacion -= 15
        elif any(k in sev for k in ["WARNING", "MEDIA", "MEDIO", "MEDIUM", "WARN"]):
            puntuacion -= 8
        else:
            puntuacion -= 3
    return max(0.0, round(puntuacion, 2))



@celery_app.task(bind=True, name="procesar_auditoria", max_retries=3)
def procesar_auditoria_task(
    self,
    audit_id,
    zip_path,
    work_dir,
    file_name,
    usuario_id,
    modelo_ia="llama3:8b",
    temperatura=0.0,
):
    logger.info(f"[{audit_id}] Iniciando auditoría para el archivo: {file_name}")
    db = SessionLocal()

    try:
        emitir_progreso(audit_id, "Descomprimiendo y analizando seguridad del ZIP...", 5)

        MAX_UNCOMPRESSED_SIZE = 400 * 1024 * 1024
        total_extracted_size = 0

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for zip_info in zip_ref.infolist():
                if zip_info.filename.count("/") > 10 or zip_info.filename.count("\\") > 10:
                    raise ValueError(f"Estructura demasiado profunda rechazada: {zip_info.filename}")

                if (zip_info.external_attr >> 16) & 0o120000 == 0o120000:
                    raise ValueError(f"Enlaces simbólicos bloqueados por seguridad: {zip_info.filename}")
                if zip_info.file_size > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError(f"Archivo sospechoso detectado (demasiado grande): {zip_info.filename}")

                total_extracted_size += zip_info.file_size
                if total_extracted_size > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError("Ataque de Zip Bomb detectado: El tamaño total supera el límite seguro.")

                target_path = os.path.abspath(os.path.join(work_dir, zip_info.filename))

                if not target_path.startswith(os.path.abspath(work_dir)):
                    raise ValueError(f"Ataque de Path Traversal bloqueado: {zip_info.filename}")

                zip_ref.extract(zip_info, work_dir)

        if os.path.exists(zip_path):
            os.remove(zip_path)

        logger.info(f"[{audit_id}] ZIP extraído con éxito. Iniciando escáner SAST.")
        emitir_progreso(audit_id, "Archivos extraídos de forma segura. Iniciando escáner...", 10)

        hallazgos = ejecutar_sast_profesional(work_dir)
        hallazgos = deduplicar_hallazgos(hallazgos)

        if not hallazgos:
            logger.info(f"[{audit_id}] No se encontraron vulnerabilidades. Código seguro.")
            emitir_progreso(audit_id, "No se encontraron vulnerabilidades. Código seguro.", 100)
            return

        logger.info(f"[{audit_id}] Se encontraron {len(hallazgos)} vulnerabilidades. Iniciando análisis IA.")

        for i, h in enumerate(hallazgos):
            progreso_actual = 10 + int((i / len(hallazgos)) * 55)
            emitir_progreso(
                audit_id,
                f"Agente IA analizando vulnerabilidad {i+1} de {len(hallazgos)}...",
                progreso_actual,
            )

            try:
                ruta_archivo = os.path.join(work_dir, h["archivo"])
                with open(ruta_archivo, "r", encoding="utf-8") as f:
                    h["codigo_completo"] = f.read()
            except Exception:
                h["codigo_completo"] = "Contenido no disponible"

            analisis = "Sin análisis"
            referencias = "Sin referencias"
            consulta_real = "Desconocida"

            try:
                respuesta = grafo_agentes.invoke(
                    {
                        "hallazgos_tecnicos": [h],
                        "tiempos": {},
                        "modelo_ia": modelo_ia,
                        "temperatura": float(temperatura),
                    }
                )
                analisis = respuesta.get("veredicto_final", "Sin análisis")
                referencias = respuesta.get("referencias_legales", "Sin referencias")
                consulta_real = respuesta.get("consulta_index", "Desconocida")
            except Exception as e:
                logger.warning(f"[{audit_id}] Error en IA al analizar hallazgo {i+1}: {str(e)}")
                analisis = f"Error en IA: {str(e)}"
                referencias = "Error al procesar referencias"
                consulta_real = "Error en consulta"

            nueva_vuln = Vulnerabilidad(
                auditoria_id=audit_id,
                nombre=h.get("vulnerabilidad", "Desconocida"),
                severidad=h.get("severidad", "INFO"),
                archivo_afectado=h.get("archivo", "Desconocido"),
                linea=h.get("linea", 0),
                codigo_afectado=h.get("codigo_afectado", ""),
                referencias_legales=referencias,
                analisis_legal=analisis,
                modelo_llm=modelo_ia,
                regla_semgrep=h.get("regla_semgrep", "Desconocida"),
                consulta_index=consulta_real,
            )
            db.add(nueva_vuln)

        # Calcular y persistir la puntuación global de la auditoría
        puntuacion_final = calcular_puntuacion(hallazgos)
        auditoria_db = db.query(Auditoria).filter(Auditoria.id == audit_id).first()
        if auditoria_db:
            auditoria_db.puntuacion = puntuacion_final
            logger.info(f"[{audit_id}] Puntuación calculada: {puntuacion_final}/100")

        db.commit()
        logger.info(f"[{audit_id}] Auditoría completada y guardada exitosamente.")
        emitir_progreso(audit_id, "Auditoría completada y guardada.", 100)

    except ValueError as ve:

        logger.error(f"[{audit_id}] Alerta de Seguridad: {str(ve)}")
        emitir_progreso(audit_id, f"Error de seguridad: {str(ve)}", -1)

    except Exception as e:

        logger.error(f"[{audit_id}] Error inesperado: {str(e)}", exc_info=True)

        try:

            tiempo_espera = 2**self.request.retries
            logger.warning(
                f"[{audit_id}] Reintentando tarea en {tiempo_espera}s (Intento {self.request.retries + 1}/3)..."
            )
            self.retry(exc=e, countdown=tiempo_espera)
        except self.MaxRetriesExceededError:
            logger.error(f"[{audit_id}] Se agotaron los 3 reintentos. Abortando auditoría.")
            emitir_progreso(audit_id, f"Error crítico tras 3 reintentos: {str(e)}", -1)

    finally:
        db.close()
        try:
            if os.path.exists(work_dir):
                shutil.rmtree(work_dir)
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except Exception as e:
            logger.error(f"[{audit_id}] Error limpiando archivos temporales: {e}")

