import os
import shutil
import zipfile
import json
import redis
from celery import Celery

from Src.database import SessionLocal
from Src.models import Vulnerabilidad, Auditoria
from Src.sast_scanner import ejecutar_sast_profesional
from Src.orquestador import app as grafo_agentes

# Conexiones
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
celery_app = Celery("auditor_tasks", broker=REDIS_URL, backend=REDIS_URL)
redis_client = redis.Redis.from_url(REDIS_URL)

def emitir_progreso(audit_id, mensaje, progreso):
    """Envía un evento en tiempo real a través de Redis"""
    evento = json.dumps({"mensaje": mensaje, "progreso": progreso})
    redis_client.publish(f"progreso_{audit_id}", evento)

@celery_app.task(name="procesar_auditoria")
def procesar_auditoria_task(audit_id, zip_path, work_dir, file_name, usuario_id):
    db = SessionLocal()
    try:
        emitir_progreso(audit_id, "Descomprimiendo y preparando entorno...", 5)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(work_dir)
            
        emitir_progreso(audit_id, "Ejecutando escáner SAST de código base...", 20)
        hallazgos = ejecutar_sast_profesional(work_dir)
        
        if not hallazgos:
            hallazgos = []
            
        emitir_progreso(audit_id, f"Se encontraron {len(hallazgos)} vulnerabilidades. Iniciando IA...", 40)
        
        for i, h in enumerate(hallazgos):
            # Calculamos el progreso proporcional
            progreso_actual = 40 + int(((i + 1) / len(hallazgos)) * 55) 
            emitir_progreso(audit_id, f"Agente IA analizando vulnerabilidad {i+1} de {len(hallazgos)}...", progreso_actual)
            
            # --- NUEVO: LEER EL ARCHIVO COMPLETO PARA LA IA ---
            try:
                ruta_archivo = os.path.join(work_dir, h['archivo'])
                with open(ruta_archivo, 'r', encoding='utf-8') as f:
                    h['codigo_completo'] = f.read()
            except Exception:
                h['codigo_completo'] = "Contenido no disponible"
            # --------------------------------------------------

            try:
                # LLAMADA A LA IA
                respuesta = grafo_agentes.invoke({"hallazgos_tecnicos": [h], "tiempos": {}})
                analisis = respuesta['veredicto_final']
            except Exception as e:
                analisis = f"Error en IA: {str(e)}"

            nueva_vuln = Vulnerabilidad(
                auditoria_id=audit_id,
                nombre=h['vulnerabilidad'],
                severidad=h['severidad'],
                archivo_afectado=h['archivo'],
                analisis_legal=analisis
            )
            db.add(nueva_vuln)
            
        db.commit()
        emitir_progreso(audit_id, "Auditoría completada y guardada.", 100)
        
    except Exception as e:
        emitir_progreso(audit_id, f"Error crítico: {str(e)}", -1)
    finally:
        db.close()
     
        try:
            if os.path.exists(work_dir): shutil.rmtree(work_dir)
            if os.path.exists(zip_path): os.remove(zip_path)
        except:
            pass