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
        emitir_progreso(audit_id, "Descomprimiendo y analizando seguridad del ZIP...", 5)
        
     
        MAX_UNCOMPRESSED_SIZE = 400 * 1024 * 1024 
        total_extracted_size = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for zip_info in zip_ref.infolist():
                if zip_info.filename.count('/') > 10 or zip_info.filename.count('\\') > 10:
                    raise Exception(f"Estructura demasiado profunda rechazada: {zip_info.filename}")
                
                if (zip_info.external_attr >> 16) & 0o120000 == 0o120000:
                    raise Exception(f"Enlaces simbólicos bloqueados por seguridad: {zip_info.filename}")
                if zip_info.file_size > MAX_UNCOMPRESSED_SIZE:
                    raise Exception(f"Archivo sospechoso detectado (demasiado grande): {zip_info.filename}")
                
                total_extracted_size += zip_info.file_size
                if total_extracted_size > MAX_UNCOMPRESSED_SIZE:
                    raise Exception("Ataque de Zip Bomb detectado: El tamaño total supera el límite seguro.")

                target_path = os.path.abspath(os.path.join(work_dir, zip_info.filename))
                
                if not target_path.startswith(os.path.abspath(work_dir)):
                    raise Exception(f"Ataque de Path Traversal bloqueado: {zip_info.filename}")

                zip_ref.extract(zip_info, work_dir)
        
        if os.path.exists(zip_path):
            os.remove(zip_path)
            
        emitir_progreso(audit_id, "Archivos extraídos de forma segura. Iniciando escáner...", 10)
            
     
        hallazgos = ejecutar_sast_profesional(work_dir)
        
        if not hallazgos:
            emitir_progreso(audit_id, "No se encontraron vulnerabilidades. Código seguro.", 100)
            return

     
        for i, h in enumerate(hallazgos):
            progreso_actual = 10 + int((i / len(hallazgos)) * 55) 
            emitir_progreso(audit_id, f"Agente IA analizando vulnerabilidad {i+1} de {len(hallazgos)}...", progreso_actual)
            
            try:
                ruta_archivo = os.path.join(work_dir, h['archivo'])
                with open(ruta_archivo, 'r', encoding='utf-8') as f:
                    h['codigo_completo'] = f.read()
            except Exception:
                h['codigo_completo'] = "Contenido no disponible"
         
            try:
             
                respuesta = grafo_agentes.invoke({"hallazgos_tecnicos": [h], "tiempos": {}})
                analisis = respuesta.get('veredicto_final', 'Sin análisis')
                referencias = respuesta.get('referencias_legales', 'Sin referencias')
            except Exception as e:
                analisis = f"Error en IA: {str(e)}"
                referencias = "Error al procesar referencias"

    
            nueva_vuln = Vulnerabilidad(
                auditoria_id=audit_id,
                nombre=h.get('vulnerabilidad', 'Desconocida'),
                severidad=h.get('severidad', 'INFO'),
                archivo_afectado=h.get('archivo', 'Desconocido'),
                linea=h.get('linea', 0),                            
                codigo_afectado=h.get('codigo_afectado', ''),      
                referencias_legales=referencias,                   
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