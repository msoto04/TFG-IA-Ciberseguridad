import os
import uuid
import logging
import aiofiles
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from Src.core.database import SessionLocal
from Src.db_models.models import Auditoria, Usuario
from Src.routers.auth_router import obtener_usuario_actual
from Src.workers.celery_worker import procesar_auditoria_task


logger = logging.getLogger(__name__)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
EXTRACT_DIR = os.getenv("EXTRACT_DIR", "./extracted")
MAX_ZIP_SIZE = 100 * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

router = APIRouter(tags=["Auditoría"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/auditar-zip")
async def auditar_zip(
    file: UploadFile = File(...),
    current_user: Usuario = Depends(obtener_usuario_actual),
    db: Session = Depends(get_db),
):

    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400, detail="Rechazado: El archivo debe tener extensión .zip"
        )

    if file.content_type not in [
        "application/zip",
        "application/x-zip-compressed",
        "multipart/x-zip",
    ]:
        raise HTTPException(
            status_code=400,
            detail="Rechazado: El contenido real del archivo no es un ZIP válido",
        )

    audit_id = str(uuid.uuid4())
    zip_path = os.path.join(UPLOAD_DIR, f"{audit_id}.zip")
    work_dir = os.path.join(EXTRACT_DIR, audit_id)

    tamanio_descargado = 0
    CHUNK_SIZE = 1024 * 1024

    try:
        async with aiofiles.open(zip_path, "wb") as out_file:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                tamanio_descargado += len(chunk)

                if tamanio_descargado > MAX_ZIP_SIZE:
                    os.remove(zip_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Rechazado: El archivo supera el límite de {MAX_ZIP_SIZE // (1024*1024)}MB permitidos.",
                    )

                await out_file.write(chunk)
    except HTTPException:
        raise
    except Exception as e:

        if os.path.exists(zip_path):
            os.remove(zip_path)
        logger.error(f"Error procesando la subida del ZIP: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Error interno al procesar el archivo."
        )

    nueva_auditoria = Auditoria(
        id=audit_id,
        nombre_archivo=file.filename,
        usuario_id=current_user.id,
        puntuacion=0.0,
    )
    db.add(nueva_auditoria)
    db.commit()

    procesar_auditoria_task.apply_async(
        args=[audit_id, zip_path, work_dir, file.filename, current_user.id], countdown=2
    )

    return {"estado": "Procesando", "audit_id": audit_id}


@router.get("/auditoria/{audit_id}")
def obtener_resultado_auditoria(
    audit_id: str,
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(obtener_usuario_actual),
):
    auditoria = db.query(Auditoria).filter(Auditoria.id == audit_id).first()
    if not auditoria:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada")

    if auditoria.usuario_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado: No tienes permiso para ver esta auditoría",
        )

    resultados = []
    for v in auditoria.vulnerabilidades:
        resultados.append(
            {
                "vulnerabilidad": v.nombre,
                "archivo": v.archivo_afectado,
                "severidad": v.severidad,
                "analisis_legal": v.analisis_legal,
                "linea": v.linea,
                "codigo_afectado": v.codigo_afectado,
                "referencias_legales": v.referencias_legales,
                "modelo_llm": v.modelo_llm,
                "regla_semgrep": v.regla_semgrep,
            }
        )

    return {
        "estado": "Finalizado",
        "total_vulnerabilidades": len(resultados),
        "resultados": resultados,
    }


@router.get("/historial")
def obtener_historial(
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(obtener_usuario_actual),
):

    auditorias = (
        db.query(Auditoria)
        .filter(Auditoria.usuario_id == current_user.id)
        .order_by(Auditoria.fecha.desc())
        .all()
    )

    resultados = []
    for a in auditorias:

        criticas = 0
        medias = 0
        bajas = 0

        for v in a.vulnerabilidades:
            sev = str(v.severidad).upper()
            if "CRIT" in sev or "HIGH" in sev or "ALTA" in sev or "ERROR" in sev:
                criticas += 1
            elif "MED" in sev or "WARN" in sev:
                medias += 1
            else:
                bajas += 1

        resultados.append(
            {
                "id": a.id,
                "nombre_archivo": a.nombre_archivo,
                "fecha": a.fecha.strftime("%Y-%m-%d %H:%M:%S"),
                "total_vulnerabilidades": criticas + medias + bajas,
                "criticas": criticas,
                "medias": medias,
                "bajas": bajas,
            }
        )
    return resultados
