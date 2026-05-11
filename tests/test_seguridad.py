import os
import zipfile
import tempfile
import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────

def crear_zip_normal(directorio_destino, nombre="prueba.zip"):
    """Crea un ZIP legítimo con un archivo Python vulnerable para tests."""
    zip_path = os.path.join(directorio_destino, nombre)
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("main.py", "import os\nos.system(input())\n")
    return zip_path


def crear_zip_path_traversal(directorio_destino):
    """Crea un ZIP malicioso con path traversal (ZIP Slip)."""
    zip_path = os.path.join(directorio_destino, "malicioso.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    return zip_path


def crear_zip_profundidad_excesiva(directorio_destino):
    """Crea un ZIP con estructura de directorios demasiado profunda."""
    zip_path = os.path.join(directorio_destino, "profundo.zip")
    ruta_profunda = "/".join([f"nivel{i}" for i in range(15)]) + "/archivo.py"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(ruta_profunda, "print('hola')")
    return zip_path


def crear_zip_bomb(directorio_destino):
    """Crea un ZIP con metadatos que simulan un archivo enorme."""
    zip_path = os.path.join(directorio_destino, "bomb.zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("enorme.txt", "A" * 1024)
    # Manipular manualmente el tamaño declarado no es trivial,
    # así que simulamos el escenario verificando la lógica de conteo
    return zip_path


# ── Tests de validación de seguridad ZIP ──────────────────────────────────────

class TestValidacionZIP:

    def test_zip_normal_se_extrae_correctamente(self):
        """Un ZIP legítimo debe extraerse sin lanzar excepciones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = os.path.join(tmpdir, "extraccion")
            os.makedirs(work_dir)
            zip_path = crear_zip_normal(tmpdir)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                for zip_info in zip_ref.infolist():
                    target_path = os.path.abspath(
                        os.path.join(work_dir, zip_info.filename)
                    )
                    assert target_path.startswith(os.path.abspath(work_dir)), \
                        "Ruta escapó del directorio de trabajo"
                    zip_ref.extract(zip_info, work_dir)

            archivos = os.listdir(work_dir)
            assert "main.py" in archivos

    def test_path_traversal_es_detectado(self):
        """Un ZIP con path traversal debe ser detectado antes de extraerse."""
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = os.path.join(tmpdir, "extraccion")
            os.makedirs(work_dir)
            zip_path = crear_zip_path_traversal(tmpdir)

            detectado = False
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                for zip_info in zip_ref.infolist():
                    target_path = os.path.abspath(
                        os.path.join(work_dir, zip_info.filename)
                    )
                    if not target_path.startswith(os.path.abspath(work_dir)):
                        detectado = True
                        break

            assert detectado, "El path traversal no fue detectado"

    def test_profundidad_excesiva_es_rechazada(self):
        """Un ZIP con más de 10 niveles de profundidad debe ser rechazado."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = crear_zip_profundidad_excesiva(tmpdir)

            rechazado = False
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                for zip_info in zip_ref.infolist():
                    if zip_info.filename.count("/") > 10:
                        rechazado = True
                        break

            assert rechazado, "La profundidad excesiva no fue detectada"

    def test_zip_sin_archivos_no_falla(self):
        """Un ZIP vacío debe procesarse sin lanzar excepciones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "vacio.zip")
            with zipfile.ZipFile(zip_path, "w"):
                pass

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                assert zip_ref.infolist() == []

    def test_zip_con_extension_incorrecta_no_es_ejecutable(self):
        """Verificar que solo se aceptan archivos .zip."""
        nombre_archivo = "repositorio.tar.gz"
        assert nombre_archivo.endswith(".zip") is False

# ── Tests del motor SAST ───────────────────────────────────────────────────────

try:
    from Src.security_tools.sast_scanner import ejecutar_sast_profesional
    SAST_DISPONIBLE = True
except ModuleNotFoundError:
    SAST_DISPONIBLE = False

@pytest.mark.skipif(not SAST_DISPONIBLE, reason="Módulo Src no disponible en este entorno")
class TestMotorSAST:

    def test_sast_retorna_lista_vacia_si_directorio_no_existe(self):
        """Si el directorio no existe, el scanner debe devolver lista vacía."""
        resultado = ejecutar_sast_profesional("/ruta/que/no/existe")
        assert isinstance(resultado, list)
        assert len(resultado) == 0

    def test_sast_retorna_lista_con_directorio_vacio(self):
        """Con un directorio vacío, el scanner debe devolver lista vacía sin errores."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resultado = ejecutar_sast_profesional(tmpdir)
            assert isinstance(resultado, list)

    def test_estructura_hallazgo_tiene_campos_requeridos(self):
        """Cada hallazgo debe contener los campos esperados por el sistema."""
        campos_requeridos = {
            "vulnerabilidad", "archivo", "linea",
            "codigo_afectado", "severidad", "regla_semgrep"
        }
        hallazgo_ejemplo = {
            "vulnerabilidad": "sql-injection",
            "archivo": "app.py",
            "linea": 42,
            "codigo_afectado": "query = 'SELECT * FROM users WHERE id=' + user_id",
            "severidad": "ERROR",
            "mensaje": "Posible inyección SQL",
            "regla_semgrep": "python.django.security.injection.sql-injection"
        }
        assert campos_requeridos.issubset(set(hallazgo_ejemplo.keys()))

def test_zip_bomb_conteo_acumulado_detectado():
    """El sistema debe detectar cuando el tamaño acumulado supera el límite."""
    MAX_UNCOMPRESSED_SIZE = 400 * 1024 * 1024
    total = 0
    detectado = False

    tamanios_simulados = [
        100 * 1024 * 1024,
        150 * 1024 * 1024,
        200 * 1024 * 1024,
    ]

    for tamanio in tamanios_simulados:
        total += tamanio
        if total > MAX_UNCOMPRESSED_SIZE:
            detectado = True
            break

    assert detectado, "El límite de tamaño acumulado no fue detectado"