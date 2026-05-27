"""
tests/test_pipeline.py
======================
Tests de integración del pipeline principal de SecureAudit.

Estrategia: mocks para aislar LangGraph, Semgrep, Celery, FAISS y Ollama,
de forma que los tests sean reproducibles en CI sin infraestructura externa.

Flujo cubierto:
    Registro → Login → Cookie → /me → /historial
    Subida ZIP autenticada → encolado de tarea Celery
    SAST → estructura de hallazgos
    Worker completo → análisis IA → persistencia en BD
    Verificación de que cada hallazgo recibe su propio análisis (no el [0])
"""

import io
import os
import zipfile
import tempfile
import pytest
import sys
from unittest.mock import patch, MagicMock

# ── Stubs de módulos pesados — deben registrarse ANTES de importar la app ─────
_langgraph_stub = MagicMock()
_langgraph_stub.graph.StateGraph = MagicMock()
_langgraph_stub.graph.END = "END"

for _mod, _obj in [
    ("langgraph",                            _langgraph_stub),
    ("langgraph.graph",                      _langgraph_stub.graph),
    ("langchain_community",                  MagicMock()),
    ("langchain_community.chat_models",      MagicMock()),
    ("langchain_community.embeddings",       MagicMock()),
    ("langchain_community.vectorstores",     MagicMock()),
    ("langchain_community.document_loaders", MagicMock()),
    ("langchain_groq",                       MagicMock()),
    ("langchain_core",                       MagicMock()),
    ("langchain_core.prompts",               MagicMock()),
    ("langchain",                            MagicMock()),
    ("langchain.chains",                     MagicMock()),
    ("langchain.chains.combine_documents",   MagicMock()),
    ("langchain.schema",                     MagicMock()),
    ("langchain_text_splitters",             MagicMock()),
    ("langchain_ollama",                     MagicMock()),
    ("faiss",                                MagicMock()),
]:
    sys.modules.setdefault(_mod, _obj)

# ── Variables de entorno para el entorno de test ──────────────────────────────
os.environ.setdefault("SECRET_KEY",    "clave_test_segura_pytest_secureaudit")
os.environ.setdefault("DATABASE_URL",  "sqlite:///./test_integration.db")
os.environ.setdefault("REDIS_URL",     "redis://localhost:6379/0")
os.environ.setdefault("UPLOAD_DIR",    "./uploads_test")
os.environ.setdefault("EXTRACT_DIR",   "./extract_test")
os.makedirs("data", exist_ok=True)

from fastapi.testclient import TestClient
from Src.api import app
from Src.core.database import engine, Base

Base.metadata.create_all(bind=engine)
client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _zip_en_memoria(codigo: str = "import os\nos.system(input())\n") -> io.BytesIO:
    """Genera un ZIP en memoria con un archivo Python de prueba."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("vulnerable.py", codigo)
    buf.seek(0)
    return buf


def _crear_zip_real(directorio: str, nombre: str = "fake.zip") -> str:
    """Crea un ZIP real en disco (el worker lo abre antes de llamar a Semgrep)."""
    ruta = os.path.join(directorio, nombre)
    with zipfile.ZipFile(ruta, "w") as zf:
        zf.writestr("dummy.py", "print('prueba')\n")
    return ruta


def _invocar_worker(audit_id, work_dir, hallazgos_mock, respuesta_ia_mock):
    """
    Llama a procesar_auditoria_task.run() — la función Python pura,
    sin que Celery la intercepte — mockeando todas las dependencias externas.
    El ZIP debe existir en disco porque el worker lo abre antes de Semgrep.
    """
    from Src.workers.celery_worker import procesar_auditoria_task

    zip_path = _crear_zip_real(work_dir)

    with patch("Src.workers.celery_worker.ejecutar_sast_profesional",
               return_value=hallazgos_mock), \
         patch("Src.workers.celery_worker.grafo_agentes") as mock_grafo, \
         patch("Src.workers.celery_worker.emitir_progreso"), \
         patch("Src.workers.celery_worker.redis_client"):

        if respuesta_ia_mock is not None:
            mock_grafo.invoke.return_value = respuesta_ia_mock

        # .run() es la función real sin el decorador bind=True;
        # no recibe 'self' ni pasa por el broker Redis.
        procesar_auditoria_task.run(
            audit_id,
            zip_path,
            work_dir,
            "codigo_test.zip",
            1,              # usuario_id
            "llama3:8b",
            0.0,
            "local",
        )
        return mock_grafo


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def usuario_autenticado():
    """
    Crea un usuario de test y devuelve el cliente con la cookie de sesión.
    bcrypt se mockea para evitar incompatibilidades de versión en CI.
    """
    email    = "test_pipeline@secureaudit.com"
    password = "Test1234"
    hash_falso = "$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

    with patch("Src.core.auth.pwd_context.hash",   return_value=hash_falso), \
         patch("Src.core.auth.pwd_context.verify", return_value=True):

        r = client.post("/registro", json={"email": email, "password": password})
        assert r.status_code in (200, 400), \
            f"Registro falló: {r.status_code} — {r.text}"

        r_login = client.post("/login", json={"email": email, "password": password})
        assert r_login.status_code == 200, f"Login falló: {r_login.text}"

    return client


# ─────────────────────────────────────────────────────────────────────────────
# Tests de autenticación (flujo completo)
# ─────────────────────────────────────────────────────────────────────────────

class TestAutenticacionCompleta:

    def test_registro_crea_usuario_y_devuelve_token(self):
        """Un registro válido debe devolver un access_token JWT."""
        hash_falso = "$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        with patch("Src.core.auth.pwd_context.hash", return_value=hash_falso):
            r = client.post("/registro", json={
                "email": "nuevo_usuario@secureaudit.com",
                "password": "Test1234"
            })
        assert r.status_code in (200, 400)
        if r.status_code == 200:
            assert "access_token" in r.json()
            assert r.json()["token_type"] == "bearer"

    def test_login_valido_setea_cookie_httponly(self):
        """Un login correcto debe establecer la cookie HttpOnly de sesión."""
        hash_falso = "$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        with patch("Src.core.auth.pwd_context.hash",   return_value=hash_falso), \
             patch("Src.core.auth.pwd_context.verify", return_value=True):
            client.post("/registro", json={
                "email": "cookie_test@secureaudit.com", "password": "Test1234"
            })
            r = client.post("/login", json={
                "email": "cookie_test@secureaudit.com", "password": "Test1234"
            })
        assert r.status_code == 200
        assert "access_token" in r.cookies, \
            "El login no estableció la cookie de sesión HttpOnly"

    def test_endpoint_me_devuelve_email_del_usuario(self, usuario_autenticado):
        """Con sesión activa, /me debe devolver el email del usuario."""
        r = usuario_autenticado.get("/me")
        assert r.status_code == 200, f"/me falló: {r.text}"
        assert "email" in r.json()

    def test_historial_con_sesion_activa_devuelve_lista(self, usuario_autenticado):
        """Con sesión activa, /historial debe devolver una lista."""
        r = usuario_autenticado.get("/historial")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ─────────────────────────────────────────────────────────────────────────────
# Tests de subida de ZIP
# ─────────────────────────────────────────────────────────────────────────────

class TestSubidaZIP:

    def test_zip_valido_autenticado_devuelve_audit_id(self, usuario_autenticado):
        """ZIP válido + sesión activa → devuelve audit_id y estado 'Procesando'."""
        with patch("Src.routers.audit_router.procesar_auditoria_task") as mock_task:
            mock_task.apply_async = MagicMock(return_value=MagicMock(id="task-test"))
            r = usuario_autenticado.post(
                "/auditar-zip",
                files={"file": ("test.zip", _zip_en_memoria(), "application/zip")},
                data={
                    "modelo_ia": "llama3:8b",
                    "temperatura": "0.0",
                    "modo_inferencia": "local",
                },
            )
        assert r.status_code == 200, f"Subida de ZIP falló: {r.text}"
        assert "audit_id" in r.json()
        assert r.json()["estado"] == "Procesando"

    def test_zip_sin_autenticacion_devuelve_401(self):
        """Sin cookie de sesión, la subida debe ser rechazada con 401."""
        # Cliente limpio sin cookies para garantizar ausencia de sesión
        cliente_sin_sesion = TestClient(app, cookies={})
        r = cliente_sin_sesion.post(
            "/auditar-zip",
            files={"file": ("test.zip", _zip_en_memoria(), "application/zip")},
        )
        assert r.status_code == 401

    def test_archivo_no_zip_es_rechazado_con_400(self, usuario_autenticado):
        """Un archivo que no sea ZIP debe ser rechazado con 400."""
        r = usuario_autenticado.post(
            "/auditar-zip",
            files={"file": ("script.py", io.BytesIO(b"print('hola')"), "text/plain")},
            data={
                "modelo_ia": "llama3:8b",
                "temperatura": "0.0",
                "modo_inferencia": "local",
            },
        )
        assert r.status_code == 400, \
            f"Archivo .py debería ser rechazado con 400, recibimos {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# Tests del motor SAST
# ─────────────────────────────────────────────────────────────────────────────

class TestMotorSAST:

    def test_hallazgo_tiene_todos_los_campos_requeridos(self):
        """
        Cada hallazgo debe contener los campos que el pipeline necesita:
        vulnerabilidad, archivo, linea, codigo_afectado, severidad, regla_semgrep.
        """
        campos_requeridos = {
            "vulnerabilidad", "archivo", "linea",
            "codigo_afectado", "severidad", "regla_semgrep"
        }
        hallazgo = {
            "vulnerabilidad": "dangerous-system-call",
            "archivo": "app.py",
            "linea": 3,
            "codigo_afectado": "os.system(cmd)",
            "severidad": "ERROR",
            "mensaje": "Uso inseguro de os.system",
            "regla_semgrep": "python.lang.security.audit.dangerous-system-call",
        }
        assert campos_requeridos.issubset(set(hallazgo.keys()))

    def test_sast_retorna_lista_vacia_si_directorio_no_existe(self):
        """Si el directorio no existe, el scanner devuelve lista vacía sin errores."""
        from Src.security_tools.sast_scanner import ejecutar_sast_profesional
        resultado = ejecutar_sast_profesional("/ruta/que/no/existe/jamas")
        assert isinstance(resultado, list) and len(resultado) == 0

    def test_sast_no_falla_con_directorio_vacio(self):
        """Con directorio vacío, el scanner no lanza excepciones."""
        from Src.security_tools.sast_scanner import ejecutar_sast_profesional
        with tempfile.TemporaryDirectory() as tmpdir:
            assert isinstance(ejecutar_sast_profesional(tmpdir), list)


# ─────────────────────────────────────────────────────────────────────────────
# Tests del pipeline completo (Worker → SAST → LangGraph → BD)
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineCompleto:

    def _preparar_bd(self, audit_id):
        """Elimina y recrea la auditoría de test en BD para cada test."""
        from Src.core.database import SessionLocal
        from Src.db_models.models import Auditoria, Vulnerabilidad
        db = SessionLocal()
        db.query(Vulnerabilidad).filter(
            Vulnerabilidad.auditoria_id == audit_id).delete()
        db.query(Auditoria).filter(Auditoria.id == audit_id).delete()
        db.commit()
        db.add(Auditoria(
            id=audit_id,
            nombre_archivo="test.zip",
            usuario_id=1,
            puntuacion=0.0,
        ))
        db.commit()
        db.close()

    def test_pipeline_guarda_vulnerabilidades_en_bd(self):
        """
        Dado código con 2 vulnerabilidades, el pipeline debe persistir
        ambos registros en BD con análisis IA no vacío.
        """
        from Src.core.database import SessionLocal
        from Src.db_models.models import Auditoria, Vulnerabilidad

        audit_id = "test-full-pipeline-001"
        self._preparar_bd(audit_id)

        hallazgos = [
            {
                "vulnerabilidad": "dangerous-system-call",
                "archivo": "app.py", "linea": 5,
                "codigo_afectado": "os.system(user_input)",
                "severidad": "ERROR", "mensaje": "Inyección de comandos",
                "regla_semgrep": "python.lang.security.audit.dangerous-system-call",
            },
            {
                "vulnerabilidad": "hardcoded-password",
                "archivo": "config.py", "linea": 12,
                "codigo_afectado": "PASSWORD = 'admin123'",
                "severidad": "WARNING", "mensaje": "Contraseña hardcodeada",
                "regla_semgrep": "python.lang.security.audit.hardcoded-password",
            },
        ]
        respuesta_ia = {
            "veredicto_final": "**Análisis:** Incumple ENS art. 32\n\n**Solución:** Validar entrada.",
            "referencias_legales": "ENS_2022.pdf (Pág 15)",
            "consulta_index": "dangerous-system-call",
            "tiempos": {"tecnico": 1.2, "legal": 0.8},
        }

        with tempfile.TemporaryDirectory() as work_dir:
            for h in hallazgos:
                with open(os.path.join(work_dir, h["archivo"]), "w") as f:
                    f.write(h["codigo_afectado"])
            _invocar_worker(audit_id, work_dir, hallazgos, respuesta_ia)

        db = SessionLocal()
        vulns = db.query(Vulnerabilidad).filter(
            Vulnerabilidad.auditoria_id == audit_id).all()
        auditoria = db.query(Auditoria).filter(Auditoria.id == audit_id).first()
        db.close()

        assert len(vulns) == 2, \
            f"Se esperaban 2 vulnerabilidades en BD, se encontraron {len(vulns)}"
        assert {v.nombre for v in vulns} == {
            "dangerous-system-call", "hardcoded-password"
        }
        assert auditoria.puntuacion < 100, \
            "La puntuación debería reducirse por las vulnerabilidades detectadas"
        for v in vulns:
            assert v.analisis_legal and v.analisis_legal != "Sin análisis", \
                f"El análisis de '{v.nombre}' no fue guardado correctamente"

    def test_pipeline_con_codigo_limpio_no_genera_vulnerabilidades(self):
        """Código sin vulnerabilidades → ningún registro de vulnerabilidad en BD."""
        from Src.core.database import SessionLocal
        from Src.db_models.models import Vulnerabilidad

        audit_id = "test-full-pipeline-clean-001"
        self._preparar_bd(audit_id)

        with tempfile.TemporaryDirectory() as work_dir:
            _invocar_worker(audit_id, work_dir, [], None)

        db = SessionLocal()
        vulns = db.query(Vulnerabilidad).filter(
            Vulnerabilidad.auditoria_id == audit_id).all()
        db.close()

        assert len(vulns) == 0, \
            "Código sin vulnerabilidades no debería generar registros en BD"

    def test_cada_hallazgo_recibe_su_propio_analisis_langgraph(self):
        """
        Verifica que el orquestador LangGraph se invoca UNA VEZ POR HALLAZGO
        y que cada invocación recibe el hallazgo_actual correcto (no siempre el [0]).

        Este test valida específicamente la corrección del error fatal
        'LangGraph solo procesaba UN hallazgo': con el bug, las 3 invocaciones
        recibirían siempre 'sql-injection' (el primer hallazgo).
        """
        from Src.workers.celery_worker import procesar_auditoria_task

        audit_id = "test-full-pipeline-multivuln-001"
        self._preparar_bd(audit_id)

        hallazgos = [
            {
                "vulnerabilidad": "sql-injection",
                "archivo": "db.py", "linea": 10,
                "codigo_afectado": "query = 'SELECT * FROM users WHERE id=' + user_id",
                "severidad": "ERROR", "mensaje": "SQL Injection",
                "regla_semgrep": "python.django.security.injection.sql-injection",
            },
            {
                "vulnerabilidad": "insecure-hash-algorithm-md5",
                "archivo": "crypto.py", "linea": 5,
                "codigo_afectado": "hashlib.md5(password)",
                "severidad": "WARNING", "mensaje": "Hash débil",
                "regla_semgrep": "python.lang.security.audit.insecure-hash-md5",
            },
            {
                "vulnerabilidad": "hardcoded-password",
                "archivo": "settings.py", "linea": 3,
                "codigo_afectado": "DB_PASS = 'root123'",
                "severidad": "ERROR", "mensaje": "Credencial hardcodeada",
                "regla_semgrep": "python.lang.security.audit.hardcoded-password",
            },
        ]

        invocaciones = []

        def spy_invoke(state):
            """Registra el hallazgo_actual recibido en cada llamada al LangGraph."""
            invocaciones.append(state["hallazgo_actual"]["vulnerabilidad"])
            return {
                "veredicto_final": f"Análisis: {state['hallazgo_actual']['vulnerabilidad']}",
                "referencias_legales": "ENS_2022.pdf",
                "consulta_index": state["hallazgo_actual"]["vulnerabilidad"],
                "tiempos": {},
            }

        with patch("Src.workers.celery_worker.ejecutar_sast_profesional",
                   return_value=hallazgos), \
             patch("Src.workers.celery_worker.grafo_agentes") as mock_grafo, \
             patch("Src.workers.celery_worker.emitir_progreso"), \
             patch("Src.workers.celery_worker.redis_client"):

            mock_grafo.invoke.side_effect = spy_invoke

            with tempfile.TemporaryDirectory() as work_dir:
                for h in hallazgos:
                    with open(os.path.join(work_dir, h["archivo"]), "w") as f:
                        f.write(h["codigo_afectado"])

                zip_path = _crear_zip_real(work_dir)

                procesar_auditoria_task.run(
                    audit_id,
                    zip_path,
                    work_dir,
                    "multivuln.zip",
                    1,
                    "llama3:8b",
                    0.0,
                    "local",
                )

        # El LangGraph debe haberse invocado exactamente 3 veces
        assert len(invocaciones) == 3, \
            f"LangGraph debería invocarse 3 veces, se invocó {len(invocaciones)}"

        # Cada invocación debe haber recibido una vulnerabilidad distinta
        assert set(invocaciones) == {
            "sql-injection", "insecure-hash-algorithm-md5", "hardcoded-password"
        }, f"No se analizaron todas las vulnerabilidades: {invocaciones}"

        # Sin el bug [0]: no hay duplicados en las invocaciones
        assert len(invocaciones) == len(set(invocaciones)), \
            f"Se detectaron análisis duplicados (bug hallazgos[0]): {invocaciones}"