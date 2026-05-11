from fastapi.testclient import TestClient
from Src.api import app

client = TestClient(app)


def test_api_arranca_y_documentacion_responde():
    """
    Verifica que el núcleo de la API levanta sin errores fatales
    y que la ruta automática de Swagger (/docs) devuelve un 200 OK.
    """
    response = client.get("/docs")
    assert response.status_code == 200, \
        f"Error fatal: La API no pudo arrancar. Código: {response.status_code}"


def test_endpoint_historial_sin_token_devuelve_401():
    """Un endpoint protegido sin token JWT debe devolver 401."""
    response = client.get("/historial")
    assert response.status_code == 401, \
        f"El endpoint /historial no está protegido. Código: {response.status_code}"


def test_endpoint_me_sin_token_devuelve_401():
    """El endpoint /me sin autenticación debe devolver 401."""
    response = client.get("/me")
    assert response.status_code == 401, \
        f"El endpoint /me no está protegido. Código: {response.status_code}"


def test_login_con_credenciales_invalidas_devuelve_401():
    """Login con credenciales incorrectas debe devolver 401."""
    response = client.post("/login", json={
        "email": "noexiste@test.com",
        "password": "contraseña_incorrecta"
    })
    assert response.status_code == 401, \
        f"El login no rechazó credenciales inválidas. Código: {response.status_code}"


def test_registro_con_password_corta_devuelve_422():
    """Registro con contraseña menor de 8 caracteres debe devolver 422."""
    response = client.post("/registro", json={
        "email": "test@test.com",
        "password": "123"
    })
    assert response.status_code == 422, \
        f"La validación de contraseña no funcionó. Código: {response.status_code}"


def test_registro_con_email_invalido_devuelve_422():
    """Registro con email mal formado debe devolver 422."""
    response = client.post("/registro", json={
        "email": "esto_no_es_un_email",
        "password": "password_valida_123"
    })
    assert response.status_code == 422, \
        f"La validación de email no funcionó. Código: {response.status_code}"


def test_subir_zip_sin_autenticacion_devuelve_401():
    """Subir un ZIP sin estar autenticado debe devolver 401."""
    response = client.post("/auditar-zip")
    assert response.status_code == 401, \
        f"El endpoint /auditar-zip no está protegido. Código: {response.status_code}"