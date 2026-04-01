from fastapi.testclient import TestClient
from Src.api import app


client = TestClient(app)


def test_api_arranca_y_documentacion_responde():
    """
    Verifica que el núcleo de la API levanta sin errores fatales
    y que la ruta automática de Swagger (/docs) devuelve un 200 OK.
    """
    response = client.get("/docs")
    assert (
        response.status_code == 200
    ), f"Error fatal: La API no pudo arrancar. Código: {response.status_code}"
