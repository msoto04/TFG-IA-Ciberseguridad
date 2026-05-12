import pytest
import requests


@pytest.mark.skip(
    reason="Test de integración manual — requiere Ollama activo en localhost:11434. "
           "Ejecutar manualmente con: pytest Src/test_ia.py -v -k test_ollama --no-header -s"
)
def test_ollama_responde_correctamente():
    """
    Verifica que el motor de inferencia local Ollama está activo
    y responde correctamente a una petición de generación de texto.
    Requiere que Ollama esté ejecutándose en el host anfitrión (puerto 11434).
    """
    url = "http://localhost:11434/api/generate"
    data = {
        "model": "llama3.2:3b",
        "prompt": "Responde solo con la palabra: OK",
        "stream": False
    }

    try:
        response = requests.post(url, json=data, timeout=60)
        response.raise_for_status()
        respuesta = response.json().get("response", "")
        assert respuesta, "Ollama respondió pero la respuesta está vacía"
        assert len(respuesta) > 0, "La respuesta del modelo no contiene texto"
    except requests.exceptions.Timeout:
        pytest.fail("Timeout: Ollama tardó más de 60 segundos. ¿Tiene suficiente RAM?")
    except requests.exceptions.ConnectionError:
        pytest.fail("ConnectionError: No se pudo conectar a Ollama. ¿Está el servicio activo?")