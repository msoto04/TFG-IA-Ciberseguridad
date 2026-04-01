import requests


def test_ollama():
    url = "http://localhost:11434/api/generate"
    data = {"model": "deepseek-r1:8b", "prompt": "Responde solo: OK", "stream": False}

    print("Conectando con Ollama... (esto puede tardar si el modelo se está cargando)")
    try:

        response = requests.post(url, json=data, timeout=60)
        response.raise_for_status()
        print("Respuesta recibida:", response.json()["response"])
    except requests.exceptions.Timeout:
        print("ERROR: El modelo tardó demasiado en responder. ¿Tienes suficiente RAM?")
    except requests.exceptions.ConnectionError:
        print(
            "ERROR: No se pudo conectar. ¿Está el icono de la ovejita de Ollama abierto?"
        )
    except Exception as e:
        print(f"ERROR inesperado: {e}")


if __name__ == "__main__":
    test_ollama()
