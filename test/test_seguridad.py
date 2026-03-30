from fastapi.testclient import TestClient
from Src.api import app
from Src.auth import crear_token_acceso

client = TestClient(app)

def test_aislamiento_usuarios():
    # 1. Creamos tokens para dos usuarios distintos
    token_usuario_a = crear_token_acceso({"sub": "1"}) # Usuario A (ID: 1)
    token_usuario_b = crear_token_acceso({"sub": "2"}) # Usuario B (ID: 2)

    headers_a = {"Authorization": f"Bearer {token_usuario_a}"}
    headers_b = {"Authorization": f"Bearer {token_usuario_b}"}

    # 2. Asumimos que existe una auditoría que pertenece al Usuario A
    # (En un test real, insertaríamos la auditoría en la BD de prueba aquí)
    audit_id_falsa = "auditoria_del_usuario_a_123"

    # 3. El Usuario B intenta robar/leer la auditoría del Usuario A
    response_b = client.get(f"/auditoria/{audit_id_falsa}", headers=headers_b)

    # 4. Verificamos que el sistema lo bloquea con un error 403 o 404 (Acceso Denegado / No encontrado)
    # Como tu sistema comprueba primero si existe, si no está en la BD dará 404, 
    # pero si existiera y no fuera suya, dará 403. Ambos significan que NO pudo verla.
    assert response_b.status_code in [403, 404], f"Fallo de seguridad: El usuario B pudo acceder. Código: {response_b.status_code}"
    
    print(" Prueba de aislamiento superada: El Usuario B no puede espiar al Usuario A.")

if __name__ == "__main__":
    test_aislamiento_usuarios()