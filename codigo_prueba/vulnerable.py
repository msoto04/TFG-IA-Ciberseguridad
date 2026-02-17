import os
import pickle
import subprocess
import base64
from flask import Flask, request, send_file

app = Flask(__name__)

# FALLO 1: Clave criptográfica débil y hardcodeada
SECRET_KEY = "12345" 

@app.route('/admin/dashboard')
def admin_dashboard():
    # FALLO 2: Inyección de Comandos (RCE) - ¡Gravísimo!
    # Permite al usuario ejecutar comandos de terminal directamente
    ip = request.args.get('ip')
    if ip:
        # Si el usuario pone "; rm -rf /", borra el servidor
        comando = f"ping -c 1 {ip}"
        return subprocess.check_output(comando, shell=True) 
    return "Indica una IP"

@app.route('/descargar')
def descargar_factura():
    filename = request.args.get('archivo')
    
    # FALLO 3: Path Traversal (LFI)
    # El usuario puede pedir "../../../etc/passwd" y robar archivos del sistema
    ruta_completa = os.path.join("/var/www/uploads", filename)
    
    if os.path.exists(ruta_completa):
        return send_file(ruta_completa)
    return "Archivo no encontrado"

@app.route('/login_token')
def login_token():
    token = request.args.get('token')
    
    # FALLO 4: Deserialización Insegura (Pickle)
    # Esto permite ejecutar código arbitrario al decodificar el objeto
    try:
        data = base64.b64decode(token)
        obj = pickle.loads(data) # <--- NUNCA usar pickle con datos externos
        return f"Bienvenido {obj['user']}"
    except:
        return "Error de token"

@app.route('/debug')
def debug():
    # FALLO 5: Debug activado en producción
    # Muestra errores detallados y código fuente al atacante
    app.run(debug=True) 

if __name__ == '__main__':
    app.run(host='0.0.0.0')