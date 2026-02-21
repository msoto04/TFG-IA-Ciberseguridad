from flask import Flask, request
from database import DBHandler
from security import PasswordManager

app = Flask(__name__)
db = DBHandler()
auth = PasswordManager()

@app.route('/transferir')
def transferir():
    # FALLO 4: Uso de eval() - Esto es gravísimo (RCE)
    # Permite al usuario ejecutar código Python enviando una operación matemática
    cantidad = request.args.get('cantidad')
    monto_final = eval(cantidad) 
    return f"Transfiriendo {monto_final} euros"

@app.route('/consultar')
def consultar():
    user_id = request.args.get('id')
    # Llamada a la clase Database (de otro archivo)
    datos = db.ejecutar_consulta_peligrosa(user_id)
    return str(datos)

if __name__ == '__main__':
    # FALLO 5: Debug activado en producción
    app.run(debug=True, port=5000)