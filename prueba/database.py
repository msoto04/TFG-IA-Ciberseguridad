import sqlite3

class DBHandler:
    def __init__(self, db_name="banco.db"):
        self.connection = sqlite3.connect(db_name)

    def ejecutar_consulta_peligrosa(self, user_input):
        cursor = self.connection.cursor()
        # FALLO 1: Inyección SQL (Concatenación directa de strings)
        # Semgrep debe detectar esto aunque esté dentro de una clase.
        query = "SELECT * FROM cuentas WHERE id_usuario = '" + user_input + "'"
        print(f"[DEBUG] Ejecutando: {query}")
        cursor.execute(query)
        return cursor.fetchall()

    def cerrar(self):
        self.connection.close()