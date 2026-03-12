import sqlite3



# FALLO 1: Contraseña a fuego (Hardcoded secret)

ADMIN_PASSWORD = "Password_Super_Segura_1234"



def login(user_input):

    conn = sqlite3.connect('users.db')

    cursor = conn.cursor()

   

    # FALLO 2: Inyección SQL (No usa parámetros)

    query = "SELECT * FROM users WHERE username = '" + user_input + "'"

    cursor.execute(query)

    return cursor.fetchone()



print("Iniciando sistema...")



# Otro fallo: Uso de MD5 (algoritmo débil)

import hashlib

hash = hashlib.md5("secret".encode()).hexdigest()