import hashlib

class PasswordManager:
    # FALLO 2: Clave secreta escrita a fuego en el código (Hardcoded Secret)
    SECRET_KEY = "admin12345"

    @staticmethod
    def hashear_password(password):
        # FALLO 3: Algoritmo de hash obsoleto e inseguro (MD5)
        # El ENS prohíbe algoritmos rotos como MD5 o SHA1
        return hashlib.md5(password.encode()).hexdigest()

    def verificar_acceso(self, input_password):
        if input_password == self.SECRET_KEY:
            return True
        return False