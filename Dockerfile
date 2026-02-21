# Usamos una imagen base de Python ligera (Linux)
FROM python:3.10-slim

# 1. Instalamos dependencias del sistema necesarias para compilar
# (git y curl son necesarios para descargar cosas, build-essential para librerías C++)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalamos Semgrep directamente en el sistema
RUN python3 -m pip install semgrep

# 3. Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# 4. Copiamos los archivos de requerimientos primero (para aprovechar caché)
# Crea un archivo requirements.txt si no lo tienes, ahora te digo cómo.
COPY requirements.txt .

# 5. Instalamos las librerías de Python
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copiamos TODO el código de tu proyecto al contenedor
COPY . .

# 7. Variable de entorno para que Python no guarde caché (__pycache__)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# CREAMOS DIRECTORIOS NECESARIOS
RUN mkdir -p /app/auditoria /app/resultados

# ABRIMOS EL PUERTO 8000 (La ventanilla de atención al cliente)
EXPOSE 8000

# COMANDO DE ARRANQUE:
# Lanzamos Uvicorn (el servidor) apuntando al archivo api.py
CMD ["uvicorn", "Src.api:app", "--host", "0.0.0.0", "--port", "8000"]

COPY ingesta_vectores.py /app/ingesta_vectores.py