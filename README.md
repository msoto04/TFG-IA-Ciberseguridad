Este proyecto consiste en una plataforma de auditoría de ciberseguridad que combina análisis estático de código (SAST) con un sistema RAG (Generación Aumentada por Recuperación) para consultar la normativa de seguridad.



Todo el procesamiento de Inteligencia Artificial se realiza de forma local utilizando modelos de la familia Llama, garantizando que el código y los datos auditados no salgan del equipo.



\## Requisitos Previos



Para ejecutar este proyecto en tu máquina, necesitas tener instalados:

1\. Docker Desktop (para levantar el backend, Redis, los workers y la base de datos vectorial de forma aislada).

2\. Ollama (para ejecutar los modelos de IA localmente).



\## Instrucciones de Instalación y Ejecución



\### Paso 1: Preparar la Inteligencia Artificial (Ollama)

El contenedor de Docker se conectará al Ollama de tu máquina anfitriona. 

1\. Abre Ollama en tu ordenador.

2\. Abre una terminal y descarga los modelos necesarios ejecutando:

&nbsp;  `ollama run llama3.1:8b` (Modelo principal)

&nbsp;  `ollama run nomic-embed-text` (Modelo de embeddings para el RAG)



\### Paso 2: Levantar la Aplicación

Abre una terminal en la raíz de este proyecto (donde está el archivo docker-compose.yml) y ejecuta este único comando para construir y arrancar todos los servicios a la vez:



&nbsp;  `docker-compose up --build`



\### Paso 3: Acceso

Abre tu navegador web y ve a la ruta donde esta el archivo `index.html` (Frontend/index.html) para ver la interfaz, o ve directamente a la API en `http://localhost:8000`.