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





## Arquitectura RAG y Modelos de Inteligencia Artificial

Para garantizar que los análisis de vulnerabilidades estén alineados con el Esquema Nacional de Seguridad (ENS) y evitar "alucinaciones" (respuestas inventadas), esta plataforma implementa una arquitectura **RAG (Retrieval-Augmented Generation)**.

### 1. Modelo de Embeddings: `mxbai-embed-large`
Para la vectorización de los documentos legales (ENS) se utiliza el modelo **`mxbai-embed-large`** a través de Ollama. 
* **¿Por qué este modelo?** Es un modelo de estado del arte diseñado específicamente para tareas de recuperación de información (Retrieval) y búsqueda semántica, superando a otros modelos estándar en precisión al mapear consultas técnicas con textos legales.

### 2. Base de Datos Vectorial: FAISS
Los embeddings generados se almacenan y consultan utilizando **FAISS (Facebook AI Similarity Search)**. FAISS permite realizar búsquedas de similitud ultrarrápidas, recuperando los artículos exactos del ENS que aplican a la vulnerabilidad detectada en el código fuente.

### 3. Modelos LLM de Análisis Legal
El sistema permite al usuario elegir entre dos modelos de lenguaje locales (ejecutados vía Ollama) para realizar el razonamiento jurídico-técnico:
* **Llama 3.2 (3B)**: Optimizado para velocidad y entornos con recursos limitados.
* **Llama 3.1 (8B)**: Modelo experto que ofrece un razonamiento más profundo en auditorías críticas (requiere mayor capacidad de RAM).

### 4. Trazabilidad y Evidencia Legal
El sistema persiste en la base de datos la evidencia completa de cada hallazgo para su posterior auditoría humana:
* Regla exacta del motor SAST (Semgrep).
* Modelo LLM utilizado en la inferencia.
* Fragmentos del ENS recuperados por FAISS y utilizados como contexto estricto.