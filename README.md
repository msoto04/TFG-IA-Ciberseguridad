
# SECUREAUDIT ENS | Plataforma de Auditoría de Ciberseguridad AI

Esta plataforma combina el análisis estático de código (**SAST**) con un sistema de Inteligencia Artificial Soberana (**RAG**) para auditar software bajo el marco del **Esquema Nacional de Seguridad (ENS)**.

Todo el procesamiento se realiza en infraestructura propia. El motor de inferencia (Ollama) se ejecuta en la máquina anfitriona; el resto de servicios operan completamente dentro de contenedores Docker aislados.

---

## Instalación y Puesta en Marcha

Gracias a la arquitectura de contenedores, la plataforma se despliega con una intervención mínima.

### 1. Requisitos Previos
* **Docker Desktop** (con Docker Compose).
* **Ollama** instalado y ejecutándose en la máquina anfitriona.

### 2. Preparar los Modelos de IA (Ollama)
Antes de arrancar la aplicación, asegúrate de tener descargados los modelos necesarios ejecutando estos comandos en tu terminal:

```bash
ollama run deepseek-r1:8b      # Modelo de razonamiento experto
ollama run mxbai-embed-large   # Modelo de embeddings para normativa ENS
```

#### Alternativamente, para usar el modo API (Groq):
1. Obtén una clave en https://console.groq.com/keys
2. Añade GROQ_API_KEY=tu_clave en el archivo .env
3. Establece MODO_INFERENCIA=api en el archivo .env
En este modo no se envía código fuente, solo metadatos de la vulnerabilidad.

### 3. Configuración del Entorno
1. Copia el archivo de ejemplo: `cp .env.example .env`
2. *(Opcional)* Revisa los valores en `.env`, aunque los valores por defecto están optimizados para el entorno Docker.

### 4. Despliegue y Ejecución
Desde la raíz del proyecto, ejecuta el siguiente comando para construir y levantar todos los servicios:

```bash
docker-compose up --build
```

> [!IMPORTANT]
> **NOTA CRÍTICA SOBRE LA PRIMERA EJECUCIÓN:**
> La primera vez que inicies el sistema, el contenedor detectará que la base de datos de normativa ENS no existe. **Debes observar la terminal (CMD/Logs).** > 
> Verás mensajes indicando: `Iniciando ingesta de vectores automática...`. **Este proceso puede tardar varios minutos** dependiendo de la potencia de tu procesador y RAM, ya que la IA está leyendo y procesando todos los documentos legales del ENS. 
> 
> **Por favor, espera hasta que la terminal deje de mostrar procesos de lectura antes de intentar realizar tu primera auditoría.**

## Acceso a la Plataforma

Una vez que los servicios estén listos y la ingesta haya finalizado, accede a:

* **Panel de Usuario (Frontend):** [http://localhost:3000](http://localhost:3000)
* **Documentación de API (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Arquitectura RAG y Motor de IA

Para evitar "alucinaciones" y garantizar el cumplimiento normativo, el sistema implementa una arquitectura **Retrieval-Augmented Generation**:

* **Modelo de Embeddings (`mxbai-embed-large`):** Utilizado para transformar la normativa técnica del ENS en vectores matemáticos de alta precisión.
* **Base de Datos Vectorial (FAISS):** Almacena el conocimiento legal de la aplicación, permitiendo búsquedas semánticas ultrarrápidas.
* **Orquestador LangGraph:** Coordina el flujo entre los hallazgos técnicos (Semgrep) y la validación legal (Llama 3.1/3.2), asegurando que cada vulnerabilidad esté vinculada a un artículo específico del ENS.

## Características de Seguridad

* **Análisis SAST Profesional:** Integración con reglas personalizadas de Semgrep para la detección profunda de vulnerabilidades.
* **Privacidad Configurable:** El sistema ofrece dos modos de inferencia. En modo local, ningún dato sale de tu infraestructura. En modo API, únicamente se envían metadatos mínimos (tipo de vulnerabilidad, archivo y línea), nunca el código fuente.
* **Trazabilidad y Evidencia:** Cada informe generado incluye el fragmento exacto de la normativa ENS recuperada por la IA como evidencia legal.