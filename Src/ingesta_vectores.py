import os
import sys
from langchain_community.vectorstores import FAISS

from langchain_community.document_loaders import PyMuPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter


from langchain_community.embeddings import OllamaEmbeddings


def crear_base_datos():
    docs_path = "/app/docs"
    db_path = "/app/faiss_index"

    print("=" * 60)
    print(" INICIANDO")
    print("=" * 60)

    if not os.path.exists(docs_path):
        print(f"ERROR: La carpeta {docs_path} no existe dentro de Docker.")
        sys.exit(1)

    archivos_en_carpeta = os.listdir(docs_path)
    print(f"\nArchivos detectados en la carpeta por Docker: \n{archivos_en_carpeta}\n")

    documentos_totales = []

    for archivo in archivos_en_carpeta:
        ruta = os.path.join(docs_path, archivo)

        if archivo.endswith(".pdf"):
            print(f" leer PDF: {archivo}...")
            try:
                loader = PyMuPDFLoader(ruta)
                docs = loader.load()
                caracteres = sum(len(d.page_content) for d in docs)
                print(
                    f"EXITO: Leídas {len(docs)} páginas, {caracteres} caracteres extraídos."
                )
                documentos_totales.extend(docs)
            except Exception as e:
                print(f"ERROR al leer PDF {archivo}: {e}")

        elif archivo.endswith(".txt"):
            print(f"Intentando leer TXT: {archivo}...")
            try:
                try:
                    loader = TextLoader(ruta, encoding="utf-8")
                    docs = loader.load()
                except UnicodeDecodeError:
                    print("Aviso: Fall UTF-8, intentando con ISO-8859-1 (Latin-1)...")
                    loader = TextLoader(ruta, encoding="iso-8859-1")
                    docs = loader.load()

                caracteres = sum(len(d.page_content) for d in docs)

                if caracteres == 0:
                    print(
                        f"ERROR CRTICO: El archivo {archivo} está vacio (0 caracteres) para la IA."
                    )
                else:
                    print(f"ÉXITO: {caracteres} caracteres extraidos perfectamente.")

                documentos_totales.extend(docs)

            except Exception as e:
                print(f"ERROR al leer TXT {archivo}: {e}")
        else:
            print(f"Omitiendo archivo no soportado o extensión oculta: {archivo}")

    if not documentos_totales:
        print(
            "\nERROR FATAL: No se ha podido extraer texto de NINGÚN archivo. Abortando."
        )
        sys.exit(1)

    print("\nCortando texto en fragmentos...")
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    trozos = text_splitter.split_documents(documentos_totales)
    print(f"Generados {len(trozos)} fragmentos en total.")

    print("\nGenerando Embeddings (Conectando a host.docker.internal)...")

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

    embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)

    vector_db = FAISS.from_documents(trozos, embeddings)

    print(f"\nGuardando índice en {db_path}...")
    vector_db.save_local(db_path)
    print("¡Base de datos regenerada con éxito!.")


if __name__ == "__main__":
    crear_base_datos()
