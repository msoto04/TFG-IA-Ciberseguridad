import os
import sys
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import PyMuPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import OllamaEmbeddings
from langchain.schema import Document


# ─────────────────────────────────────────────
# CHUNKING ESPECIAL PARA OWASP.TXT
# El OWASP está estructurado por secciones (A01, A02...).
# Lo partimos manualmente por sección para que cada
# vulnerabilidad quede en su propio chunk, sin mezclar A09 con A10.
# ─────────────────────────────────────────────
def split_owasp_por_seccion(texto: str, fuente: str) -> list:
    import re

    secciones = re.split(r'(?=A\d{2}:2021)', texto)
    docs = []
    for seccion in secciones:
        seccion = seccion.strip()
        if len(seccion) > 30:  
            docs.append(Document(
                page_content=seccion,
                metadata={"source": fuente, "page": 0}
            ))
    return docs


def crear_base_datos():
    docs_path = "/app/docs"
    db_path = "/app/faiss_index"

    print("=" * 60)
    print(" INICIANDO INGESTA (chunking mejorado)")
    print("=" * 60)

    if not os.path.exists(docs_path):
        print(f"ERROR: La carpeta {docs_path} no existe dentro de Docker.")
        sys.exit(1)

    archivos_en_carpeta = os.listdir(docs_path)
    print(f"\nArchivos detectados: {archivos_en_carpeta}\n")

    documentos_totales = []
    documentos_owasp = [] 

    for archivo in archivos_en_carpeta:
        ruta = os.path.join(docs_path, archivo)

        if archivo.endswith(".pdf"):
            print(f"Leyendo PDF: {archivo}...")
            try:
                loader = PyMuPDFLoader(ruta)
                docs = loader.load()
                caracteres = sum(len(d.page_content) for d in docs)
                print(f"  OK: {len(docs)} páginas, {caracteres} caracteres.")
                documentos_totales.extend(docs)
            except Exception as e:
                print(f"  ERROR al leer PDF {archivo}: {e}")

        elif archivo.endswith(".txt"):
            print(f"Leyendo TXT: {archivo}...")
            try:
                try:
                    loader = TextLoader(ruta, encoding="utf-8")
                    docs = loader.load()
                except UnicodeDecodeError:
                    loader = TextLoader(ruta, encoding="iso-8859-1")
                    docs = loader.load()

                caracteres = sum(len(d.page_content) for d in docs)
                if caracteres == 0:
                    print(f"  ERROR CRÍTICO: {archivo} está vacío.")
                else:
                    print(f"  OK: {caracteres} caracteres.")

           
                if "owasp" in archivo.lower():
                    print("  → Aplicando chunking especial OWASP (por sección A0X)...")
                    for doc in docs:
                        chunks_owasp = split_owasp_por_seccion(doc.page_content, ruta)
                        documentos_owasp.extend(chunks_owasp)
                    print(f"  → {len(documentos_owasp)} secciones OWASP generadas.")
                else:
                    documentos_totales.extend(docs)

            except Exception as e:
                print(f"  ERROR al leer TXT {archivo}: {e}")
        else:
            print(f"Omitiendo: {archivo}")

    if not documentos_totales and not documentos_owasp:
        print("\nERROR FATAL: No se extrajo texto de ningún archivo.")
        sys.exit(1)


    print("\nCortando documentos generales en fragmentos...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=100,
        separators=["Artículo ", "\n\n", "\n", ". ", " ", ""]
    )
    trozos_generales = text_splitter.split_documents(documentos_totales)
    print(f"  {len(trozos_generales)} fragmentos generales.")

    # Combinar todo
    trozos_totales = trozos_generales + documentos_owasp
    print(f"\nTotal chunks a indexar: {len(trozos_totales)}")
    print(f"  - Generales (PDFs): {len(trozos_generales)}")
    print(f"  - OWASP (por sección): {len(documentos_owasp)}")

    # Verificación rápida: mostrar los chunks de OWASP generados
    print("\nChunks OWASP generados:")
    for i, doc in enumerate(documentos_owasp):
        print(f"  [{i+1}] {doc.page_content[:80].strip()}...")

    print("\nGenerando embeddings...")
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)

    vector_db = FAISS.from_documents(trozos_totales, embeddings)

    print(f"\nGuardando índice en {db_path}...")
    vector_db.save_local(db_path)
    print("¡Índice regenerado con éxito!")


if __name__ == "__main__":
    crear_base_datos()