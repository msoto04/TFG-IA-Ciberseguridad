from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
import os

def procesar_documentos():
    # 1. Ruta de la carpeta de documentos
    docs_path = "D:/TFG_Ciberseguridad/docs"
    documentos_totales = []

    # 2. Cargar cada PDF en la carpeta
    for archivo in os.listdir(docs_path):
        if archivo.endswith(".pdf"):
            print(f"Leyendo {archivo}...")
            loader = PyPDFLoader(os.path.join(docs_path, archivo))
            documentos_totales.extend(loader.load())

    # 3. Configurar el troceado (Chunking)
    # Usamos trozos de 1000 caracteres con un solapamiento de 200
    # para que no se pierda el contexto entre un trozo y otro.
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len,
        add_start_index=True,
    )

    trozos = text_splitter.split_documents(documentos_totales)
    
    print(f"\nProceso finalizado:")
    print(f"- Páginas totales leídas: {len(documentos_totales)}")
    print(f"- Trozos de texto creados: {len(trozos)}")
    
    # Vamos a ver qué hay en el primer trozo para probar
    if trozos:
        print("\nEjemplo del primer trozo:")
        print(trozos[0].page_content[:200] + "...")

if __name__ == "__main__":
    procesar_documentos()