import os
from langchain_community.document_loaders import PyMuPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
import os


def procesar_documentos():

    docs_path = os.getenv("DOCS_PATH", "/app/docs")
    documentos_totales = []

    for archivo in os.listdir(docs_path):
        if archivo.endswith(".pdf"):
            print(f"Leyendo {archivo}...")
            loader = PyMuPDFLoader(os.path.join(docs_path, archivo))
            documentos_totales.extend(loader.load())

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len,
        add_start_index=True,
    )

    trozos = text_splitter.split_documents(documentos_totales)

    print("\nProceso finalizado:")
    print(f"- Páginas totales leídas: {len(documentos_totales)}")
    print(f"- Trozos de texto creados: {len(trozos)}")

    if trozos:
        print("\nEjemplo del primer trozo:")
        print(trozos[0].page_content[:200] + "...")


if __name__ == "__main__":
    procesar_documentos()
