import os
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings

os.environ["KMP_DUPLICATE_LIB_OK"] = "True"


def ver_memoria():
    print("Conectando con la base de datos...")

    db_path = "D:/TFG_Ciberseguridad/faiss_index"

    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    vector_db = FAISS.load_local(db_path, embeddings, allow_dangerous_deserialization=True)

    pregunta = "¿Qué es la vulnerabilidad A03 del OWASP Top 10?"
    print(f"\nBuscando en los PDFs: {pregunta}")
    print("-" * 50)

    resultados = vector_db.similarity_search(pregunta, k=3)

    for i, doc in enumerate(resultados):
        print(f"\n--- TROZO RECUPERADO {i+1} ---")
        print(f"Origen: {doc.metadata.get('source', 'Desconocido')}")
        print(f"Texto: {doc.page_content[:500]}...")


if __name__ == "__main__":
    ver_memoria()
