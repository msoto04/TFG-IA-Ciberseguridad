import os
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

os.environ["KMP_DUPLICATE_LIB_OK"] = "True"


def consultar_ens():
    db_path = "D:/TFG_Ciberseguridad/faiss_index"

    print("Cargando modelo de embeddings...")
    embeddings = OllamaEmbeddings(model="mxbai-embed-large")

    print("Cargando base de datos FAISS...")
    vector_db = FAISS.load_local(db_path, embeddings, allow_dangerous_deserialization=True)

    pregunta = "Artículo 1. Objeto del Esquema Nacional de Seguridad"

    print(f"\nPreguntando al índice: {pregunta}")
    print("-" * 50)

    resultados = vector_db.similarity_search(pregunta, k=5)

    for i, doc in enumerate(resultados):
        print(f"\nRESULTADO {i+1}:")
        print(f"Contenido: {doc.page_content[:600]}...")
        print("-" * 50)


if __name__ == "__main__":
    consultar_ens()
