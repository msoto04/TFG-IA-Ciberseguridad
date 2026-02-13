import os
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

# Desactivar avisos innecesarios
os.environ['KMP_DUPLICATE_LIB_OK']='True'

def consultar_ens():
    db_path = "D:/TFG_Ciberseguridad/faiss_index"
    
    # 1. Cargamos el mismo modelo de embeddings que usamos para guardar
    print("Cargando modelo de embeddings...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    
    # 2. Cargamos la base de datos desde el disco
    print("Cargando base de datos FAISS...")
    vector_db = FAISS.load_local(
        db_path, 
        embeddings, 
        allow_dangerous_deserialization=True
    )

    # 3. Hacemos una pregunta técnica sobre el ENS
    pregunta = "¿Qué dice el ENS sobre la política de seguridad y el marco organizativo?"
    
    print(f"\nPreguntando al índice: {pregunta}")
    print("-" * 50)

    # 4. Buscamos los 2 trozos más relevantes
    resultados = vector_db.similarity_search(pregunta, k=2)

    # 5. Mostramos los resultados
    for i, doc in enumerate(resultados):
        print(f"\nRESULTADO {i+1}:")
        print(f"Contenido: {doc.page_content[:600]}...") # Mostramos solo el principio
        print("-" * 50)

if __name__ == "__main__":
    consultar_ens()