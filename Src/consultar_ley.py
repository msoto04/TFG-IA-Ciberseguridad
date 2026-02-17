import os
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

# Desactivar avisos innecesarios
os.environ['KMP_DUPLICATE_LIB_OK']='True'

def consultar_ens():
    db_path = "D:/TFG_Ciberseguridad/faiss_index"
    
    # 1. modelo de embeddings 
    print("Cargando modelo de embeddings...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    
    # 2. base de datos desde el disco
    print("Cargando base de datos FAISS...")
    vector_db = FAISS.load_local(
        db_path, 
        embeddings, 
        allow_dangerous_deserialization=True
    )

    # 3. ENS pregunta tecnica 
    pregunta = "¿Qué dice el ENS sobre la política de seguridad y el marco organizativo?"
    
    print(f"\nPreguntando al índice: {pregunta}")
    print("-" * 50)

    # 4. Trozos relevantes
    resultados = vector_db.similarity_search(pregunta, k=2)

    # 5. Resultados
    for i, doc in enumerate(resultados):
        print(f"\nRESULTADO {i+1}:")
        print(f"Contenido: {doc.page_content[:600]}...") 
        print("-" * 50)

if __name__ == "__main__":
    consultar_ens()