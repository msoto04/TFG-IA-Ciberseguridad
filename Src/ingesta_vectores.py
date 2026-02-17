import os
import time
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

def crear_base_datos():
    docs_path = "D:/TFG_Ciberseguridad/docs"
    db_path = "D:/TFG_Ciberseguridad/faiss_index"
    
    print("1. Verificando archivos...")
    if not os.path.exists(os.path.join(docs_path, "ENS_2022.pdf")):
        print("ERROR: No veo el PDF en D:/TFG_Ciberseguridad/docs")
        return

    print("2. Cargando PDF y troceando... (esto es rápido)")
    loader = PyPDFLoader(os.path.join(docs_path, "ENS_2022.pdf"))
    documentos = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    trozos = text_splitter.split_documents(documentos)
    print(f"   Hecho: {len(trozos)} trozos creados.")

    print("3. Conectando con Ollama para Embeddings... (Aquí suele tardar)")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    
    try:
        start_time = time.time()
  
        vector_db = FAISS.from_documents(trozos, embeddings)
        print(f"4. Índice creado en {round(time.time() - start_time, 2)} segundos.")
        
     
        print(f"5. Guardando en {db_path}...")
        vector_db.save_local(db_path)
        print("¡ÉXITO! Carpeta creada correctamente.")
        
    except Exception as e:
        print(f"ERROR CRÍTICO: {e}")

if __name__ == "__main__":
    crear_base_datos()