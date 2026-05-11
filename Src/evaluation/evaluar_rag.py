import os
import json
import asyncio
import pandas as pd
import matplotlib.pyplot as plt
import nest_asyncio
from datasets import Dataset
from ragas import evaluate
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    context_precision,
    context_recall,
)
from ragas.llms import LangchainLLMWrapper
from ragas.embeddings import LangchainEmbeddingsWrapper
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_community.chat_models import ChatOllama

nest_asyncio.apply()

# ── Configuración ──────────────────────────────────────────────────────────────
OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
FAISS_PATH      = os.getenv("FAISS_PATH", "/app/faiss_index")
MODELO_JUEZ     = "llama3.1:8b"
MODELO_EMBED    = "mxbai-embed-large"
DATASET_PATH    = "Src/evaluation/dataset_groundtruth.json"
RESULTADOS_PATH = "Src/evaluation/resultados_ragas.csv"
GRAFICA_PATH    = "Src/evaluation/grafica_ragas.png"
RESPUESTAS_PATH = "Src/evaluation/respuestas_intermedias.json"
K_DOCS          = 3


# ── 1. Cargar dataset ──────────────────────────────────────────────────────────
def cargar_dataset():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"Dataset cargado: {len(data)} preguntas.")
    return data


# ── 2. Pipeline RAG — con caché para no repetir si ya existe ──────────────────
def ejecutar_pipeline_rag(preguntas: list) -> dict:

    # Si ya existe el archivo intermedio, lo carga directamente
    if os.path.exists(RESPUESTAS_PATH):
        print(f"\nArchivo intermedio encontrado en {RESPUESTAS_PATH}")
        print("Cargando respuestas ya generadas (saltando pipeline RAG)...")
        with open(RESPUESTAS_PATH, "r", encoding="utf-8") as f:
            data_dict = json.load(f)
        print(f"Cargadas {len(data_dict['question'])} respuestas del caché.")
        return data_dict

    print("\nCargando índice FAISS y modelos...")
    embeddings  = OllamaEmbeddings(model=MODELO_EMBED, base_url=OLLAMA_URL)
    vectorstore = FAISS.load_local(
        FAISS_PATH, embeddings, allow_dangerous_deserialization=True
    )
    retriever   = vectorstore.as_retriever(search_kwargs={"k": K_DOCS})
    llm         = ChatOllama(model=MODELO_JUEZ, temperature=0.0, base_url=OLLAMA_URL)

    questions_out     = []
    answers_out       = []
    contexts_out      = []
    ground_truths_out = []

    total = len(preguntas)
    for i, item in enumerate(preguntas):
        pregunta     = item["question"]
        ground_truth = item["ground_truth"]
        tipo         = item.get("tipo", "A")

        print(f"[{i+1}/{total}] ({tipo}) {pregunta[:70]}...")

        try:
            docs      = retriever.invoke(pregunta)
            contextos = [doc.page_content for doc in docs]
        except Exception as e:
            print(f"  ⚠ Error FAISS: {e}")
            contextos = ["Error recuperando contexto"]

        contexto_texto = "\n\n".join(
            [f"--- REFERENCIA {j+1} ---\n{c}" for j, c in enumerate(contextos)]
        )

        prompt = f"""Eres un auditor experto en ciberseguridad y normativas legales (ENS, RGPD).

[CONTEXTO NORMATIVO RECUPERADO]
{contexto_texto}

[INSTRUCCIONES]
Responde la siguiente pregunta basándote ÚNICAMENTE en el contexto normativo recuperado.
Si la respuesta no se encuentra en el contexto, responde exactamente:
"Esta información no se encuentra en el contexto normativo proporcionado."
No inventes información. No uses conocimiento externo.

[PREGUNTA]
{pregunta}

[RESPUESTA]"""

        try:
            respuesta = llm.invoke(prompt)
            answer    = respuesta.content.strip()
        except Exception as e:
            print(f"  ⚠ Error LLM: {e}")
            answer = f"Error generando respuesta: {str(e)}"

        questions_out.append(pregunta)
        answers_out.append(answer)
        contexts_out.append(contextos)
        ground_truths_out.append(ground_truth)

        print(f"  ✓ [{i+1}/{total}] Respuesta generada ({len(answer)} chars)")

        # Guardado incremental — si se cae, no pierdes nada
        data_parcial = {
            "question":     questions_out,
            "answer":       answers_out,
            "contexts":     contexts_out,
            "ground_truth": ground_truths_out,
        }
        with open(RESPUESTAS_PATH, "w", encoding="utf-8") as f:
            json.dump(data_parcial, f, ensure_ascii=False, indent=2)

    print(f"\nTodas las respuestas guardadas en {RESPUESTAS_PATH}")
    return data_parcial


# ── 3. RAGAS ───────────────────────────────────────────────────────────────────
def ejecutar_ragas(data_dict: dict) -> pd.DataFrame:
    print("\nEjecutando métricas RAGAS en modo secuencial (Context Precision + Context Recall)...")

    from ragas.metrics.base import MetricWithLLM, MetricWithEmbeddings

    llm_juez = ChatOllama(
        model=MODELO_JUEZ,
        temperature=0.0,
        base_url=OLLAMA_URL,
        timeout=600,
    )
    embeddings = OllamaEmbeddings(
        model=MODELO_EMBED,
        base_url=OLLAMA_URL,
    )

    llm_wrapper   = LangchainLLMWrapper(llm_juez)
    embed_wrapper = LangchainEmbeddingsWrapper(embeddings)

    metricas_lista = [context_precision, context_recall]

    for metrica in metricas_lista:
        if isinstance(metrica, MetricWithLLM):
            metrica.llm = llm_wrapper
        if isinstance(metrica, MetricWithEmbeddings):
            metrica.embeddings = embed_wrapper

    loop = asyncio.get_event_loop()

    preguntas     = data_dict["question"]
    respuestas    = data_dict["answer"]
    contextos     = data_dict["contexts"]
    ground_truths = data_dict["ground_truth"]

    resultados = []
    total = len(preguntas)

    for i in range(total):
        print(f"  Evaluando [{i+1}/{total}]: {preguntas[i][:60]}...")

        fila = {
            "question":     preguntas[i],
            "answer":       respuestas[i],
            "contexts":     contextos[i],
            "ground_truth": ground_truths[i],
        }

        fila_resultado = {
            "question":     preguntas[i],
            "answer":       respuestas[i],
            "ground_truth": ground_truths[i],
        }

        for metrica in metricas_lista:
            try:
                muestra = Dataset.from_dict({
                    "question":     [fila["question"]],
                    "answer":       [fila["answer"]],
                    "contexts":     [fila["contexts"]],
                    "ground_truth": [fila["ground_truth"]],
                })
                score = loop.run_until_complete(
                    metrica.ascore(muestra[0])
                )
                fila_resultado[metrica.name] = round(float(score), 4) if score is not None else None
                print(f"    ✓ {metrica.name}: {score:.4f}")
            except Exception as e:
                print(f"    ⚠ {metrica.name}: error — {str(e)[:60]}")
                fila_resultado[metrica.name] = None

        resultados.append(fila_resultado)

        # Guardado incremental
        df_parcial = pd.DataFrame(resultados)
        df_parcial.to_csv(RESULTADOS_PATH, index=False, encoding="utf-8")
        print(f"    💾 Guardado parcial ({i+1}/{total})")

    df = pd.DataFrame(resultados)
    return df

# ── 4. Guardar resultados y gráfica ───────────────────────────────────────────
def guardar_resultados(df: pd.DataFrame):
    df.to_csv(RESULTADOS_PATH, index=False, encoding="utf-8")
    print(f"\nResultados guardados en: {RESULTADOS_PATH}")

    metricas = ["context_precision", "context_recall"]
    medias   = {m: round(df[m].mean(), 4) for m in metricas if m in df.columns}

    print("\n" + "="*50)
    print("  RESULTADOS RAGAS — RESUMEN")
    print("="*50)
    for nombre, valor in medias.items():
        barra = "█" * int(valor * 20)
        print(f"  {nombre:<22} {valor:.4f}  {barra}")
    print("="*50)

    fig, ax = plt.subplots(figsize=(7, 5))
    colores = ["#2563eb", "#16a34a"]
    bars    = ax.bar(
        list(medias.keys()),
        list(medias.values()),
        color=colores,
        width=0.4,
        zorder=3,
    )
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Puntuación (0 – 1)", fontsize=11)
    ax.set_title(
        "Evaluación RAGAS del Motor RAG — SecureAudit TFG",
        fontsize=13, fontweight="bold", pad=15,
    )
    ax.axhline(
        y=0.7, color="gray", linestyle="--",
        linewidth=0.8, label="Umbral aceptable (0.7)"
    )
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.set_xticklabels(
        ["Context Precision\n(Precisión de Recuperación)",
         "Context Recall\n(Cobertura de Recuperación)"],
        fontsize=10,
    )
    for bar, val in zip(bars, medias.values()):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.02,
            f"{val:.3f}",
            ha="center", va="bottom", fontsize=12, fontweight="bold",
        )
    plt.tight_layout()
    plt.savefig(GRAFICA_PATH, dpi=150, bbox_inches="tight")
    print(f"Gráfica guardada en: {GRAFICA_PATH}")
    plt.close()

    return medias

# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("="*50)
    print("  EVALUACIÓN RAGAS — SecureAudit TFG")
    print("="*50)

    dataset_raw   = cargar_dataset()
    data_dict     = ejecutar_pipeline_rag(dataset_raw)
    df_resultados = ejecutar_ragas(data_dict)
    medias        = guardar_resultados(df_resultados)

    print("\n✓ Evaluación completada.")