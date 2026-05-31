"""
test_recuperacion_rag.py
========================
Pruebas de recuperación del motor RAG — SecureAudit TFG
--------------------------------------------------------
Propósito:
    Verificar que el índice FAISS recupera los fragmentos normativos
    correctos para cada tipo de vulnerabilidad detectada por SAST.

    A diferencia de RAGAS (calidad de respuesta del LLM), este script
    evalúa exclusivamente la etapa de RECUPERACIÓN: qué documentos,
    qué secciones y con qué score de similitud devuelve el índice
    vectorial ante cada consulta de vulnerabilidad.

Corpus evaluado (5 documentos):
    - OWASP.txt               → OWASP Top 10 2021
    - ENS_2022.pdf            → Real Decreto 311/2022
    - RGPD.pdf                → Reglamento UE 2016/679
    - Criptologia_de_empleo_ENS.pdf  → CCN-STIC-807
    - Glosario_Ciberseguridad.pdf    → Glosario CCN

Salidas:
    - resultados_recuperacion.json   → datos completos por caso
    - reporte_recuperacion.md        → informe para la memoria del TFG

Uso:
    docker exec -it secureaudit-worker python /app/Src/evaluation/test_recuperacion_rag.py
"""

import os
import json
import time
from datetime import datetime
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

# ── Configuración ─────────────────────────────────────────────────────────────
DB_PATH    = os.getenv("FAISS_PATH",  "/app/faiss_index")
OLLAMA_URL = os.getenv("OLLAMA_URL",  "http://host.docker.internal:11434")
OUTPUT_DIR = os.getenv("OUTPUT_DIR",  "/app/data")
K_RESULTS  = 4      # chunks recuperados por consulta (igual que en orquestador)
UMBRAL_OK  = 1.5    # distancia L2 por debajo de la cual se considera recuperación válida

# ── 20 Casos de prueba distribuidos por documento ────────────────────────────
#
# Distribución:
#   OWASP.txt                     → TC-01 a TC-05  (5 casos)
#   ENS_2022.pdf                  → TC-06 a TC-10  (5 casos)
#   RGPD.pdf                      → TC-11 a TC-14  (4 casos)
#   Criptologia_de_empleo_ENS.pdf → TC-15 a TC-17  (3 casos)
#   Glosario_Ciberseguridad.pdf   → TC-18 a TC-20  (3 casos)
#
# Campos:
#   consulta_faiss   → texto que se envía al índice (simula la query del orquestador)
#   fuente_esperada  → nombre del archivo que DEBE aparecer entre los resultados
#   seccion_esperada → fragmento de texto que DEBE estar en algún chunk recuperado

CASOS_PRUEBA = [

    # ── OWASP Top 10 (5 casos) ────────────────────────────────────────────────
    {
        "id": "TC-01",
        "documento": "OWASP.txt",
        "vulnerabilidad_semgrep": "ssrf-requests",
        "consulta_faiss": "A10:2021 SSRF falsificación solicitudes servidor URL no validada",
        "fuente_esperada": "OWASP.txt",
        "seccion_esperada": "A10:2021",
        "descripcion": "SSRF → OWASP A10:2021 Falsificación de Solicitudes del Lado del Servidor",
    },
    {
        "id": "TC-02",
        "documento": "OWASP.txt",
        "vulnerabilidad_semgrep": "sqlalchemy-execute-raw-query",
        "consulta_faiss": "A03:2021 inyección SQL consultas parametrizadas prepared statements",
        "fuente_esperada": "OWASP.txt",
        "seccion_esperada": "A03:2021",
        "descripcion": "SQL Injection → OWASP A03:2021 Inyección",
    },
    {
        "id": "TC-03",
        "documento": "OWASP.txt",
        "vulnerabilidad_semgrep": "insecure-hash-algorithm-md5",
        "consulta_faiss": "A02:2021 fallos criptográficos contraseñas datos sensibles cifrado TLS AES",
        "fuente_esperada": "OWASP.txt",
        "seccion_esperada": "A02:2021",
        "descripcion": "Hash MD5 débil → OWASP A02:2021 Fallos Criptográficos",
    },
    {
        "id": "TC-04",
        "documento": "OWASP.txt",
        "vulnerabilidad_semgrep": "secure-set-cookie",
        "consulta_faiss": "A07:2021 autenticación gestión sesiones tokens claves contraseñas",
        "fuente_esperada": "OWASP.txt",
        "seccion_esperada": "A07:2021",
        "descripcion": "Cookie insegura → OWASP A07:2021 Fallos de Autenticación",
    },
    {
        "id": "TC-05",
        "documento": "OWASP.txt",
        "vulnerabilidad_semgrep": "avoid-hardcoded-config-debug",
        "consulta_faiss": "A05:2021 configuración incorrecta debug producción encabezados HTTP mensajes error",
        "fuente_esperada": "OWASP.txt",
        "seccion_esperada": "A05:2021",
        "descripcion": "Debug en producción → OWASP A05:2021 Security Misconfiguration",
    },

    # ── ENS 2022 (5 casos) ────────────────────────────────────────────────────
    {
        "id": "TC-06",
        "documento": "ENS_2022.pdf",
        "vulnerabilidad_semgrep": "path-traversal-open",
        "consulta_faiss": "control de acceso op.acc usuarios permisos mínimo privilegio roles",
        "fuente_esperada": "ENS_2022.pdf",
        "seccion_esperada": "op.acc",
        "descripcion": "Path Traversal → ENS op.acc Control de Acceso (Art. 17 / 20)",
    },
    {
        "id": "TC-07",
        "documento": "ENS_2022.pdf",
        "vulnerabilidad_semgrep": "missing-security-logging",
        "consulta_faiss": "gestión de incidentes registro actividad usuarios op.exp.7 monitorización",
        "fuente_esperada": "ENS_2022.pdf",
        "seccion_esperada": "incidentes",
        "descripcion": "Falta de logging → ENS op.exp.7 Gestión de Incidentes",
    },
    {
        "id": "TC-08",
        "documento": "ENS_2022.pdf",
        "vulnerabilidad_semgrep": "hardcoded-password",
        "consulta_faiss": "gestión de personal formación obligaciones seguridad ENS artículo 15",
        "fuente_esperada": "ENS_2022.pdf",
        "seccion_esperada": "personal",
        "descripcion": "Credenciales en código → ENS Art. 15 Gestión de Personal",
    },
    {
        "id": "TC-09",
        "documento": "ENS_2022.pdf",
        "vulnerabilidad_semgrep": "insecure-deserialization",
        "consulta_faiss": "proceso de autorización org.4 elementos sistema de información ENS",
        "fuente_esperada": "ENS_2022.pdf",
        "seccion_esperada": "org.4",
        "descripcion": "Deserialización insegura → ENS org.4 Proceso de Autorización",
    },
    {
        "id": "TC-10",
        "documento": "ENS_2022.pdf",
        "vulnerabilidad_semgrep": "missing-encryption-at-rest",
        "consulta_faiss": "cifrado algoritmos autorizados CCN op.exp.10 protección claves criptográficas ENS",
        "fuente_esperada": "ENS_2022.pdf",
        "seccion_esperada": "op.exp.10",
        "descripcion": "Cifrado ausente → ENS op.exp.10 Protección de claves criptográficas",
    },

    # ── RGPD (4 casos) ────────────────────────────────────────────────────────
    {
        "id": "TC-11",
        "documento": "RGPD.pdf",
        "vulnerabilidad_semgrep": "detected-stripe-api-key",
        "consulta_faiss": "violación seguridad datos personales notificación 72 horas responsable tratamiento RGPD",
        "fuente_esperada": "RGPD.pdf",
        "seccion_esperada": "violación",
        "descripcion": "Credencial API expuesta → RGPD notificación de violación de datos (Art. 33)",
    },
    {
        "id": "TC-12",
        "documento": "RGPD.pdf",
        "vulnerabilidad_semgrep": "insecure-data-storage",
        "consulta_faiss": "integridad confidencialidad datos personales medidas técnicas organizativas RGPD Art. 5",
        "fuente_esperada": "RGPD.pdf",
        "seccion_esperada": "integridad",
        "descripcion": "Almacenamiento inseguro → RGPD Art. 5 principios tratamiento datos",
    },
    {
        "id": "TC-13",
        "documento": "RGPD.pdf",
        "vulnerabilidad_semgrep": "missing-pseudonymization",
        "consulta_faiss": "pseudonimización minimización datos tratamiento privacidad diseño RGPD Art. 25",
        "fuente_esperada": "RGPD.pdf",
        "seccion_esperada": "datos personales",
        "descripcion": "Sin pseudonimización → RGPD Art. 25 Privacidad por diseño",
    },
    {
        "id": "TC-14",
        "documento": "RGPD.pdf",
        "vulnerabilidad_semgrep": "logging-sensitive-data",
        "consulta_faiss": "minimización datos personales conservación limitada finalidad RGPD principios",
        "fuente_esperada": "RGPD.pdf",
        "seccion_esperada": "minimización",
        "descripcion": "Log con datos sensibles → RGPD principio de minimización de datos",
    },

    # ── Criptología de Empleo ENS / CCN-STIC-807 (3 casos) ───────────────────
    {
        "id": "TC-15",
        "documento": "Criptologia_de_empleo_ENS.pdf",
        "vulnerabilidad_semgrep": "insecure-hash-algorithm-md5",
        "consulta_faiss": "SHA-2 SHA-3 algoritmos hash autorizados fortaleza mínima CCN-STIC-807",
        "fuente_esperada": "Criptologia_de_empleo_ENS.pdf",
        "seccion_esperada": "SHA",
        "descripcion": "MD5 débil → CCN-STIC-807 tabla de algoritmos hash autorizados",
    },
    {
        "id": "TC-16",
        "documento": "Criptologia_de_empleo_ENS.pdf",
        "vulnerabilidad_semgrep": "weak-tls-version",
        "consulta_faiss": "TLS versiones autorizadas protocolo seguro cifrado comunicaciones CCN",
        "fuente_esperada": "Criptologia_de_empleo_ENS.pdf",
        "seccion_esperada": "TLS",
        "descripcion": "TLS débil → CCN-STIC-807 versiones TLS autorizadas",
    },
    {
        "id": "TC-17",
        "documento": "Criptologia_de_empleo_ENS.pdf",
        "vulnerabilidad_semgrep": "weak-rsa-key-size",
        "consulta_faiss": "longitud de clave RSA curvas elípticas fortaleza bits cifrado asimétrico CCN",
        "fuente_esperada": "Criptologia_de_empleo_ENS.pdf",
        "seccion_esperada": "clave",
        "descripcion": "Clave RSA insuficiente → CCN-STIC-807 longitudes mínimas de clave",
    },

    # ── Glosario de Ciberseguridad CCN (3 casos) ─────────────────────────────
    {
        "id": "TC-18",
        "documento": "Glosario_Ciberseguridad.pdf",
        "vulnerabilidad_semgrep": "sql-injection-generic",
        "consulta_faiss": "inyección SQL definición ataque validación entradas base de datos",
        "fuente_esperada": "Glosario_Ciberseguridad.pdf",
        "seccion_esperada": "Inyección SQL",
        "descripcion": "SQL Injection → Glosario CCN definición de Inyección SQL (sección 2.9.20)",
    },
    {
        "id": "TC-19",
        "documento": "Glosario_Ciberseguridad.pdf",
        "vulnerabilidad_semgrep": "zero-day-exploit",
        "consulta_faiss": "zero-day vulnerabilidad desconocida fabricante sin parche explotación",
        "fuente_esperada": "Glosario_Ciberseguridad.pdf",
        "seccion_esperada": "Zero-day",
        "descripcion": "Explotación zero-day → Glosario CCN definición de vulnerabilidad Zero-day",
    },
    {
        "id": "TC-20",
        "documento": "Glosario_Ciberseguridad.pdf",
        "vulnerabilidad_semgrep": "missing-incident-response",
        "consulta_faiss": "gestión de incidentes definición respuesta proceso notificación ciberseguridad",
        "fuente_esperada": "Glosario_Ciberseguridad.pdf",
        "seccion_esperada": "incidentes",
        "descripcion": "Sin gestión de incidentes → Glosario CCN definición Gestión de Incidentes",
    },
]


# ── Lógica de evaluación ──────────────────────────────────────────────────────

def cargar_vectorstore():
    print("Cargando modelo de embeddings (mxbai-embed-large)...")
    embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=OLLAMA_URL)
    print(f"Cargando índice FAISS desde {DB_PATH}...")
    vs = FAISS.load_local(DB_PATH, embeddings, allow_dangerous_deserialization=True)
    total = len(vs.docstore._dict)
    print(f"Índice cargado correctamente. Chunks totales indexados: {total}\n")
    return vs


def evaluar_caso(vs, caso: dict) -> dict:
    t0   = time.time()
    docs = vs.similarity_search_with_score(caso["consulta_faiss"], k=K_RESULTS)
    latencia = round(time.time() - t0, 3)

    chunks = []
    for doc, score in docs:
        fuente = os.path.basename(doc.metadata.get("source", "desconocido"))
        chunks.append({
            "fuente":    fuente,
            "score_l2":  round(float(score), 4),
            "fragmento": doc.page_content[:350],
        })

    fuentes_recuperadas    = [c["fuente"] for c in chunks]
    fragmentos_recuperados = [c["fragmento"] for c in chunks]
    scores                 = [c["score_l2"] for c in chunks]

    fuente_ok  = any(caso["fuente_esperada"].lower() in f.lower()
                     for f in fuentes_recuperadas)
    seccion_ok = any(caso["seccion_esperada"].lower() in frag.lower()
                     for frag in fragmentos_recuperados)
    score_ok   = scores[0] < UMBRAL_OK if scores else False
    resultado  = "PASS" if (fuente_ok and seccion_ok) else "FAIL"

    return {
        "id":                     caso["id"],
        "documento":              caso["documento"],
        "descripcion":            caso["descripcion"],
        "vulnerabilidad_semgrep": caso["vulnerabilidad_semgrep"],
        "consulta_enviada":       caso["consulta_faiss"],
        "fuente_esperada":        caso["fuente_esperada"],
        "seccion_esperada":       caso["seccion_esperada"],
        "resultado":              resultado,
        "fuente_ok":              fuente_ok,
        "seccion_ok":             seccion_ok,
        "score_top1":             scores[0] if scores else None,
        "score_ok_umbral":        score_ok,
        "latencia_seg":           latencia,
        "chunks_recuperados": [
            {"rank": i + 1, **c} for i, c in enumerate(chunks)
        ],
    }


def imprimir_tabla(resultados: list):
    print("\n" + "=" * 90)
    print("  RESULTADOS — PRUEBAS DE RECUPERACIÓN RAG")
    print("=" * 90)
    print(f"  {'ID':<7} {'Doc':<35} {'Res':<8} {'Fuente':<9} {'Sección':<9} {'Score':<8} {'ms'}")
    print("-" * 90)

    por_doc = {}
    for r in resultados:
        doc = r["documento"]
        if doc not in por_doc:
            por_doc[doc] = {"pass": 0, "fail": 0}
        if r["resultado"] == "PASS":
            por_doc[doc]["pass"] += 1
        else:
            por_doc[doc]["fail"] += 1

        icono = "✓ PASS" if r["resultado"] == "PASS" else "✗ FAIL"
        desc  = r["descripcion"][:33]
        print(
            f"  {r['id']:<7} {desc:<35} {icono:<8} "
            f"{'Sí'  if r['fuente_ok']  else 'No':<9} "
            f"{'Sí'  if r['seccion_ok'] else 'No':<9} "
            f"{str(r['score_top1']):<8} "
            f"{int(r['latencia_seg']*1000)}ms"
        )

    total  = len(resultados)
    passed = sum(1 for r in resultados if r["resultado"] == "PASS")
    print("=" * 90)
    print(f"\n  RESUMEN GLOBAL: {passed}/{total} PASS  ({round(passed/total*100)}%)\n")
    print("  Por documento:")
    for doc, stats in por_doc.items():
        total_doc = stats["pass"] + stats["fail"]
        print(f"    {doc:<40} {stats['pass']}/{total_doc} PASS")
    print("=" * 90)


def guardar_json(resultados: list):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "resultados_recuperacion.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(resultados, f, ensure_ascii=False, indent=2)
    print(f"\nJSON guardado en: {path}")
    return path


def guardar_markdown(resultados: list):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path   = os.path.join(OUTPUT_DIR, "reporte_recuperacion.md")
    total  = len(resultados)
    passed = sum(1 for r in resultados if r["resultado"] == "PASS")
    fecha  = datetime.now().strftime("%d/%m/%Y %H:%M")

    # Agrupar por documento para el resumen
    por_doc = {}
    for r in resultados:
        d = r["documento"]
        por_doc.setdefault(d, []).append(r)

    lines = [
        "# Pruebas de Recuperación del Motor RAG — SecureAudit",
        "",
        f"**Fecha:** {fecha}  ",
        f"**Índice FAISS:** `{DB_PATH}`  ",
        "**Modelo embeddings:** `mxbai-embed-large`  ",
        f"**Chunks por consulta (k):** {K_RESULTS}  ",
        f"**Umbral score L2:** < {UMBRAL_OK}  ",
        "",
        "## Resumen global",
        "",
        "| Métrica | Valor |",
        "|---------|-------|",
        f"| Tests ejecutados | {total} |",
        f"| **Tests PASS** | **{passed}** |",
        f"| Tests FAIL | {total - passed} |",
        f"| **Tasa de éxito** | **{round(passed/total*100)}%** |",
        "",
        "## Resultados por documento",
        "",
        "| Documento | PASS | FAIL | Tasa |",
        "|-----------|------|------|------|",
    ]
    for doc, casos in por_doc.items():
        p = sum(1 for c in casos if c["resultado"] == "PASS")
        f = len(casos) - p
        lines.append(f"| `{doc}` | {p} | {f} | {round(p/len(casos)*100)}% |")

    lines += ["", "---", "", "## Detalle por caso de prueba", ""]

    for r in resultados:
        icono = "✅ PASS" if r["resultado"] == "PASS" else "❌ FAIL"
        lines += [
            f"### {r['id']} — {icono}",
            "",
            "| Campo | Valor |",
            "|-------|-------|",
            f"| **Descripción** | {r['descripcion']} |",
            f"| **Documento objetivo** | `{r['documento']}` |",
            f"| **Vulnerabilidad Semgrep** | `{r['vulnerabilidad_semgrep']}` |",
            f"| **Consulta enviada a FAISS** | `{r['consulta_enviada']}` |",
            f"| **Fuente esperada** | `{r['fuente_esperada']}` → {'✓ encontrada' if r['fuente_ok'] else '✗ NO encontrada'} |",
            f"| **Sección esperada** | `{r['seccion_esperada']}` → {'✓ presente' if r['seccion_ok'] else '✗ NO presente'} |",
            f"| **Score L2 top-1** | `{r['score_top1']}` ({'≤ umbral ✓' if r['score_ok_umbral'] else '> umbral ✗'}) |",
            f"| **Latencia** | `{r['latencia_seg']}s` |",
            "",
            "**Fragmentos recuperados:**",
            "",
        ]
        for chunk in r["chunks_recuperados"]:
            frag = chunk["fragmento"][:280].replace("\n", " ")
            lines += [
                f"**#{chunk['rank']}** `{chunk['fuente']}` — score L2: `{chunk['score_l2']}`",
                f"> {frag}...",
                "",
            ]
        lines += ["---", ""]

    # Sección de fallos
    fallos = [r for r in resultados if r["resultado"] == "FAIL"]
    if fallos:
        lines += ["## Análisis de fallos", ""]
        for r in fallos:
            causas = []
            if not r["fuente_ok"]:
                causas.append(f"fuente `{r['fuente_esperada']}` no recuperada entre los top-{K_RESULTS}")
            if not r["seccion_ok"]:
                causas.append(f"sección `{r['seccion_esperada']}` ausente en los chunks recuperados")
            lines.append(f"- **{r['id']}** (`{r['vulnerabilidad_semgrep']}`): {'; '.join(causas)}.")
        lines += [
            "",
            "**Causa probable:** tamaño de chunk insuficiente en la ingesta o "
            "vocabulario de la consulta no alineado con el texto indexado. "
            "Solución: reindexar con `ingesta_vectores.py` corregido (chunk_size=1000) "
            "y revisar las traducciones del diccionario `TRADUCCION_CONOCIDAS`.",
        ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Informe Markdown guardado en: {path}")
    return path


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  PRUEBAS DE RECUPERACIÓN RAG — SecureAudit TFG")
    print(f"  {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("=" * 60)

    vs         = cargar_vectorstore()
    resultados = []

    for i, caso in enumerate(CASOS_PRUEBA):
        print(f"[{i+1:02d}/{len(CASOS_PRUEBA)}] {caso['id']} ({caso['documento']}) — {caso['descripcion'][:55]}")
        r = evaluar_caso(vs, caso)
        resultados.append(r)
        icono  = "✓ PASS" if r["resultado"] == "PASS" else "✗ FAIL"
        top1   = r["chunks_recuperados"][0]["fuente"] if r["chunks_recuperados"] else "—"
        print(f"         → {icono}  score: {r['score_top1']}  top-1: {top1}")

    imprimir_tabla(resultados)
    guardar_json(resultados)
    guardar_markdown(resultados)

    print("\nEjecución completada.")
