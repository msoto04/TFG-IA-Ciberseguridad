import os
import json
from Src.security_tools.sast_scanner import ejecutar_sast_profesional
from Src.ai_engine.orquestador import app


def ejecutar_auditoria_completa(ruta):
    print("\n" + "=" * 70)
    print("SISTEMA MULTI-AGENTE DE AUDITORÍA DE SEGURIDAD (ENS)")
    print("=" * 70)

    print(f"[+] Iniciando análisis SAST en: {ruta}")
    hallazgos = ejecutar_sast_profesional(ruta)

    if not hallazgos:
        print("\n[!] No se han detectado vulnerabilidades críticas.")
        return

    print(f"\n[!] Se han encontrado {len(hallazgos)} vulnerabilidades.")
    print("[!] Iniciando razonamiento multi-agente...\n")

    informe_markdown = ""
    datos_json = []

    for i, h in enumerate(hallazgos):
        print(
            f"-> Procesando hallazgo {i+1}/{len(hallazgos)}: {h['vulnerabilidad']}..."
        )

        resultado = app.invoke({"hallazgos_tecnicos": [h]})

        tiempos = resultado["tiempos"]
        print(
            f"    [Reloj] T. Técnico: {tiempos['tecnico']}s | T. Legal: {tiempos['legal']}s"
        )

        informe_markdown += f"### HALLAZGO {i+1}: {h['vulnerabilidad']}\n"
        informe_markdown += f"*Archivo: {h['archivo']} (Línea {h['linea']})*\n"
        informe_markdown += f"*Tiempos: Técnico ({tiempos['tecnico']}s), Legal ({tiempos['legal']}s)*\n\n"
        informe_markdown += resultado["veredicto_final"] + "\n"
        informe_markdown += "-" * 40 + "\n\n"

        item_json = {
            "id": i + 1,
            "vulnerabilidad": h["vulnerabilidad"],
            "archivo": h["archivo"],
            "linea": h["linea"],
            "codigo_afectado": h["codigo_afectado"],
            "analisis_tecnico": resultado.get("explicacion_tecnica", "N/A"),
            "analisis_legal_markdown": resultado["veredicto_final"],
            "tiempos": {
                "tecnico": tiempos["tecnico"],
                "legal": tiempos["legal"],
                "total": round(tiempos["tecnico"] + tiempos["legal"], 2),
            },
        }
        datos_json.append(item_json)

    ruta_md = os.path.join(ruta, "reporte_auditoria.md")
    ruta_json = os.path.join(ruta, "auditoria.json")

    try:

        with open(ruta_md, "w", encoding="utf-8") as f:
            f.write("# INFORME TÉCNICO-LEGAL DE SEGURIDAD (ENS)\n")
            f.write(
                f"**Fecha:** {os.popen('date').read().strip() if os.name != 'nt' else ''}\n"
            )
            f.write(f"**Directorio:** {ruta}\n\n")
            f.write(informe_markdown)

        with open(ruta_json, "w", encoding="utf-8") as f:
            json.dump(datos_json, f, indent=4, ensure_ascii=False)

        print("\n" + "=" * 70)
        print("AUDITORÍA FINALIZADA CON ÉXITO")
        print(f"[1] Informe PDF/MD: {ruta_md}")
        print(f"[2] Datos JSON:     {ruta_json}")
        print("=" * 70)

    except Exception as e:
        print(f"\n[ERROR] No se pudieron guardar los informes: {e}")


if __name__ == "__main__":
    if os.path.exists("/app/auditoria"):
        carpeta_a_auditar = "/app/auditoria"
    else:
        carpeta_a_auditar = "D:/TFG_Ciberseguridad/codigo_prueba"

    if os.path.isdir(carpeta_a_auditar):
        ejecutar_auditoria_completa(carpeta_a_auditar)
    else:
        print(f"Error: No se encuentra el directorio: {carpeta_a_auditar}")
