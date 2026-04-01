import subprocess
import json
import os
import logging


logger = logging.getLogger("SecureAudit_SAST")


def ejecutar_sast_profesional(directorio_codigo):
    """
    Ejecuta Semgrep de forma segura y concurrente.
    """
    if not os.path.exists(directorio_codigo):
        logger.error(f"El directorio a analizar no existe: {directorio_codigo}")
        return []

    archivo_salida = os.path.join(directorio_codigo, "semgrep_results.json")

    comando = [
        "semgrep",
        "scan",
        "--config",
        "p/default",
        "--config",
        "p/security-audit",
        "--config",
        "p/secrets",
        "--config",
        "p/python",
        "--config",
        "p/owasp-top-ten",
        "--json",
        "--output",
        archivo_salida,
        "--quiet",
        "--no-git-ignore",
        directorio_codigo,
    ]

    logger.info(f"Iniciando escaneo SAST en: {directorio_codigo}")

    try:

        proceso = subprocess.run(comando, check=False, capture_output=True, text=True)

        if os.path.exists(archivo_salida):
            with open(archivo_salida, "r", encoding="utf-8") as f:
                try:
                    datos = json.load(f)
                except json.JSONDecodeError:
                    logger.error("Error crítico: Semgrep devolvió un JSON corrupto.")
                    return []

            os.remove(archivo_salida)

            hallazgos_limpios = []
            resultados = datos.get("results", [])

            for resultado in resultados:
                extra = resultado.get("extra", {})
                start = resultado.get("start", {})

                vuln = {
                    "vulnerabilidad": resultado.get("check_id", "Desconocida").split(
                        "."
                    )[-1],
                    "archivo": resultado.get("path", "Desconocido"),
                    "linea": start.get("line", 0),
                    "codigo_afectado": extra.get("lines", "No disponible"),
                    "severidad": extra.get("severity", "INFO"),
                    "mensaje": extra.get("message", "Sin descripción"),
                    "regla_semgrep": resultado.get("check_id", "Desconocida"),
                }
                hallazgos_limpios.append(vuln)

            logger.info(
                f"Escaneo SAST completado. Se encontraron {len(hallazgos_limpios)} vulnerabilidades."
            )
            return hallazgos_limpios

        else:
            logger.warning(
                f"Semgrep no generó el archivo JSON. Código de salida: {proceso.returncode}. Error: {proceso.stderr}"
            )
            return []

    except Exception as e:
        logger.error(f"Fallo al ejecutar el binario de Semgrep: {e}", exc_info=True)
        return []
