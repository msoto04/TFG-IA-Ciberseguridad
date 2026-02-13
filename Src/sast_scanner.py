import subprocess
import json
import sys
import os

def ejecutar_sast_profesional(directorio_a_escanear):
    """
    Cumple con el hito: 'Módulo de Escaneo de Directorios' 
    y 'Estructuración de Hallazgos' para el Agente Técnico.
    """
    if not os.path.isdir(directorio_a_escanear):
        print(f"Error: La ruta {directorio_a_escanear} no es un directorio válido.")
        return None

    print(f"[*] Analizando directorio: {directorio_a_escanear}")
    
    # Comando Semgrep:
    # --json: Para obtener el JSON limpio que pide el TFG.
    # --config=auto: Para detectar múltiples tipos de fallos (SQLi, Passwords, etc).
    # --no-git-ignore: Para que lea todo el contenido descomprimido.
    comando = [
        "semgrep", "scan", 
        "--config=auto", 
        "--json", 
        "--no-git-ignore",
        directorio_a_escanear
    ]

    try:
        # Ejecución y captura de salida
        proceso = subprocess.run(comando, capture_output=True, text=True, encoding='utf-8')
        raw_json = json.loads(proceso.stdout)
        
        hallazgos_finales = []

        # Filtrado técnico: Solo "High" (ERROR) y "Medium" (WARNING)
        for f in raw_json.get("results", []):
            severidad = f["extra"]["severity"]
            
            if severidad in ["ERROR", "WARNING"]:
                # Estructuración exacta para el Agente Técnico
                resumen = {
                    "vulnerabilidad": f["extra"]["metadata"].get("shortlink", f["check_id"]),
                    "descripcion": f["extra"]["message"],
                    "archivo": os.path.basename(f["path"]),
                    "linea": f["start"]["line"],
                    "codigo_afectado": f["extra"]["lines"].strip(),
                    "severidad": "High" if severidad == "ERROR" else "Medium"
                }
                hallazgos_finales.append(resumen)

        return hallazgos_finales

    except Exception as e:
        print(f"Error crítico en el escaneo: {e}")
        return []

if __name__ == "__main__":
    # Si el usuario pasa una ruta por terminal, la usamos. Si no, la de prueba.
    ruta_test = sys.argv[1] if len(sys.argv) > 1 else "D:/TFG_Ciberseguridad/codigo_prueba"
    
    resultados = ejecutar_sast_profesional(ruta_test)
    
    if resultados:
        print(f"\n[+] Auditoría completada. {len(resultados)} vulnerabilidades detectadas.")
        # Esto es lo que recibirá el Agente Técnico
        print("\n--- RESUMEN PARA EL AGENTE TÉCNICO ---")
        print(json.dumps(resultados, indent=4))
    else:
        print("\n[-] No se encontraron fallos críticos.")