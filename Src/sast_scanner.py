import subprocess
import json
import os
import sys

def ejecutar_sast_profesional(directorio_codigo):
    """
    Ejecuta Semgrep usando la configuración 'default' (Seguridad + Secretos + Calidad).
    """
    
    if not os.path.exists(directorio_codigo):
        print(f"[ERROR SAST] El directorio no existe: {directorio_codigo}")
        return []

    archivo_salida = "semgrep_results.json"
    
    comando = [
        "semgrep", "scan",
        "--config", "p/default", 
        
        "--json",             
        "--output", archivo_salida,
        "--quiet",            
        "--no-git-ignore",    
        directorio_codigo
    ]
    
    try:
        subprocess.run(comando, check=False) 
        
        if os.path.exists(archivo_salida):
            with open(archivo_salida, "r") as f:
                datos = json.load(f)
            
            os.remove(archivo_salida)
            
            hallazgos_limpios = []
            
            for resultado in datos.get("results", []):
                vuln = {
                
                    "vulnerabilidad": resultado["check_id"].split(".")[-1], 
                    "archivo": resultado["path"],
                    "linea": resultado["start"]["line"],
                    "codigo_afectado": resultado["extra"]["lines"],
                    "severidad": resultado["extra"]["severity"],
                    "mensaje": resultado["extra"]["message"]
                }
                hallazgos_limpios.append(vuln)
                
            return hallazgos_limpios
            
        else:
            return []

    except Exception as e:
        print(f"[ERROR SAST] Fallo al ejecutar Semgrep: {e}")
        return []