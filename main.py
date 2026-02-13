import sys
import json
from Src.sast_scanner import ejecutar_sast_profesional
from Src.orquestador import app

def iniciar_auditoria(ruta_carpeta):
    # 1. Ejecutamos el Ojo Técnico (Semana 3)
    print("="*60)
    print(f"SISTEMA DE AUDITORÍA AUTOMATIZADA ENS - INICIANDO")
    print("="*60)
    
    hallazgos = ejecutar_sast_profesional(ruta_carpeta)
    
    if not hallazgos:
        print("No se detectaron vulnerabilidades. El código parece cumplir con los estándares técnicos.")
        return

    # 2. Iniciamos el Cerebro Multi-Agente (Semana 4 y 5)
    print(f"\nSe han detectado {len(hallazgos)} fallos. Procesando con Agentes IA...")
    
    # Le pasamos todos los hallazgos al orquestador
    # (Por ahora procesamos el primero para no saturar, luego lo haremos en bucle)
    resultado = app.invoke({"hallazgos_tecnicos": hallazgos})
    
    # 3. Resultado Final
    print("\n" + "#"*60)
    print("INFORME DE CUMPLIMIENTO LEGAL (ENS)")
    print("#"*60)
    print(resultado['veredicto_final'])

if __name__ == "__main__":
    ruta = "D:/TFG_Ciberseguridad/codigo_prueba"
    iniciar_auditoria(ruta)