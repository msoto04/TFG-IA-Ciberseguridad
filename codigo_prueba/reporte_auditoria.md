# INFORME TÉCNICO-LEGAL DE SEGURIDAD (ENS)
**Fecha:** Tue Feb 17 08:34:48 UTC 2026
**Directorio:** /app/auditoria

### HALLAZGO 1: subprocess-injection
*Archivo: /app/auditoria/vulnerable.py (Línea 20)*
*Tiempos: Técnico (62.04s), Legal (67.27s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | subprocess-injection |
| **Incumplimiento ENS** | [op.pl.2.r3.1] Controles técnicos internos, incluyendo la validación de datos de entrada, salida y datos intermedios. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar parámetros en lugar de concatenar strings para evitar la inyección de código. Por ejemplo, en lugar de `command = "echo " + input + ";", utilizar `command = ["echo", input];`. Esto evita que un atacante pueda inyectar código y ejecutar comandos arbitrarios.
----------------------------------------

### HALLAZGO 2: dangerous-subprocess-use
*Archivo: /app/auditoria/vulnerable.py (Línea 20)*
*Tiempos: Técnico (59.02s), Legal (56.25s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | dangerous-subprocess-use |
| **Incumplimiento ENS** | [op.pl.2.r3.1] Controles técnicos internos, incluyendo la validación de datos de entrada, salida y datos intermedios. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar parámetros en lugar de concatenar strings para evitar vulnerabilidades de inyección SQL o de código malicioso. Por ejemplo, en lugar de `system("ls -l " . $input);`, utilizar `system("ls -l", $input);`. Esto garantiza que el comando sea ejecutado con los parámetros correctos y no permita la inyección de código malicioso.
----------------------------------------

### HALLAZGO 3: subprocess-shell-true
*Archivo: /app/auditoria/vulnerable.py (Línea 20)*
*Tiempos: Técnico (62.76s), Legal (55.25s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | subprocess-shell-true |
| **Incumplimiento ENS** | [op.pl.2.r3.1] Controles técnicos internos, incluyendo la validación de datos de entrada, salida y datos intermedios. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar `subprocess.run()` con parámetros en lugar de concatenar strings para evitar comandos arbitrarios. Por ejemplo: `subprocess.run(['command', 'param1', 'param2'])` en lugar de `subprocess.call('command "param1" "param2"')`. Esto garantiza que los comandos se ejecuten de manera segura y controlada.
----------------------------------------

### HALLAZGO 4: insecure-deserialization
*Archivo: /app/auditoria/vulnerable.py (Línea 43)*
*Tiempos: Técnico (64.54s), Legal (58.72s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | insecure-deserialization |
| **Incumplimiento ENS** | [mp.info.6.r2.1] Al menos, una de las copias de seguridad se almacenará de forma separada en lugar diferente, de tal manera que un incidente no pueda afectar tanto al repositorio original como a la copia simultáneamente |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar bibliotecas de deserialization seguras y actualizadas, y validar adecuadamente los datos de deserialización para evitar inyecciones de código arbitrario.
----------------------------------------

### HALLAZGO 5: avoid-pickle
*Archivo: /app/auditoria/vulnerable.py (Línea 43)*
*Tiempos: Técnico (89.15s), Legal (65.53s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | avoid-pickle |
| **Incumplimiento ENS** | op.pl.2.r3.1: Controles técnicos internos, incluyendo la validación de datos de entrada, salida y datos intermedios. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar parámetros en lugar de concatenar strings para evitar problemas de serialización y deserialización de objetos. Por ejemplo, en lugar de `username = req.body.username + password`, utilizar `const username = req.body.username; const password = req.body.password;`. Esto garantiza que los datos se validen correctamente antes de ser utilizados en la aplicación.
----------------------------------------

### HALLAZGO 6: directly-returned-format-string
*Archivo: /app/auditoria/vulnerable.py (Línea 44)*
*Tiempos: Técnico (87.47s), Legal (65.67s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | directly-returned-format-string |
| **Incumplimiento ENS** | Artículo 4. Definiciones, específicamente la categoría BÁSICA de op.pl.2, que establece la importancia de la validación de datos y la protección de la integridad de los sistemas. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Utilizar parámetros en lugar de concatenar strings para evitar la manipulación de salida, por ejemplo: `Console.WriteLine($"Hola, {userName}");` se convierte en `Console.WriteLine($"Hola, {getUserName()}");`, asegurando que el valor del usuario sea seguro y no permita la ejecución de código malicioso.
----------------------------------------

### HALLAZGO 7: debug-enabled
*Archivo: /app/auditoria/vulnerable.py (Línea 52)*
*Tiempos: Técnico (53.13s), Legal (49.75s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | debug-enabled |
| **Incumplimiento ENS** | [op.pl.2.r3.1] Controles técnicos internos, incluyendo la validación de datos de entrada, salida y datos intermedios. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Desactivar el debug-enabled cuando no sea necesario o utilizar herramientas de seguridad adicionales para proteger la información confidencial. Por ejemplo, se puede utilizar un mecanismo de autenticación y integridad para validar los datos de entrada y salida antes de procesarlos.
----------------------------------------

### HALLAZGO 8: avoid_app_run_with_bad_host
*Archivo: /app/auditoria/vulnerable.py (Línea 55)*
*Tiempos: Técnico (49.05s), Legal (64.33s)*

| Campo | Detalle |
| :--- | :--- |
| **Vulnerabilidad** | avoid_app_run_with_bad_host |
| **Incumplimiento ENS** | [op.exp.4.r2.1] Antes de la aplicación de las configuraciones, parches y actualizaciones de seguridad se preverá un mecanismo para revertirlos en caso de aparición de efectos adversos. |
| **Nivel de Riesgo** | Alto |
| **SOLUCIÓN TÉCNICA** | Verificar la configuración del certificado SSL/TLS y asegurarse de que la dirección host esté configurada correctamente en el archivo `Info.plist`. También se puede intentar ejecutar el aplicativo con una dirección host diferente. |

Nota: La solución técnica propuesta es solo un ejemplo y puede variar dependiendo de las especificaciones del proyecto y del código existente. Es importante realizar una evaluación detallada de la vulnerabilidad y desarrollar una solución adecuada para cada caso específico.
----------------------------------------

