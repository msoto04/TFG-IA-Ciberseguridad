/**
 * Lógica del Chat Legal con IA (Soporte ENS)
 * Conecta con el endpoint /chat y gestiona parámetros de inferencia.
 */

async function enviarMensaje() {
    // 1. Referencias al DOM
    const input = document.getElementById('chat-input');
    const history = document.getElementById('chat-history');
    
    // 2. LEER CONFIGURACIÓN (Temperatura y Modelo)
    // Buscamos el slider en el modal de configuración.
    const slider = document.querySelector('input[type="range"]');
    const tempValue = slider ? parseFloat(slider.value) : 0.0;

    // --- NUEVO: Capturar el modelo del selector ---
    const modelSelect = document.getElementById('model-select');
    const modelValue = modelSelect ? modelSelect.value : "llama3.1:8b";

    const txt = input.value.trim();
    if (!txt) return; // No enviar si está vacío

    // 3. Renderizar mensaje del USUARIO
    history.innerHTML += `
        <div class="message user">
            <div class="text">${txt}</div>
        </div>
    `;
    
    // Limpiar input y bajar scroll
    input.value = '';
    history.scrollTop = history.scrollHeight;

    // 4. Renderizar estado "PENSANDO..." (Placeholder)
    // Usamos un ID único para luego reemplazar este bloque con la respuesta real
    const loadingId = 'load-' + Date.now();
    history.innerHTML += `
        <div class="message bot" id="${loadingId}">
            <div class="text">
                <i class="fas fa-circle-notch fa-spin"></i> 
                <span style="font-size: 0.9em; opacity: 0.8;">Consultando a ${modelValue} (Creatividad: ${tempValue})...</span>
            </div>
        </div>
    `;
    history.scrollTop = history.scrollHeight;

    try {
        // 5. LLAMADA A LA API (BACKEND)
        const res = await fetch('http://localhost:8000/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                mensaje: txt,
                temperature: tempValue, // <--- Temperatura
                modelo: modelValue      // <--- NUEVO: EL MODELO ELEGIDO
            })
        });

        if (!res.ok) throw new Error("Error en la respuesta del servidor");

        const data = await res.json();
        
        // 6. FORMATEO DE TEXTO (Markdown a HTML)
        // Llama 3 usa markdown (**negrita**, `código`). Lo convertimos para que se vea bien.
        let respuestaFormateada = data.respuesta
            .replace(/\n/g, '<br>') // Saltos de línea
            .replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--primary)">$1</strong>') // Negritas azules
            .replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.3); padding:2px 5px; border-radius:4px; font-family:monospace;">$1</code>'); // Código inline

        // 7. Reemplazar el mensaje de carga con la respuesta final
        document.getElementById(loadingId).outerHTML = `
            <div class="message bot">
                <div class="avatar"><i class="fas fa-robot"></i></div>
                <div class="text">${respuestaFormateada}</div>
            </div>
        `;

    } catch (e) {
        console.error(e);
        // Mostrar error visual en el chat
        document.getElementById(loadingId).innerHTML = `
            <div class="text" style="border: 1px solid var(--danger); color: var(--danger); background: rgba(239, 68, 68, 0.1);">
                <i class="fas fa-exclamation-triangle"></i> Error: El servidor Docker no responde o el modelo está apagado.
            </div>
        `;
    }

    // Asegurar que el scroll esté abajo
    history.scrollTop = history.scrollHeight;
}

// 8. Evento para enviar con la tecla ENTER
document.getElementById('chat-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        enviarMensaje();
    }
});