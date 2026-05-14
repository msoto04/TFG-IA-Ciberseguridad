/**
 * Lógica del Chat Legal con IA (Soporte ENS)
 * Conecta con el endpoint /chat y gestiona parámetros de inferencia.
 */

async function enviarMensaje() {
  
    const input = document.getElementById('chat-input');
    const history = document.getElementById('chat-history');
    
   
    const slider = document.querySelector('input[type="range"]');
    const tempValue = slider ? parseFloat(slider.value) : 0.0;

    
    const modelValue = window.modeloIA || (document.getElementById('model-select') ? document.getElementById('model-select').value : "llama3:8b");

    const txt = input.value.trim();
    if (!txt) return; 

   
  
    const userMsgDiv = document.createElement('div');
    userMsgDiv.className = 'message user';
    
    // Crear contenedor del texto de forma segura
    const textDiv = document.createElement('div');
    textDiv.className = 'text';
    textDiv.textContent = txt; 
    
   
    userMsgDiv.appendChild(textDiv);
    history.appendChild(userMsgDiv);
    
   
    input.value = '';
    history.scrollTop = history.scrollHeight;

    
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
      
        const res = await fetch('http://localhost:8000/chat',{
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({
                mensaje: txt,
                temperature: tempValue, 
                modelo: modelValue     
            })
        });

        if (!res.ok) throw new Error("Error en la respuesta del servidor");

        const data = await res.json();
        
     
      
        let respuestaFormateada = data.respuesta
            .replace(/\n/g, '<br>') 
            .replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--primary)">$1</strong>') 
            .replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.3); padding:2px 5px; border-radius:4px; font-family:monospace;">$1</code>');

    
        if (data.fuentes && data.fuentes.length > 0) {
            let htmlFuentes = `
                <div style="margin-top: 15px; font-size: 0.85em; background-color: rgba(0, 242, 254, 0.05); border-left: 3px solid #00f2fe; padding: 10px; border-radius: 4px;">
                    <strong style="color: #00f2fe;"><i class="fas fa-book-open"></i> Fuentes normativas consultadas:</strong>
                    <ul style="margin-top: 8px; margin-bottom: 0; padding-left: 20px; color: #bbb;">
            `;
            
            data.fuentes.forEach(fuente => {
                htmlFuentes += `
                    <li style="margin-bottom: 8px;">
                        <strong style="color: #ddd;">${fuente.origen} (Pág. ${fuente.pagina})</strong><br>
                        <i style="color: #888;">"${fuente.fragmento.trim()}"</i>
                    </li>
                `;
            });
            
            htmlFuentes += `</ul></div>`;
            respuestaFormateada += htmlFuentes;
        }
  
        const respuestaSegura = DOMPurify.sanitize(respuestaFormateada);

        document.getElementById(loadingId).outerHTML = `
            <div class="message bot">
                <div class="avatar"><i class="fas fa-robot"></i></div>
                <div class="text">${respuestaSegura}</div>
            </div>
        `;

    } catch (e) {
        console.error(e);
      
        document.getElementById(loadingId).innerHTML = `
            <div class="text" style="border: 1px solid var(--danger); color: var(--danger); background: rgba(239, 68, 68, 0.1);">
                <i class="fas fa-exclamation-triangle"></i> Error: El servidor Docker no responde o el modelo está apagado.
            </div>
        `;
    }

    
    history.scrollTop = history.scrollHeight;
}


document.getElementById('chat-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        enviarMensaje();
    }
});