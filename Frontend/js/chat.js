/**
 * Lógica del Chat Legal con IA (Soporte ENS)
 * Conecta con el endpoint /chat y gestiona parámetros de inferencia.
 */

async function enviarMensaje() {
  
    const input = document.getElementById('chat-input');
    const history = document.getElementById('chat-history');
    
   
    const slider = document.querySelector('input[type="range"]');
    const tempValue = slider ? parseFloat(slider.value) : 0.0;

    
    const modelSelect = document.getElementById('model-select');
    const modelValue = modelSelect ? modelSelect.value : "llama3.1:8b";

    const txt = input.value.trim();
    if (!txt) return; 

   
    history.innerHTML += `
        <div class="message user">
            <div class="text">${txt}</div>
        </div>
    `;
    
   
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
      
        const res = await fetch('/chat',{
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
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
            .replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.3); padding:2px 5px; border-radius:4px; font-family:monospace;">$1</code>'); // Código inline

       
        document.getElementById(loadingId).outerHTML = `
            <div class="message bot">
                <div class="avatar"><i class="fas fa-robot"></i></div>
                <div class="text">${respuestaFormateada}</div>
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