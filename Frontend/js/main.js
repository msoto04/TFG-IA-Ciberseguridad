function navigate(view) {
    document.querySelectorAll('.section-view').forEach(e => e.classList.remove('active'));
    document.getElementById('view-' + view).classList.add('active');
    
    document.querySelectorAll('.nav-item').forEach(e => e.classList.remove('active'));
  
    if(view === 'home') document.querySelectorAll('.nav-item')[0].classList.add('active');
    if(view === 'audit') document.querySelectorAll('.nav-item')[1].classList.add('active');
    if(view === 'chat') document.querySelectorAll('.nav-item')[2].classList.add('active');
    
    document.getElementById('page-title').innerText = view === 'home' ? 'Dashboard General' : (view === 'audit' ? 'Auditoría Técnica' : 'Consultor Legal');
}

function toggleSettings() {
    const modal = document.getElementById('settings-modal');
    modal.style.display = modal.style.display === 'flex' ? 'none' : 'flex';
}


function toggleAuth() {
    const boxLogin = document.getElementById('box-login');
    const boxReg = document.getElementById('box-registro');
    if (boxLogin.style.display === 'none') {
        boxLogin.style.display = 'block';
        boxReg.style.display = 'none';
    } else {
        boxLogin.style.display = 'none';
        boxReg.style.display = 'block';
    }
}

document.addEventListener('DOMContentLoaded', checkAuth);


async function checkAuth() {
    try {
   
        const res = await fetch('http://localhost:8000/historial', { credentials: 'include' });
        
        if (res.ok) {
      
            document.getElementById('login-overlay').style.display = 'none'; 
        } else {
         
            document.getElementById('login-overlay').style.display = 'flex'; 
        }
    } catch (e) {
    
        document.getElementById('login-overlay').style.display = 'flex'; 
    }
}

async function registrarUsuario() {
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;
    const msgBox = document.getElementById('reg-msg');
    
    if (!email || !password) {
        msgBox.style.color = "var(--warning)";
        msgBox.innerText = "Por favor, rellena todos los campos.";
        return;
    }
    
    try {
        const res = await fetch('http://localhost:8000/registro', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        
        if (res.ok) {
            msgBox.style.color = "var(--success)";
            msgBox.innerText = "¡Registrado! Ahora haz clic en 'Inicia sesión'.";
        } else {
            msgBox.style.color = "var(--danger)";
            
            
            if (Array.isArray(data.detail)) {
                msgBox.innerText = "Error de formato: " + data.detail[0].msg;
            } else {
                msgBox.innerText = data.detail || "Error al registrar";
            }
      
        }
    } catch (e) { 
        msgBox.style.color = "var(--danger)"; 
        msgBox.innerText = "Error de conexión"; 
    }
}

async function iniciarSesion() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const msgBox = document.getElementById('login-msg');
    
    if (!email || !password) {
        msgBox.style.color = "var(--warning)";
        msgBox.innerText = "Por favor, rellena todos los campos.";
        return;
    }
    
    try {
        const res = await fetch('http://localhost:8000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include', 
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        
        if (res.ok) {
            document.getElementById('login-overlay').style.display = 'none';
            if (typeof loadHistory === 'function') loadHistory();
        } else {
            msgBox.style.color = "var(--danger)";
            
            if (Array.isArray(data.detail)) {
                msgBox.innerText = "Error de formato: " + data.detail[0].msg;
            } else {
               
                msgBox.innerText = data.detail || "Credenciales incorrectas";
            }
        }
    } catch (e) { 
        msgBox.style.color = "var(--danger)";
        msgBox.innerText = "Error de conexión"; 
    }
}


async function cerrarSesion() {
    try {
      
        await fetch('http://localhost:8000/logout', { 
            method: 'POST', 
            credentials: 'include' 
        });
        
   
        document.getElementById('login-overlay').style.display = 'flex';
        
   
        window.location.reload();
    } catch (e) {
        console.error("Error al cerrar sesión", e);
    }
}

function guardarConfigIA() {
    const modelo = document.getElementById('model-select').value;
    const temperatura = document.querySelector('input[type="range"]').value;
    
    // Guardar en variables globales accesibles por audit.js y chat.js
    window.modeloIA = modelo;
    window.temperaturaIA = parseFloat(temperatura);
    
    toggleSettings();
    
    // Feedback visual
    const btn = document.querySelector('.btn-primary');
    const textoOriginal = btn.innerText;
    btn.innerText = '✓ Guardado';
    btn.style.background = 'var(--success)';
    setTimeout(() => {
        btn.innerText = textoOriginal;
        btn.style.background = '';
    }, 1500);
}