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

document.addEventListener('DOMContentLoaded', checkAuth);


function checkAuth() {
    const token = localStorage.getItem('jwt_token');
    if (token) {
        document.getElementById('login-overlay').style.display = 'none'; 
    } else {
        document.getElementById('login-overlay').style.display = 'flex'; 
    }
}

// Alternar entre pantalla de Login y Registro
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
        const res = await fetch('/registro', {
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
            msgBox.innerText = data.detail || "Error al registrar";
        }
    } catch (e) { msgBox.innerText = "Error de conexión"; }
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
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (res.ok) {
            localStorage.setItem('jwt_token', data.access_token);
            document.getElementById('login-overlay').style.display = 'none';
            if (typeof loadHistory === 'function') loadHistory();
        } else {
            msgBox.style.color = "var(--danger)";
            msgBox.innerText = data.detail || "Credenciales incorrectas";
        }
    } catch (e) { msgBox.innerText = "Error de conexión"; }
}

function cerrarSesion() {
    localStorage.removeItem('jwt_token'); 
    checkAuth(); 
}