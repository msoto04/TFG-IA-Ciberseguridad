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