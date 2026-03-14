let currentAuditData = null;
let chartRadar = null;
let chartDoughnut = null;


document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadHistory();
});


document.getElementById('upload-zone').onclick = () => document.getElementById('fileInput').click();
document.getElementById('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

   
    if (!file.name.toLowerCase().endsWith('.zip')) {
        alert("Formato incorrecto. Por favor, sube únicamente un archivo .zip");
        e.target.value = ''; 
        return; 
    }


    document.getElementById('upload-zone').style.display = 'none';
  
    const progressContainer = document.getElementById('progress-container');
    if(progressContainer) progressContainer.style.display = 'block';
    if(document.getElementById('spinner')) document.getElementById('spinner').style.display = 'none';
    
    document.getElementById('progress-text').innerText = "Subiendo archivo...";
    document.getElementById('progress-bar-fill').style.width = "5%";

    const formData = new FormData();
    formData.append('file', file);

    try {
   
       
        const token = localStorage.getItem('jwt_token');

      
        const res = await fetch('/auditar-zip', { 
            method: 'POST', 
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData 
        });

      
        if (res.status === 401) { cerrarSesion(); throw new Error("Sesión caducada"); }
        const data = await res.json();
        
        if (data.estado !== "Procesando") throw new Error("Error al iniciar");
        
        const auditId = data.audit_id;


        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/progreso/${auditId}`);
      
        ws.onopen = () => {
            document.getElementById('progress-text').innerText = "Conexión en vivo establecida. Esperando a la IA...";
        };

      
        ws.onmessage = async (event) => {
            const msg = JSON.parse(event.data);
            
          
            document.getElementById('progress-text').innerText = msg.mensaje;
            document.getElementById('progress-bar-fill').style.width = msg.progreso + '%';

         
            if (msg.progreso === 100) {
                ws.close(); 
                
                const resFinal = await fetch(`/auditoria/${auditId}`);
                const dataFinal = await resFinal.json();
                
                currentAuditData = dataFinal;
                processAuditResults(dataFinal);
                saveToHistory(file.name, dataFinal.total_vulnerabilidades);

                if(progressContainer) progressContainer.style.display = 'none';
                document.getElementById('audit-workspace').style.display = 'grid';
                document.getElementById('btn-export-pdf').style.display = 'inline-block';
                
            } else if (msg.progreso === -1) {
            
                ws.close();
                alert("Error en la auditoría: " + msg.mensaje);
                document.getElementById('upload-zone').style.display = 'block';
                progressContainer.style.display = 'none';
            }
        };

    } catch (e) {
        alert("Error de conexión: " + e);
        document.getElementById('upload-zone').style.display = 'block';
        if(progressContainer) progressContainer.style.display = 'none';
    }
});

function processAuditResults(data) {
   
    document.getElementById('stat-vuln').innerText = `${data.total_vulnerabilidades} Detectadas`;
    const score = Math.max(0, 100 - (data.total_vulnerabilidades * 5));
    document.getElementById('stat-score').innerText = `${score} / 100`;
    document.getElementById('stat-status').innerText = "Finalizado";
    document.getElementById('stat-status').style.color = "#10b981";

    
    const list = document.getElementById('findings-list');
    list.innerHTML = '';
    
    let severities = { ERROR: 0, WARNING: 0, INFO: 0 };

    data.resultados.forEach((item, idx) => {
        severities[item.severidad] = (severities[item.severidad] || 0) + 1;

        const div = document.createElement('div');
        div.className = `finding-item ${item.severidad}`;
        div.innerHTML = `
            <div style="display:flex; justify-content:space-between">
                <strong>${item.vulnerabilidad}</strong>
                <span style="font-size:0.8em; font-weight:bold">${item.severidad}</span>
            </div>
            <div style="font-size:0.8em; color:#94a3b8; margin-top:5px">
                <i class="far fa-file-code"></i> ${item.archivo.split('/').pop()}
            </div>
        `;
        div.onclick = () => showDetail(item, div);
        list.appendChild(div);
    });

    
    updateCharts(score, severities);
}

function showDetail(item, element) {
   
    document.querySelectorAll('.finding-item').forEach(e => e.classList.remove('active'));
    element.classList.add('active');

   
    let content = item.analisis_legal
        .replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--primary)">$1</strong>')
        .replace(/\|/g, '')
        .replace(/SOLUCIÓN TÉCNICA/g, '<h4 style="color:var(--success); margin-top:20px">Solución Técnica</h4>')
        .replace(/Incumplimiento ENS/g, '<h4 style="color:var(--danger)">Incumplimiento ENS</h4>');

    document.getElementById('finding-detail').innerHTML = `
        <h2 style="color:var(--accent); border-bottom:1px solid #333; padding-bottom:10px;">${item.vulnerabilidad}</h2>
        <div style="font-family:monospace; background:#0f172a; padding:10px; border-radius:5px; margin:10px 0;">
            ${item.archivo}
        </div>
        <div>${content}</div>
    `;
}


function initCharts() {
    const ctxRadar = document.getElementById('radarChart').getContext('2d');
    chartRadar = new Chart(ctxRadar, {
        type: 'radar',
        data: {
            labels: ['Confidencialidad', 'Integridad', 'Trazabilidad', 'Autenticidad', 'Disponibilidad'],
            datasets: [{
                label: 'Nivel de Cumplimiento',
                data: [0,0,0,0,0], 
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderColor: '#3b82f6',
                borderWidth: 2,
                pointBackgroundColor: '#fff'
            }]
        },
        options: {
            scales: { 
                r: { 
                    angleLines: { color: '#334155' }, 
                    grid: { color: '#334155' }, 
                    suggestMin: 0, 
                    suggestMax: 100, 
                    ticks: { display: false },
                  
                    pointLabels: { 
                        color: '#ffffff', 
                        font: { size: 14, weight: 'bold' } 
                    }
                } 
            },
            plugins: { legend: { display: false } }
        }
    });

    const ctxDoughnut = document.getElementById('doughnutChart').getContext('2d');
    chartDoughnut = new Chart(ctxDoughnut, {
        type: 'doughnut',
        data: {
            labels: ['Crítico (High)', 'Medio (Med)', 'Bajo (Low)'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'],
                borderWidth: 0
            }]
        },
        options: { cutout: '70%', plugins: { legend: { position: 'right', labels: { color: '#fff' } } } }
    });
}

function updateCharts(score, severities) {
   
    chartRadar.data.datasets[0].data = [score, score-10, score+5, score-5, score];
    chartRadar.update();

    chartDoughnut.data.datasets[0].data = [severities.ERROR || 0, severities.WARNING || 0, severities.INFO || 0];
    chartDoughnut.update();
}



async function generarPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
   
    const colorPrimary = [59, 130, 246]; // Azul
    const colorDanger = [239, 68, 68];  // Rojo
    const colorDark = [15, 23, 42];     // Azul oscuro
    
 
  
    doc.setFillColor(...colorDark);
    doc.rect(0, 0, 210, 40, 'F');
    
 
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.setTextColor(255, 255, 255);
    doc.text("INFORME DE AUDITORÍA TÉCNICO-LEGAL", 105, 20, { align: "center" });
    doc.setFontSize(12);
    doc.text("Cumplimiento Esquema Nacional de Seguridad (ENS)", 105, 30, { align: "center" });
    
   
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.text(`ID Auditoría: ${currentAuditData.id_auditoria || 'N/A'}`, 14, 50);
    doc.text(`Fecha de Emisión: ${new Date().toLocaleString()}`, 14, 55);
    
    
    const score = Math.max(0, 100 - (currentAuditData.total_vulnerabilidades * 5));
    doc.autoTable({
        startY: 65,
        head: [['Métrica', 'Resultado']],
        body: [
            ['Total Hallazgos', currentAuditData.total_vulnerabilidades],
            ['Puntuación de Seguridad', `${score}/100`],
            ['Estado del Sistema', score > 50 ? 'APROBADO (Con Riesgos)' : 'CRÍTICO'],
            ['Modelo IA Utilizado', 'Llama 3.2 (Quantized 4-bit) Local']
        ],
        theme: 'striped',
        headStyles: { fillColor: colorPrimary },
        styles: { fontSize: 11 }
    });
    
   
    doc.setFontSize(14);
    doc.setTextColor(...colorPrimary);
    doc.text("Detalle de Vulnerabilidades y Análisis Normativo", 14, doc.lastAutoTable.finalY + 15);
    
    let yPos = doc.lastAutoTable.finalY + 20;

    currentAuditData.resultados.forEach((item, index) => {
       
        doc.setFontSize(12);
        doc.setTextColor(...colorDanger);
        doc.setFont("helvetica", "bold");
        
      
        if (yPos > 250) { doc.addPage(); yPos = 20; }
        
        doc.text(`${index + 1}. ${item.vulnerabilidad.toUpperCase()} [${item.severidad}]`, 14, yPos);
        

        const cleanAnalysis = item.analisis_legal
            .replace(/\|/g, '')
            .replace(/\*\*/g, '')
            .replace(/Incumplimiento ENS/g, '\n[INCUMPLIMIENTO ENS]')
            .replace(/SOLUCIÓN TÉCNICA/g, '\n[SOLUCIÓN TÉCNICA]');

        doc.autoTable({
            startY: yPos + 5,
            body: [
                [{ content: 'Archivo Afectado:', styles: { fontStyle: 'bold', cellWidth: 40 } }, item.archivo.split('/').pop()],
                [{ content: 'Análisis IA:', styles: { fontStyle: 'bold' } }, cleanAnalysis]
            ],
            theme: 'grid',
            styles: { fontSize: 9, cellPadding: 4 },
            columnStyles: { 0: { fillColor: [240, 240, 240] } },
            margin: { left: 14, right: 14 }
        });
        
        yPos = doc.lastAutoTable.finalY + 15;
    });
    
  
    const pageCount = doc.internal.getNumberOfPages();
    for(let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150);
        doc.text(`Página ${i} de ${pageCount} - Generado por SecureAudit AI (Soberanía Local)`, 105, 290, { align: "center" });
    }

    doc.save("Informe_Oficial_ENS.pdf");
}



function saveToHistory(fileName, count) {
    loadHistory(); 
}


async function loadHistory() {
    try {
    
        const token = localStorage.getItem('jwt_token');
        
      
        const res = await fetch('/historial', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
     
        if (res.status === 401) {
            return;
        }

        const history = await res.json();
        
        const container = document.getElementById('history-list');
        
     
        if (!history || history.length === 0) {
            container.innerHTML = '<div style="font-size: 0.85em; color: var(--text-muted); text-align: center; margin-top: 10px;">Tu historial está vacío.</div>';
            return;
        }
        
        container.innerHTML = '';
        history.forEach(h => {

        const div = document.createElement('div');
        div.className = 'history-item';
        div.style.cursor = 'pointer'; 
        
    
        div.onclick = () => cargarAuditoriaPasada(h.id); 
        
        div.innerHTML = `
            <div style="font-size: 0.8em; color: var(--text-muted);">${h.fecha}</div>
            <div style="font-weight: 600;">${h.nombre_archivo}</div>
            <div style="font-size: 0.8em; color: var(--primary);"><i class="fas fa-eye"></i> Ver Resultados</div>
        `;
        container.appendChild(div);
        });
    } catch (e) {
        console.error("Error cargando historial de la BD:", e);
    }
}


function resetAuditoria() {
    const progressContainer = document.getElementById('progress-container');
    if(progressContainer) progressContainer.style.display = 'none';
    
 
    const resultsContainer = document.getElementById('results-container');
    const findingsSection = document.querySelector('.findings-section');
    const chartsGrid = document.querySelector('.charts-grid');
    
    if(resultsContainer) resultsContainer.style.display = 'none';
    if(findingsSection) findingsSection.style.display = 'none';
    if(chartsGrid) chartsGrid.style.display = 'none';
    
    const uploadZone = document.getElementById('upload-zone');
    if (uploadZone) uploadZone.style.display = 'flex';
    
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
    
    const progressBar = document.getElementById('progress-bar-fill');
    if (progressBar) progressBar.style.width = '0%';
    
    const progressText = document.getElementById('progress-text');
    if (progressText) progressText.innerText = 'Preparando...';
}


async function cargarAuditoriaPasada(auditId) {
    try {
        const token = localStorage.getItem('jwt_token');
        
        if (typeof navigate === 'function') navigate('audit');
        
        const uploadZone = document.getElementById('upload-zone');
        if (uploadZone) uploadZone.style.display = 'none';
        
        const progressContainer = document.getElementById('progress-container');
        if(progressContainer) progressContainer.style.display = 'block';
        
        const progressText = document.getElementById('progress-text');
        if (progressText) progressText.innerText = "Recuperando auditoría de la bóveda...";
        
        const progressBar = document.getElementById('progress-bar-fill');
        if (progressBar) progressBar.style.width = "100%";
        
        const res = await fetch(`/auditoria/${auditId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.status === 401) { cerrarSesion(); return; }
        if (!res.ok) throw new Error("No se pudo cargar la auditoría");
        
        const data = await res.json();
        currentAuditData = data; 
        
        if(progressContainer) progressContainer.style.display = 'none';
        
       
        const workspace = document.getElementById('audit-workspace');
        if (workspace) workspace.style.display = 'block';

     
        const findingsList = document.getElementById('findings-list');
        const findingDetail = document.getElementById('finding-detail');

        if (findingsList && findingDetail) {
            findingsList.innerHTML = '';
            
           
            findingDetail.innerHTML = `
                <p style="color: var(--text-muted); text-align: center; margin-top: 80px;">
                    <i class="fas fa-hand-pointer" style="font-size: 2rem; margin-bottom: 10px; display: block;"></i>
                    Selecciona una vulnerabilidad de la lista izquierda para ver el diagnóstico legal y la solución técnica.
                </p>
            `;
            
            let criticas = 0, medias = 0, bajas = 0;

            data.resultados.forEach((v) => {

                const sev = (v.severidad || "").toString().toUpperCase().trim();

                let colorBase = 'var(--success)'; 
                let icono = 'fa-check-circle';

              
                if (sev.includes('ERROR') || sev.includes('ALTA') || sev.includes('ALTO') || sev.includes('HIGH') || sev.includes('CRITIC')) {
                    criticas++;
                    colorBase = 'var(--danger)'; 
                    icono = 'fa-exclamation-triangle';
                } 
                else if (sev.includes('WARNING') || sev.includes('MEDIA') || sev.includes('MEDIO') || sev.includes('MEDIUM') || sev.includes('MODERAD')) {
                    medias++;
                    colorBase = 'var(--warning)'; 
                    icono = 'fa-exclamation-circle';
                } 
                else {
                    bajas++;
                
                }


      
                const item = document.createElement('div');
                item.style.padding = '12px';
                item.style.marginBottom = '10px';
                item.style.background = 'var(--bg-panel)';
                item.style.border = '1px solid var(--border)';
                item.style.borderLeft = `4px solid ${colorBase}`;
                item.style.borderRadius = '6px';
                item.style.cursor = 'pointer';
                item.style.transition = 'all 0.2s ease';
                
                item.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 5px; font-size: 0.95em;">${v.vulnerabilidad}</div>
                    <div style="font-size: 0.8em; color: var(--text-muted);"><i class="fas ${icono}" style="color: ${colorBase}"></i> ${v.severidad.toUpperCase()}</div>
                `;

              
                item.onclick = () => {
                   
                    Array.from(findingsList.children).forEach(c => c.style.background = 'var(--bg-panel)');
                    item.style.background = 'rgba(255, 255, 255, 0.05)'; 

                   
                    findingDetail.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                            <span style="background: ${colorBase}; color: white; padding: 5px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em;">
                                ${v.severidad.toUpperCase()}
                            </span>
                            <h3 style="margin: 0; color: var(--text-main); font-size: 1.1em;">${v.vulnerabilidad}</h3>
                        </div>
                        
                        <div style="margin-bottom: 20px;">
                            <h4 style="color: var(--text-muted); margin-bottom: 8px; font-size: 0.85em;">ARCHIVO AFECTADO:</h4>
                            <code style="background: var(--bg-card); padding: 8px 12px; border-radius: 6px; display: block; color: var(--primary); border: 1px solid var(--border); font-family: 'JetBrains Mono', monospace;">
                                ${v.archivo}
                            </code>
                        </div>

                        <div>
                            <h4 style="color: var(--text-muted); margin-bottom: 8px; font-size: 0.85em;">ANÁLISIS LEGAL / TÉCNICO:</h4>
                            <div style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 6px; line-height: 1.6; font-size: 0.95em; border-left: 2px solid var(--border);">
                                ${v.analisis_legal}
                            </div>
                        </div>
                    `;
                };

                findingsList.appendChild(item);
            });

           
            const statVuln = document.getElementById('stat-vuln');
            if(statVuln) statVuln.innerText = `${data.total_vulnerabilidades} Detectadas`;
            
            const statStatus = document.getElementById('stat-status');
            if(statStatus) statStatus.innerText = "Historial Recuperado";

            if (typeof chartDoughnut !== 'undefined' && chartDoughnut !== null) {
                chartDoughnut.data.datasets[0].data = [criticas, medias, bajas];
                chartDoughnut.update();
            }
            if (typeof chartRadar !== 'undefined' && chartRadar !== null) {
                chartRadar.data.datasets[0].data = [
                    criticas > 0 ? criticas * 10 : 10, 
                    medias > 0 ? medias * 15 : 20, 
                    bajas > 0 ? bajas * 20 : 30, 
                    criticas + medias, 
                    (criticas + medias + bajas) * 5
                ];
                chartRadar.update();
            }

            
            const btnPdf = document.getElementById('btn-export-pdf');
            if (btnPdf) btnPdf.style.display = 'inline-block';
        }
        
    } catch (e) {
        console.error(e);
        alert("Error al cargar el historial: " + e.message);
    }
}