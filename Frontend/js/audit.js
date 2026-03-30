let currentAuditData = null;
let chartRadar = null; // Para el Dashboard
let chartDoughnut = null; // Para el Dashboard
let auditChartRadar = null; // Para la vista de Auditoría
let auditChartDoughnut = null; // Para la vista de Auditoría


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
        
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/progreso/${auditId}?token=${token}`);
      
        ws.onopen = () => {
            document.getElementById('progress-text').innerText = "Conexión en vivo establecida. Esperando a la IA...";
        };

      
        ws.onmessage = async (event) => {
            const msg = JSON.parse(event.data);
            
          
            document.getElementById('progress-text').innerText = msg.mensaje;
            document.getElementById('progress-bar-fill').style.width = msg.progreso + '%';

         
            if (msg.progreso === 100) {
                ws.close(); 
                
              
                const token = localStorage.getItem('jwt_token'); 
                const resFinal = await fetch(`/auditoria/${auditId}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`, 
                        'Content-Type': 'application/json'
                    }
                });
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

    if (!data || !data.resultados) return;

    // --- NUEVO: Ocultamos el drag&drop y mostramos el botón de Nueva Auditoría ---
    const uploadZone = document.getElementById('upload-zone');
    if (uploadZone) uploadZone.style.display = 'none';

    const btnNew = document.getElementById('btn-new-audit');
    if (btnNew) btnNew.style.display = 'inline-block';
   
    document.getElementById('audit-stat-vuln').innerText = `${data.total_vulnerabilidades} Detectadas`;
    const score = Math.max(0, 100 - (data.total_vulnerabilidades * 5));
    document.getElementById('audit-stat-score').innerText = `${score} / 100`;
    document.getElementById('audit-stat-status').innerText = "Finalizado";
    document.getElementById('audit-stat-status').style.color = "#10b981";
    
    

    
    const list = document.getElementById('findings-list');
    list.innerHTML = '';

    let criticas = 0, medias = 0, bajas = 0;
    
    let severities = { ERROR: 0, WARNING: 0, INFO: 0 };

    data.resultados.forEach((item, idx) => {

        const sev = (item.severidad || '').toUpperCase();
        if (sev.includes('CRIT') || sev.includes('HIGH') || sev.includes('ALTA')) {
            criticas++;
        } else if (sev.includes('MED')) {
            medias++;
        } else {
            bajas++;
        }
        
        severities[item.severidad] = (severities[item.severidad] || 0) + 1;

        const div = document.createElement('div');
        div.className = `finding-item ${item.severidad.toLowerCase()}`;
        div.style.cursor = 'pointer';
        div.style.padding = '10px';
        div.style.borderBottom = '1px solid var(--border)';
        
       
        const lineaIndicador = item.linea ? `<span style="color:#ff4757; margin-left:5px;">(Línea ${item.linea})</span>` : '';

        div.innerHTML = `
            <div style="display:flex; justify-content:space-between">
                <strong>${item.vulnerabilidad}</strong>
                <span style="font-size:0.8em; font-weight:bold" class="severity-badge sev-${item.severidad.toLowerCase()}">${item.severidad}</span>
            </div>
            <div style="font-size:0.8em; color:#94a3b8; margin-top:5px">
                <i class="far fa-file-code"></i> ${item.archivo.split('/').pop()} ${lineaIndicador}
            </div>
        `;
        
      
        div.onclick = () => showDetail(item, div);
        list.appendChild(div);
    });

    
    updateCharts(score, severities);
}

function showDetail(item, divElement) {
    
    document.querySelectorAll('.finding-item').forEach(el => el.style.background = 'transparent');
    if (divElement) divElement.style.background = 'rgba(0, 242, 254, 0.1)';

    
    const detailContainer = document.getElementById('finding-detail');

  
    const codigoHtml = item.codigo_afectado ? `
        <div style="margin-top: 15px; background: #1e1e1e; padding: 15px; border-radius: 6px; border: 1px solid #333;">
            <span style="font-size: 0.8em; color: #888; text-transform: uppercase;">Fragmento Vulnerable</span>
            <pre style="margin: 5px 0 0 0; color: #d4d4d4; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.9em;"><code>${item.codigo_afectado}</code></pre>
        </div>` : '';
    
    const referenciasHtml = item.referencias_legales ? `
        <div style="margin-top: 20px; padding: 15px; background-color: rgba(0, 242, 254, 0.05); border-left: 4px solid #00f2fe; border-radius: 4px;">
            <strong style="color: #00f2fe;"><i class="fas fa-book-open"></i> Fuentes Normativas Consultadas (FAISS)</strong><br>
            <div style="color: #ccc; line-height: 1.5; margin-top: 8px; font-size: 0.9em;">
                ${item.referencias_legales.replace(/\n/g, '<br>')}
            </div>
        </div>` : '';

   
    detailContainer.innerHTML = `
        <h3 style="margin-top: 0; color: #fff;">${item.vulnerabilidad}</h3>
        <div style="color: var(--text-muted); margin-bottom: 15px;">
            <i class="fas fa-file-alt"></i> ${item.archivo} 
            ${item.linea ? `<span style="color:#ff4757; font-weight:bold; margin-left:10px;">(Línea ${item.linea})</span>` : ''}
        </div>

        ${codigoHtml}

        <div style="margin-top: 20px; background: rgba(255,255,255,0.03); padding: 15px; border-radius: 6px; border: 1px solid var(--border);">
            <strong style="color: #fff;"><i class="fas fa-brain"></i> Análisis y Solución (IA):</strong><br>
            <div style="margin-top: 10px; line-height: 1.6; color: #ddd;">
                ${(item.analisis_legal || 'Sin análisis detallado').replace(/\n/g, '<br>')}
            </div>
        </div>

        ${referenciasHtml}
    `;
}

function initCharts() {
    const radarOptions = {
        scales: { r: { angleLines: { color: '#334155' }, grid: { color: '#334155' }, suggestMin: 0, suggestMax: 100, ticks: { display: false }, pointLabels: { color: '#ffffff', font: { size: 14, weight: 'bold' } } } },
        plugins: { legend: { display: false } }
    };
    const doughnutOptions = { cutout: '70%', plugins: { legend: { position: 'right', labels: { color: '#fff' } } } };

   
    chartRadar = new Chart(document.getElementById('radarChart').getContext('2d'), {
        type: 'radar',
        data: { labels: ['Confidencialidad', 'Integridad', 'Trazabilidad', 'Autenticidad', 'Disponibilidad'], datasets: [{ label: 'Nivel', data: [0,0,0,0,0], backgroundColor: 'rgba(59, 130, 246, 0.2)', borderColor: '#3b82f6', borderWidth: 2, pointBackgroundColor: '#fff' }] },
        options: radarOptions
    });

    chartDoughnut = new Chart(document.getElementById('doughnutChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Crítico', 'Medio', 'Bajo'], datasets: [{ data: [0, 0, 0], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'], borderWidth: 0 }] },
        options: doughnutOptions
    });

   
    auditChartRadar = new Chart(document.getElementById('auditRadarChart').getContext('2d'), {
        type: 'radar',
        data: { labels: ['Confidencialidad', 'Integridad', 'Trazabilidad', 'Autenticidad', 'Disponibilidad'], datasets: [{ label: 'Nivel', data: [0,0,0,0,0], backgroundColor: 'rgba(59, 130, 246, 0.2)', borderColor: '#3b82f6', borderWidth: 2, pointBackgroundColor: '#fff' }] },
        options: radarOptions
    });

    auditChartDoughnut = new Chart(document.getElementById('auditDoughnutChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Crítico', 'Medio', 'Bajo'], datasets: [{ data: [0, 0, 0], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'], borderWidth: 0 }] },
        options: doughnutOptions
    });
}

function updateCharts(score, severities) {
    // SOLO actualizamos gráficas de la auditoría individual
    if (auditChartRadar) {
        auditChartRadar.data.datasets[0].data = [score, Math.max(0, score-10), Math.min(100, score+5), Math.max(0, score-5), score];
        auditChartRadar.update();
    }
    
    if (auditChartDoughnut) {
        auditChartDoughnut.data.datasets[0].data = [severities.ERROR || 0, severities.WARNING || 0, severities.INFO || 0];
        auditChartDoughnut.update();
    }
    
    // NOTA: Hemos eliminado las líneas que actualizaban chartRadar y chartDoughnut 
    // para no pisar los datos globales de la empresa.
}

async function generarPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
   
    const colorPrimary = [59, 130, 246]; 
    const colorDanger = [239, 68, 68];  
    const colorDark = [15, 23, 42];    
    
 
  
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
        if (!token) return;

        const res = await fetch('/historial', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) return;

        const history = await res.json();
        const container = document.getElementById('history-list');
        if (!container) return;

        if (!history || history.length === 0) {
            container.innerHTML = '<div style="font-size: 0.85em; color: var(--text-muted); text-align: center; margin-top: 10px;">Tu historial está vacío.</div>';
            return;
        }

        // --- 1. CÁLCULOS DEL DASHBOARD GLOBAL ---
        let globalCriticas = 0;
        let globalMedias = 0;
        let globalBajas = 0;
        let globalTotal = 0;

        history.forEach(h => {
            globalCriticas += (h.criticas || 0);
            globalMedias += (h.medias || 0);
            globalBajas += (h.bajas || 0);
            globalTotal += (h.total_vulnerabilidades || 0);
        });

        if (typeof trendChart !== 'undefined' && trendChart !== null) {
            const historialOrdenado = [...history].reverse(); 
            trendChart.data.labels = historialOrdenado.map(h => h.fecha || 'Auditoría');
            trendChart.data.datasets[0].data = historialOrdenado.map(h => h.total_vulnerabilidades || 0);
            trendChart.update();
        }

        if (typeof chartDoughnut !== 'undefined' && chartDoughnut !== null) {
            chartDoughnut.data.datasets[0].data = [globalCriticas, globalMedias, globalBajas];
            chartDoughnut.update();
        }

        const dashVuln = document.getElementById('stat-vuln');
        if (dashVuln) dashVuln.innerText = `${globalTotal} Totales`;
        
        const dashScore = document.getElementById('stat-score');
        let scoreGlobal = 100;
        if (dashScore) {
            let penalizacion = (globalCriticas * 5) + (globalMedias * 2) + (globalBajas * 1);
            scoreGlobal = Math.max(0, 100 - penalizacion);
            dashScore.innerText = `${scoreGlobal} / 100 (Media)`;
        }

        if (typeof chartRadar !== 'undefined' && chartRadar !== null) {
            chartRadar.data.datasets[0].data = [
                scoreGlobal, 
                Math.max(0, scoreGlobal - 10), 
                Math.min(100, scoreGlobal + 5), 
                Math.max(0, scoreGlobal - 5), 
                scoreGlobal
            ];
            chartRadar.update();
        }

        // --- 2. PINTAR LA LISTA LATERAL (¡Esto es lo que faltaba!) ---
        container.innerHTML = ''; // Limpiamos el texto de "Cargando..."

        history.forEach(h => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.style.cursor = 'pointer';
            div.style.padding = '10px';
            div.style.borderBottom = '1px solid var(--border)';
            div.innerHTML = `
                <div style="font-weight: bold; font-size: 0.9em;">${h.nombre_archivo || 'Auditoría'}</div>
                <div style="font-size: 0.8em; color: var(--text-muted);">${h.fecha}</div>
                <div style="font-size: 0.8em; margin-top: 5px;">
                    <span style="color: #ef4444; margin-right: 5px;"><i class="fas fa-bug"></i> ${h.total_vulnerabilidades || 0}</span>
                </div>
            `;
            
            // Al hacer clic en un item del historial, abrimos esa auditoría
// Al hacer clic en un item del historial, abrimos esa auditoría
            div.onclick = async () => {
                try {
                    // 1. Usamos TU función para cambiar de pantalla correctamente (sin romper el menú)
                    if (typeof navigate === 'function') {
                        navigate('audit');
                    }
                    
                    // 2. Nos aseguramos de que el panel de resultados se muestre
                    const workspace = document.getElementById('audit-workspace');
                    if (workspace) workspace.style.display = 'block';

                    // 3. Pedimos los datos al backend
                    const r = await fetch(`/auditoria/${h.id}`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    
                    if (r.ok) {
                        const data = await r.json();
                        // 4. Pintamos todo en la pantalla
                        processAuditResults(data);
                    }
                } catch(err) {
                    console.error("Error al abrir auditoría:", err);
                }
            };
            
            container.appendChild(div);
        });

    } catch (error) {
        console.error('Error cargando historial:', error);
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