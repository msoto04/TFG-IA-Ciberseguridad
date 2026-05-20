let currentAuditData = null;
let chartRadar = null; 
let chartDoughnut = null; 
let auditChartRadar = null; 
let auditChartDoughnut = null; 
let trendChart = null;
let barChart = null;


document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadHistory();
});


document.getElementById('upload-zone').onclick = () => document.getElementById('fileInput').click();



const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('fileInput');


['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    uploadZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
    }, false);
});


['dragenter', 'dragover'].forEach(eventName => {
    uploadZone.addEventListener(eventName, () => {
        uploadZone.style.border = "2px dashed var(--primary)";
        uploadZone.style.background = "rgba(0, 242, 254, 0.1)"; 
    }, false);
});


['dragleave', 'drop'].forEach(eventName => {
    uploadZone.addEventListener(eventName, () => {
        uploadZone.style.border = ""; 
        uploadZone.style.background = "";
    }, false);
});


uploadZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;

    if (files && files.length > 0) {
      
        fileInput.files = files;
      
        fileInput.dispatchEvent(new Event('change'));
    }
});



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
    formData.append('modelo_ia', window.modeloIA || document.getElementById('model-select').value || 'deepseek-r1:8b');
    formData.append('temperatura', window.temperaturaIA !== undefined ? window.temperaturaIA : 0.0);
    formData.append('modo_inferencia', window.modoInferencia || document.getElementById('modo-inferencia').value || 'local');

    try {
   
       
        //const token = localStorage.getItem('jwt_token');

      
        const res = await fetch('http://localhost:8000/auditar-zip', { 
            method: 'POST', 
            credentials: 'include',
            body: formData 
        });

      
        if (res.status === 401) { cerrarSesion(); throw new Error("Sesión caducada"); }
        const data = await res.json();
        
        if (data.estado !== "Procesando") throw new Error("Error al iniciar");
        
        const auditId = data.audit_id;


        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        
        const ws = new WebSocket(`ws://localhost:8000/ws/progreso/${auditId}`);
      
        ws.onopen = () => {
            document.getElementById('progress-text').innerText = "Conexión en vivo establecida. Esperando a la IA...";
        };

      
        ws.onmessage = async (event) => {
            const msg = JSON.parse(event.data);
            
          
            document.getElementById('progress-text').innerText = msg.mensaje;
            document.getElementById('progress-bar-fill').style.width = msg.progreso + '%';

         
                if (msg.progreso === 100) {
                ws.close(); 
                
               
                const resFinal = await fetch(`http://localhost:8000/auditoria/${auditId}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include' 
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

        div.innerHTML = DOMPurify.sanitize(`
            <div style="display:flex; justify-content:space-between">
                <strong>${item.vulnerabilidad}</strong>
                <span style="font-size:0.8em; font-weight:bold" class="severity-badge sev-${item.severidad.toLowerCase()}">${item.severidad}</span>
            </div>
            <div style="font-size:0.8em; color:#94a3b8; margin-top:5px">
                <i class="far fa-file-code"></i> ${item.archivo.split('/').pop()} ${lineaIndicador}
            </div>
        `);
      
        div.onclick = () => showDetail(item, div);
        list.appendChild(div);
    });

    
   updateCharts(score, severities, data.resultados);
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

   
    detailContainer.innerHTML = DOMPurify.sanitize(`
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
    `);
}

function initCharts() {


    if (chartRadar) chartRadar.destroy();
    if (chartDoughnut) chartDoughnut.destroy();
    if (trendChart) trendChart.destroy();
    if (barChart) barChart.destroy();
    if (auditChartRadar) auditChartRadar.destroy();
    if (auditChartDoughnut) auditChartDoughnut.destroy();

    const ctxRadar = document.getElementById('radarChart');
    if (ctxRadar) {
        chartRadar = new Chart(ctxRadar.getContext('2d'), {
            type: 'radar',
            data: {
                labels: ['Confidencialidad', 'Integridad', 'Trazabilidad', 'Autenticidad', 'Disponibilidad'],
                datasets: [{
                    label: 'Nivel de Protección',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(0, 242, 254, 0.2)',
                    borderColor: '#00f2fe',
                    pointBackgroundColor: '#00f2fe'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 200,
                scales: {
                    r: { angleLines: { color: '#334155' }, grid: { color: '#334155' }, pointLabels: { color: '#94a3b8' }, ticks: { display: false }, min: 0, max: 100}
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    
    const ctxDoughnut = document.getElementById('doughnutChart');
    if (ctxDoughnut) {
        chartDoughnut = new Chart(ctxDoughnut.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Crítica', 'Media', 'Baja'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 200,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 20 } } },
                cutout: '70%'
            }
        });
    }

 
    const ctxTrend = document.getElementById('trendChart');
    if (ctxTrend) {
        trendChart = new Chart(ctxTrend.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Vulnerabilidades Totales',
                    data: [],
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, 
                resizeDelay: 200,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                    x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

   
    const ctxBar = document.getElementById('barChart');
    if (ctxBar) {
        barChart = new Chart(ctxBar.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [
                    { label: 'Críticas', data: [], backgroundColor: '#ef4444' },
                    { label: 'Medias', data: [], backgroundColor: '#f59e0b' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, 
                resizeDelay: 200,
                plugins: { legend: { position: 'bottom', labels: { color: '#fff' } } },
                scales: {
                    y: { stacked: true, beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                    x: { stacked: true, grid: { display: false }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }


    const ctxAuditRadar = document.getElementById('auditRadarChart');
    if (ctxAuditRadar) {
        auditChartRadar = new Chart(ctxAuditRadar.getContext('2d'), {
            type: 'radar',
            data: {
                labels: ['Confidencialidad', 'Integridad', 'Trazabilidad', 'Autenticidad', 'Disponibilidad'],
                datasets: [{
                    label: 'Nivel de Protección',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(139, 92, 246, 0.2)', 
                    borderColor: '#8b5cf6',
                    pointBackgroundColor: '#8b5cf6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: { angleLines: { color: '#334155' }, grid: { color: '#334155' }, pointLabels: { color: '#94a3b8' }, ticks: { display: false }, suggestMin: 0, suggestMax: 100 }
                },
                plugins: { legend: { display: false } }
            }
        });
    }


    const ctxAuditDoughnut = document.getElementById('auditDoughnutChart');
    if (ctxAuditDoughnut) {
        auditChartDoughnut = new Chart(ctxAuditDoughnut.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Crítica', 'Media', 'Baja'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 20 } } },
                cutout: '70%'
            }
        });
    }


}

function updateCharts(score, severities, vulnerabilidades) {
    const c = severities.ERROR || 0;
    const m = severities.WARNING || 0;
    const b = severities.INFO || 0;

    // Calcular impacto real por dominio ENS usando clasificación individual
    let dominios = {confidencialidad: 0, integridad: 0, trazabilidad: 0, autenticidad: 0, disponibilidad: 0};


    if (vulnerabilidades && vulnerabilidades.length > 0) {
        vulnerabilidades.forEach(v => {
            let peso = 1.0;
            let sev = (v.severidad || "").toUpperCase();
            if (sev.includes("ERROR") || sev.includes("HIGH") || sev.includes("CRIT")) peso = 0.35;
            else if (sev.includes("WARN") || sev.includes("MED")) peso = 0.15;
            else peso = 0.05;

            let ens = null;
            try {
                if (v.dominios_ens) ens = JSON.parse(v.dominios_ens);
            } catch(e) {}

            if (ens) {
                // Clasificación individual real
                if (ens.confidencialidad) dominios.confidencialidad += peso;
                if (ens.integridad) dominios.integridad += peso;
                if (ens.trazabilidad) dominios.trazabilidad += peso;
                if (ens.autenticidad) dominios.autenticidad += peso;
                if (ens.disponibilidad) dominios.disponibilidad += peso;
            } else {
                // Fallback: afecta a todos los dominios
                dominios.confidencialidad += peso;
                dominios.integridad += peso;
                dominios.trazabilidad += peso;
                dominios.autenticidad += peso;
                dominios.disponibilidad += peso;
            }
        });
    } else {
        // Fallback antiguo si no hay vulnerabilidades individuales
        dominios.confidencialidad = (c * 0.35) + (m * 0.15) + (b * 0.05);
        dominios.integridad = (c * 0.40) + (m * 0.20) + (b * 0.05);
        dominios.trazabilidad = (c * 0.10) + (m * 0.25) + (b * 0.15);
        dominios.autenticidad = (c * 0.30) + (m * 0.10) + (b * 0.05);
        dominios.disponibilidad = (c * 0.25) + (m * 0.15) + (b * 0.10);
    }

    if (auditChartRadar) {
        auditChartRadar.data.datasets[0].data = [
            Math.round(100 * Math.exp(-dominios.confidencialidad)),
            Math.round(100 * Math.exp(-dominios.integridad)),
            Math.round(100 * Math.exp(-dominios.trazabilidad)),
            Math.round(100 * Math.exp(-dominios.autenticidad)),
            Math.round(100 * Math.exp(-dominios.disponibilidad))
        ];
        auditChartRadar.update();
    }

    if (auditChartDoughnut) {
        auditChartDoughnut.data.datasets[0].data = [c, m, b];
        auditChartDoughnut.update();
    }
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
        const res = await fetch('http://localhost:8000/historial', {
            credentials: 'include'
        });
        if (!res.ok) return;

        const history = await res.json();
        const container = document.getElementById('history-list');
        if (!container) return;

        if (!history || history.length === 0) {
            container.innerHTML = '<div style="font-size: 0.85em; color: var(--text-muted); text-align: center; margin-top: 10px;">Tu historial está vacío.</div>';
            return;
        }

        let globalCriticas = 0;
        let globalMedias = 0;
        let globalBajas = 0;
        let globalTotal = 0;

        history.forEach(h => {
            globalCriticas += (h.criticas || 0);
            globalMedias += (h.medias || 0);
            globalBajas += (h.bajas || 0);
           
            globalTotal += ((h.criticas || 0) + (h.medias || 0) + (h.bajas || 0)); 
        });

     
        if (typeof trendChart !== 'undefined' && trendChart !== null) {
            const historialOrdenado = [...history].reverse(); 
            trendChart.data.labels = historialOrdenado.map(h => (h.fecha || 'N/A').split(',')[0]);
            trendChart.data.datasets[0].data = historialOrdenado.map(h => 
                h.puntuacion > 0 ? h.puntuacion : 
                Math.max(0, 100 - ((h.criticas || 0) * 15) - ((h.medias || 0) * 8) - ((h.bajas || 0) * 3))
            );
            trendChart.update();
        }

        if (typeof barChart !== 'undefined' && barChart !== null) {
            const ultimas = [...history].slice(0, 5); 
            barChart.data.labels = ultimas.map(h => {
                let nom = h.nombre_archivo || 'N/A';
                return nom.length > 12 ? nom.substring(0, 12) + '...' : nom; 
            });
            barChart.data.datasets[0].data = ultimas.map(h => h.criticas || 0);
            barChart.data.datasets[1].data = ultimas.map(h => h.medias || 0);
            barChart.update();
        }
   

        if (typeof chartDoughnut !== 'undefined' && chartDoughnut !== null) {
            chartDoughnut.data.datasets[0].data = [globalCriticas, globalMedias, globalBajas];
            chartDoughnut.update();
        }

        const dashVuln = document.getElementById('stat-vuln');
        if (dashVuln) dashVuln.innerText = `${globalTotal} Totales`;
        

        const dashScore = document.getElementById('stat-score');
        let scoreGlobal = 100;

      
        const totalAuditorias = history.length > 0 ? history.length : 1;
        const mediaCriticas = globalCriticas / totalAuditorias;
        const mediaMedias = globalMedias / totalAuditorias;
        const mediaBajas = globalBajas / totalAuditorias;

        if (dashScore) {
          
            let penalizacion = (mediaCriticas * 5) + (mediaMedias * 2) + (mediaBajas * 1);
            scoreGlobal = Math.max(0, 100 - penalizacion);
            dashScore.innerText = `${Math.round(scoreGlobal)} / 100 (Media)`;
        }

     
        let fConfG = (mediaCriticas * 0.35) + (mediaMedias * 0.15) + (mediaBajas * 0.05);
        let fIntG  = (mediaCriticas * 0.40) + (mediaMedias * 0.20) + (mediaBajas * 0.05);
        let fTrazG = (mediaCriticas * 0.10) + (mediaMedias * 0.25) + (mediaBajas * 0.15);
        let fAutG  = (mediaCriticas * 0.30) + (mediaMedias * 0.10) + (mediaBajas * 0.05);
        let fDispG = (mediaCriticas * 0.25) + (mediaMedias * 0.15) + (mediaBajas * 0.10);

      
        if (chartRadar) { 
            chartRadar.data.datasets[0].data = [
                Math.round(100 * Math.exp(-fConfG)),
                Math.round(100 * Math.exp(-fIntG)),
                Math.round(100 * Math.exp(-fTrazG)),
                Math.round(100 * Math.exp(-fAutG)),
                Math.round(100 * Math.exp(-fDispG))
            ];
            chartRadar.update();
        }
    

                
                if (chartDoughnut) {
                    chartDoughnut.data.datasets[0].data = [globalCriticas, globalMedias, globalBajas];
                    chartDoughnut.update();
                }

        container.innerHTML = ''; 

        history.forEach(h => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.style.cursor = 'pointer';
            div.style.padding = '10px';
            div.style.borderBottom = '1px solid var(--border)';
            
           
            const totalItem = (h.criticas || 0) + (h.medias || 0) + (h.bajas || 0);
            
            div.innerHTML = DOMPurify.sanitize(`
                <div style="font-weight: bold; font-size: 0.9em;">${h.nombre_archivo || 'Auditoría'}</div>
                <div style="font-size: 0.8em; color: var(--text-muted);">${h.fecha}</div>
                <div style="font-size: 0.8em; margin-top: 5px;">
                    <span style="color: #ef4444; margin-right: 5px;"><i class="fas fa-bug"></i> ${totalItem}</span>
                </div>
            `);
            
            div.onclick = async () => {
                try {
                    if (typeof navigate === 'function') {
                        navigate('audit');
                    }
                    const workspace = document.getElementById('audit-workspace');
                    if (workspace) workspace.style.display = 'block';

                    const r = await fetch(`http://localhost:8000/auditoria/${h.id}`, {
                        credentials: 'include'
                    });
                    
                    if (r.ok) {
                        const data = await r.json();
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
        
        if (typeof navigate === 'function') navigate('audit');
        
        const uploadZone = document.getElementById('upload-zone');
        if (uploadZone) uploadZone.style.display = 'none';
        
        const progressContainer = document.getElementById('progress-container');
        if(progressContainer) progressContainer.style.display = 'block';
        
        const progressText = document.getElementById('progress-text');
        if (progressText) progressText.innerText = "Recuperando auditoría de la bóveda...";
        
        const progressBar = document.getElementById('progress-bar-fill');
        if (progressBar) progressBar.style.width = "100%";
        
        const res = await fetch(`http://localhost:8000/auditoria/${auditId}`, {
            credentials: 'include'
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
                
                // Plantilla estática — datos insertados con .textContent debajo.
                item.innerHTML = `
                    <div class="safe-title" style="font-weight: 600; margin-bottom: 5px; font-size: 0.95em;"></div>
                    <div style="font-size: 0.8em; color: var(--text-muted);"><i class="fas ${icono}" style="color: ${colorBase}"></i> <span class="safe-sev"></span></div>
                `;
                item.querySelector('.safe-title').textContent = v.vulnerabilidad;
                item.querySelector('.safe-sev').textContent = v.severidad.toUpperCase();

              
                item.onclick = () => {
                   
                    Array.from(findingsList.children).forEach(c => c.style.background = 'var(--bg-panel)');
                    item.style.background = 'rgba(255, 255, 255, 0.05)'; 

                  
                    // Estructura HTML estática del panel de detalle.
                    // Los datos dinámicos (v.vulnerabilidad, v.analisis_legal, etc.)
                    // se insertan a continuación exclusivamente mediante .textContent
                    // para prevenir ataques XSS. Ver líneas siguientes.
                    findingDetail.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                            <span id="det-sev" style="background: ${colorBase}; color: white; padding: 5px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em;"></span>
                            <h3 id="det-title" style="margin: 0; color: var(--text-main); font-size: 1.1em;"></h3>
                        </div>
                        
                        <div style="margin-bottom: 20px;">
                            <h4 style="color: var(--text-muted); margin-bottom: 8px; font-size: 0.85em;">ARCHIVO Y CÓDIGO AFECTADO:</h4>
                            <code id="det-file" style="background: var(--bg-card); padding: 8px 12px; border-radius: 6px; display: block; color: var(--primary); border: 1px solid var(--border); font-family: 'JetBrains Mono', monospace; margin-bottom: 10px;"></code>
                            <pre><code id="det-code" style="background: #1e1e1e; padding: 10px; border-radius: 6px; display: block; color: #d4d4d4; overflow-x: auto;"></code></pre>
                        </div>

                        <div>
                            <h4 style="color: var(--text-muted); margin-bottom: 8px; font-size: 0.85em;">ANÁLISIS LEGAL / TÉCNICO:</h4>
                            <div id="det-analysis" style="background: rgba(0,0,0,0.2); padding: 15px; border-radius: 6px; line-height: 1.6; font-size: 0.95em; border-left: 2px solid var(--border); white-space: pre-wrap;"></div>
                        </div>

                        <div style="margin-top: 20px; padding: 15px; background: rgba(0, 255, 170, 0.05); border-left: 3px solid #00ffaa; border-radius: 6px;">
                            <h4 style="color: #00ffaa; margin-top: 0; margin-bottom: 10px; font-size: 0.9em;"><i class="fas fa-book"></i> EVIDENCIA RAG (ENS)</h4>
                            <div id="det-ref" style="font-size: 0.9em; color: #a0aec0; font-family: 'JetBrains Mono', monospace; white-space: pre-wrap; margin-bottom: 12px;"></div>
                            <div style="font-size: 0.85em; color: #718096; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px;">
                                <span style="margin-right: 20px;"><i class="fas fa-robot"></i> Modelo: <strong id="det-model" style="color:#e2e8f0;"></strong></span>
                                <span><i class="fas fa-shield-alt"></i> Regla: <strong id="det-rule" style="color:#e2e8f0;"></strong></span>
                            </div>
                        </div>
                    `;

                   
                    document.getElementById('det-sev').textContent = v.severidad.toUpperCase();
                    document.getElementById('det-title').textContent = v.vulnerabilidad;
                    document.getElementById('det-file').textContent = v.archivo + (v.linea ? ` (Línea ${v.linea})` : '');
                    document.getElementById('det-code').textContent = v.codigo_afectado || 'No disponible';
                    document.getElementById('det-analysis').textContent = v.analisis_legal;
                    
                    document.getElementById('det-ref').textContent = v.referencias_legales || 'Sin referencias';
                    document.getElementById('det-model').textContent = v.modelo_llm || 'N/A';
                    document.getElementById('det-rule').textContent = v.regla_semgrep || 'N/A';
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


            let fConf = (criticas * 0.35) + (medias * 0.15) + (bajas * 0.05);
            let fInt  = (criticas * 0.40) + (medias * 0.20) + (bajas * 0.05);
            let fTraz = (criticas * 0.10) + (medias * 0.25) + (bajas * 0.15);
            let fAut  = (criticas * 0.30) + (medias * 0.10) + (bajas * 0.05);
            let fDisp = (criticas * 0.25) + (medias * 0.15) + (bajas * 0.10);

            if (typeof chartRadar !== 'undefined' && chartRadar !== null) {
                chartRadar.data.datasets[0].data = [
                    Math.round(100 * Math.exp(-fConf)), // Confidencialidad
                    Math.round(100 * Math.exp(-fInt)),  // Integridad
                    Math.round(100 * Math.exp(-fTraz)), // Trazabilidad
                    Math.round(100 * Math.exp(-fAut)),  // Autenticidad
                    Math.round(100 * Math.exp(-fDisp))  // Disponibilidad
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