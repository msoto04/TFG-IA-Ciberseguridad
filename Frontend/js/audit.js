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

    
    document.getElementById('spinner').style.display = 'block';
    
    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('http://127.0.0.1:8000/auditar-zip', { method: 'POST', body: formData });
        const data = await res.json();
        
        currentAuditData = data;
        processAuditResults(data);
        saveToHistory(file.name, data.total_vulnerabilidades);

        // Cambiar vista y activar botón PDF
        document.getElementById('upload-zone').style.display = 'none';
        document.getElementById('audit-workspace').style.display = 'grid';
        document.getElementById('btn-export-pdf').style.display = 'inline-block';

    } catch (e) {
        alert("Error de conexión: " + e);
    } finally {
        document.getElementById('spinner').style.display = 'none';
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
        .replace(/SOLUCIÓN TÉCNICA/g, '<h4 style="color:var(--success); margin-top:20px">💡 Solución Técnica</h4>')
        .replace(/Incumplimiento ENS/g, '<h4 style="color:var(--danger)">⚖️ Incumplimiento ENS</h4>');

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
            scales: { r: { angleLines: {color: '#334155'}, grid: {color: '#334155'}, suggestMin: 0, suggestMax: 100, ticks: { display: false } } },
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
    
    // Título
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.setTextColor(255, 255, 255);
    doc.text("INFORME DE AUDITORÍA TÉCNICO-LEGAL", 105, 20, { align: "center" });
    doc.setFontSize(12);
    doc.text("Cumplimiento Esquema Nacional de Seguridad (ENS)", 105, 30, { align: "center" });
    
    // Datos Generales
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.text(`ID Auditoría: ${currentAuditData.id_auditoria || 'N/A'}`, 14, 50);
    doc.text(`Fecha de Emisión: ${new Date().toLocaleString()}`, 14, 55);
    
    // Resumen Ejecutivo (Tabla Simple)
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
        // Título del Hallazgo
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
    let history = JSON.parse(localStorage.getItem('auditHistory') || '[]');
    history.unshift({ date: new Date().toLocaleTimeString(), file: fileName, count: count });
    if (history.length > 5) history.pop();
    localStorage.setItem('auditHistory', JSON.stringify(history));
    loadHistory();
}

function loadHistory() {
    let history = JSON.parse(localStorage.getItem('auditHistory') || '[]');
    const container = document.getElementById('history-list');
    
    if (history.length === 0) return;
    
    container.innerHTML = '';
    history.forEach(h => {
        const div = document.createElement('div');
        div.style.padding = "10px";
        div.style.borderBottom = "1px solid #333";
        div.style.fontSize = "0.8em";
        div.innerHTML = `<span style="color:var(--primary)">${h.file}</span><br>Fallos: ${h.count} <span style="float:right; color:#666">${h.date}</span>`;
        container.appendChild(div);
    });
}