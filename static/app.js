const form = document.querySelector('#upload-form');
const input = document.querySelector('#file-input');
const dropZone = document.querySelector('#drop-zone');
const fileName = document.querySelector('#file-name');
const message = document.querySelector('#message');
const button = document.querySelector('#analyze-button');
const results = document.querySelector('#results');
const pageSize = 25;
let resultRows = [];
let resultColumns = [];
let currentPage = 1;

document.querySelectorAll('.section-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.section-tab').forEach(item => item.classList.remove('is-active'));
        document.querySelectorAll('.view, .placeholder-view').forEach(view => { view.hidden = true; });
        tab.classList.add('is-active');
        document.querySelector(`#${tab.dataset.view}`).hidden = false;
    });
});

document.querySelector('#start-monitoring').addEventListener('click', async event => {
    const startButton = event.currentTarget;
    const status = document.querySelector('#monitor-status');
    startButton.disabled = true;
    status.textContent = 'Connecting to monitor...';
    try {
        const response = await fetch('/api/monitor', { method: 'POST' });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Monitor endpoint is not available yet.');
        status.textContent = payload.message || 'Logging started.';
        startButton.textContent = 'Logging active';
    } catch (error) {
        status.textContent = error.message;
        startButton.disabled = false;
    }
});

document.querySelector('#refresh-logs').addEventListener('click', async event => {
    const refreshButton = event.currentTarget;
    const status = document.querySelector('#monitor-status');
    refreshButton.disabled = true;
    status.textContent = 'Loading logs...';
    try {
        const response = await fetch('/api/monitor');
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Logs endpoint is not available yet.');
        const logs = payload.logs || [];
        document.querySelector('#logs-body').innerHTML = logs.length
            ? logs.map(log => `<tr><td>${escapeHtml(log.timestamp || log.time)}</td><td>${escapeHtml(log.event || log.type)}</td><td>${escapeHtml(log.details || log.message)}</td></tr>`).join('')
            : '<tr><td colspan="3">No logs available.</td></tr>';
        status.textContent = `Loaded ${logs.length} log${logs.length === 1 ? '' : 's'}.`;
    } catch (error) {
        status.textContent = error.message;
    } finally {
        refreshButton.disabled = false;
    }
});

function escapeHtml(value) {
    return String(value ?? '—')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function formatHeader(value) {
    return value.replaceAll('_', ' ');
}

function renderPage() {
    const totalPages = Math.max(1, Math.ceil(resultRows.length / pageSize));
    currentPage = Math.min(Math.max(currentPage, 1), totalPages);
    const start = (currentPage - 1) * pageSize;
    const rows = resultRows.slice(start, start + pageSize);

    document.querySelector('#results-body').innerHTML = rows.map((row, index) => `
        <tr><td>${start + index + 1}</td>${resultColumns.map(column => {
            const value = row[column];
            if (column === 'status') {
                return `<td><span class="status status-${escapeHtml(value)}">${escapeHtml(value)}</span></td>`;
            }
            return `<td>${escapeHtml(value)}</td>`;
        }).join('')}</tr>`).join('');

    document.querySelector('#page-indicator').textContent = `Page ${currentPage} of ${totalPages}`;
    document.querySelector('#previous-page').disabled = currentPage === 1;
    document.querySelector('#next-page').disabled = currentPage === totalPages;
    document.querySelector('#pagination').hidden = resultRows.length <= pageSize;
}

function setFile(file) {
    if (!file) return;
    input.files = (() => { const files = new DataTransfer(); files.items.add(file); return files.files; })();
    fileName.textContent = file.name;
}

input.addEventListener('change', () => setFile(input.files[0]));
['dragenter', 'dragover'].forEach(event => dropZone.addEventListener(event, e => { e.preventDefault(); dropZone.classList.add('dragging'); }));
['dragleave', 'drop'].forEach(event => dropZone.addEventListener(event, e => { e.preventDefault(); dropZone.classList.remove('dragging'); }));
dropZone.addEventListener('drop', e => setFile(e.dataTransfer.files[0]));

form.addEventListener('submit', async event => {
    event.preventDefault();
    message.textContent = '';
    button.disabled = true;
    button.firstChild.textContent = 'Analyzing... ';
    try {
        const response = await fetch('/api/analysis/logs', { method: 'POST', body: new FormData(form) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || 'Analysis failed.');
        document.querySelector('#result-file').textContent = payload.filename;
        document.querySelector('#total-count').textContent = payload.total;
        document.querySelector('#anomaly-count').textContent = payload.anomalies;
        document.querySelector('#normal-count').textContent = payload.normal;
        resultRows = payload.results;
        resultColumns = Object.keys(resultRows[0] || {});
        currentPage = 1;
        document.querySelector('#results-head').innerHTML = `
            <tr><th>Record</th>${resultColumns.map(column => `<th>${escapeHtml(formatHeader(column))}</th>`).join('')}</tr>`;
        renderPage();
        results.hidden = false;
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) { message.textContent = error.message; }
    finally { button.disabled = false; button.firstChild.textContent = 'Analyze file '; }
});

document.querySelector('#previous-page').addEventListener('click', () => { currentPage -= 1; renderPage(); });
document.querySelector('#next-page').addEventListener('click', () => { currentPage += 1; renderPage(); });
document.querySelector('#reset-button').addEventListener('click', () => {
    form.reset();
    fileName.textContent = 'No file selected';
    resultRows = [];
    resultColumns = [];
    currentPage = 1;
    results.hidden = true;
    window.scrollTo({ top: 0, behavior: 'smooth' });
});