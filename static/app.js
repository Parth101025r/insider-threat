const form = document.querySelector('#upload-form');
const input = document.querySelector('#file-input');
const dropZone = document.querySelector('#drop-zone');
const fileName = document.querySelector('#file-name');
const message = document.querySelector('#message');
const button = document.querySelector('#analyze-button');
const results = document.querySelector('#results');
const themeToggle = document.querySelector('#theme-toggle');
const pageSize = 25;
let resultRows = [];
let resultColumns = [];
let currentPage = 1;
let monitorLogs = [];
let monitorCurrentPage = 1;
let monitorPageSize = 10;

let savedTheme = 'light';
try {
    savedTheme = localStorage.getItem('insider-threat-theme') || 'light';
} catch {}
document.documentElement.dataset.theme = savedTheme === 'dark' ? 'dark' : 'light';
themeToggle.checked = savedTheme === 'dark';
themeToggle.addEventListener('change', () => {
    const theme = themeToggle.checked ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    try {
        localStorage.setItem('insider-threat-theme', theme);
    } catch {}
});

document.querySelectorAll('.section-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.section-tab').forEach(item => item.classList.remove('is-active'));
        document.querySelectorAll('.view, .placeholder-view, .dashboard-view').forEach(view => { view.hidden = true; });
        tab.classList.add('is-active');
        document.querySelector(`#${tab.dataset.view}`).hidden = false;
        if (tab.dataset.view === 'dashboard-view') loadDashboard();
        if (tab.dataset.view === 'monitor-view') refreshMonitorLogs();
    });
});

const dashboardFrom = document.querySelector('#dashboard-date-from');
const dashboardTo = document.querySelector('#dashboard-date-to');

async function loadDashboard() {
    const refreshButton = document.querySelector('#refresh-dashboard');
    const status = document.querySelector('#dashboard-status');
    refreshButton.disabled = true;
    status.textContent = 'Loading activity...';
    try {
        const query = new URLSearchParams();
        if (dashboardFrom.value) query.set('start_date', dashboardFrom.value);
        if (dashboardTo.value) query.set('end_date', dashboardTo.value);
        const queryString = query.toString();
        const response = await fetch(`/api/dashboard/summary${queryString ? `?${queryString}` : ''}`);
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Could not load monitor activity.');
        renderDashboard(payload);
    } catch (error) {
        status.textContent = error.message;
    } finally {
        refreshButton.disabled = false;
    }
}

function renderDashboard(payload) {
    const status = document.querySelector('#dashboard-status');
    const eventCounts = Object.entries(payload.events_by_type || {})
        .sort((a, b) => b[1] - a[1]);
    const maxEventCount = Math.max(1, ...eventCounts.map(([, count]) => count));
    const timeSeries = Array.isArray(payload.time_series) ? payload.time_series : [];
    const recentLogs = Array.isArray(payload.recent_events) ? payload.recent_events : [];

    document.querySelector('#dashboard-total').textContent = Number(payload.total_events || 0).toLocaleString();
    document.querySelector('#dashboard-types').textContent = eventCounts.length.toLocaleString();
    document.querySelector('#dashboard-latest').textContent = payload.latest_event?.timestamp || '—';

    document.querySelector('#dashboard-event-types').innerHTML = eventCounts.length
        ? eventCounts.map(([event, count]) => `
            <div class="event-type-row">
                <div class="event-type-info">
                    <span>${escapeHtml(event)}</span>
                    <div class="event-type-track"><span style="width: ${Math.round(count / maxEventCount * 100)}%"></span></div>
                </div>
                <strong>${Number(count).toLocaleString()}</strong>
            </div>`).join('')
        : '<p class="dashboard-empty">No events in this date range.</p>';

    const days = timeSeries.slice(-14);
    const maxDailyCount = Math.max(1, ...days.map(item => item.events));
    document.querySelector('#dashboard-trend').innerHTML = days.length
        ? days.map(item => `
            <div class="trend-row">
                <span class="trend-date">${escapeHtml(item.date)}</span>
                <div class="trend-track"><span style="width: ${Math.round(item.events / maxDailyCount * 100)}%"></span></div>
                <strong>${Number(item.events).toLocaleString()}</strong>
            </div>`).join('')
        : '<p class="dashboard-empty">No dated events in this range.</p>';

    document.querySelector('#dashboard-recent-events').innerHTML = recentLogs.length
        ? recentLogs.map(log => `<tr><td>${escapeHtml(log.timestamp)}</td><td>${escapeHtml(log.event)}</td><td>${escapeHtml(log.details)}</td></tr>`).join('')
        : '<tr><td colspan="3">No events in this date range.</td></tr>';

    status.textContent = `Showing ${Number(payload.total_events || 0).toLocaleString()} events in the selected range.`;
}

document.querySelector('#refresh-dashboard').addEventListener('click', loadDashboard);
[dashboardFrom, dashboardTo].forEach(input => input.addEventListener('change', loadDashboard));
document.querySelector('#clear-dashboard-dates').addEventListener('click', () => {
    dashboardFrom.value = '';
    dashboardTo.value = '';
    loadDashboard();
});

function setMonitorState(state) {
    const startButton = document.querySelector('#start-monitoring');
    const stopButton = document.querySelector('#stop-monitoring');

    if (state === 'active') {
        startButton.disabled = true;
        startButton.textContent = 'Logging active';
        stopButton.hidden = false;
        stopButton.disabled = false;
        stopButton.textContent = 'Stop logging';
    } else if (state === 'stopping') {
        startButton.disabled = true;
        startButton.textContent = 'Stopping...';
        stopButton.hidden = false;
        stopButton.disabled = true;
        stopButton.textContent = 'Stopping...';
    } else {
        startButton.disabled = false;
        startButton.textContent = 'Start logging';
        stopButton.hidden = true;
        stopButton.disabled = false;
        stopButton.textContent = 'Stop logging';
    }
}

document.querySelector('#start-monitoring').addEventListener('click', async () => {
    const startButton = document.querySelector('#start-monitoring');
    const status = document.querySelector('#monitor-status');
    startButton.disabled = true;
    status.textContent = 'Connecting to monitor...';
    try {
        const response = await fetch('/api/monitor', { method: 'POST' });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Monitor endpoint is not available yet.');
        setMonitorState(payload.status);
        status.textContent = payload.message || 'Logging started.';
    } catch (error) {
        status.textContent = error.message;
        setMonitorState('inactive');
    }
});

document.querySelector('#stop-monitoring').addEventListener('click', async event => {
    const stopButton = event.currentTarget;
    const status = document.querySelector('#monitor-status');
    stopButton.disabled = true;
    status.textContent = 'Stopping logging...';
    try {
        const response = await fetch('/api/monitor/stop', { method: 'POST' });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Could not stop logging.');
        setMonitorState(payload.status);
        status.textContent = payload.message || 'Stop requested.';
        if (payload.status === 'stopping') await waitForMonitorStop();
    } catch (error) {
        status.textContent = error.message;
        setMonitorState('active');
    }
});

async function waitForMonitorStop() {
    const status = document.querySelector('#monitor-status');
    for (let attempt = 0; attempt < 10; attempt += 1) {
        await new Promise(resolve => window.setTimeout(resolve, 500));
        const response = await fetch('/api/monitor');
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Could not read monitor status.');
        if (payload.status !== 'active') {
            setMonitorState('inactive');
            status.textContent = 'Monitoring stopped.';
            return;
        }
    }
    setMonitorState('stopping');
    status.textContent = 'Stop requested; waiting for the monitor to exit.';
}

document.querySelector('#refresh-logs').addEventListener('click', refreshMonitorLogs);

async function refreshMonitorLogs() {
    const refreshButton = document.querySelector('#refresh-logs');
    const status = document.querySelector('#monitor-status');
    refreshButton.disabled = true;
    status.textContent = 'Loading logs...';
    try {
        const response = await fetch('/api/monitor');
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || 'Logs endpoint is not available yet.');
        setMonitorState(payload.status);
        monitorLogs = Array.isArray(payload.logs) ? [...payload.logs].reverse() : [];
        monitorCurrentPage = 1;
        renderMonitorLogs();
        status.textContent = `Loaded ${monitorLogs.length} log${monitorLogs.length === 1 ? '' : 's'}.`;
    } catch (error) {
        status.textContent = error.message;
    } finally {
        refreshButton.disabled = false;
    }
}

function renderMonitorLogs() {
    const totalPages = Math.max(1, Math.ceil(monitorLogs.length / monitorPageSize));
    monitorCurrentPage = Math.min(Math.max(monitorCurrentPage, 1), totalPages);
    const start = (monitorCurrentPage - 1) * monitorPageSize;
    const pageLogs = monitorLogs.slice(start, start + monitorPageSize);
    const firstRow = monitorLogs.length ? start + 1 : 0;
    const lastRow = Math.min(start + monitorPageSize, monitorLogs.length);

    document.querySelector('#logs-body').innerHTML = pageLogs.length
        ? pageLogs.map(log => `<tr><td>${escapeHtml(log.timestamp || log.time)}</td><td>${escapeHtml(log.event || log.type)}</td><td>${escapeHtml(log.details || log.message)}</td></tr>`).join('')
        : '<tr><td colspan="3">No logs available.</td></tr>';
    document.querySelector('#monitor-row-range').textContent = `Showing ${firstRow} to ${lastRow} of ${monitorLogs.length}`;
    document.querySelector('#monitor-page-indicator').textContent = `Page ${monitorCurrentPage} of ${totalPages}`;
    document.querySelector('#monitor-previous-page').disabled = monitorCurrentPage === 1;
    document.querySelector('#monitor-next-page').disabled = monitorCurrentPage === totalPages;
    document.querySelector('#monitor-pagination').hidden = totalPages <= 1;
}

document.querySelector('#monitor-page-size').addEventListener('change', event => {
    monitorPageSize = Number(event.currentTarget.value);
    monitorCurrentPage = 1;
    renderMonitorLogs();
});
document.querySelector('#monitor-previous-page').addEventListener('click', () => {
    monitorCurrentPage -= 1;
    renderMonitorLogs();
});
document.querySelector('#monitor-next-page').addEventListener('click', () => {
    monitorCurrentPage += 1;
    renderMonitorLogs();
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