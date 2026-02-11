// Configuration de performance
const MAX_DOM_ROWS = 1000; // Nombre max de lignes dans le tableau
const WS_PREPEND = true;   // Les nouveaux logs arrivent-ils en haut ou en bas ?

const themeSelect = document.getElementById('themeSelect');

if (themeSelect) {
    themeSelect.addEventListener('change', () => {
        try {
            const theme = themeSelect.value;
            console.log(`[DEBUG] Attempting to switch theme to: ${theme}`);
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            console.log(`[DEBUG] Theme ${theme} applied successfully`);
        } catch (err) {
            console.error('[DEBUG] Failed to switch theme:', err);
        }
    });

    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'neon';
    themeSelect.value = savedTheme;
    document.documentElement.setAttribute('data-theme', savedTheme);
    console.log(`[DEBUG] Initial theme loaded: ${savedTheme}`);
} else {
    console.error("[DEBUG] CRITICAL: themeSelect element not found in DOM");
}

// ========== SESSION AUTH ==========
const authBtn = document.getElementById('authBtn');
const humanGate = document.getElementById('human-gate');
const appRoot = document.getElementById('app-root');

function authorizeSession() {
    if (humanGate) humanGate.classList.add('hidden');
    if (appRoot) appRoot.classList.add('visible');
    document.body.style.overflow = 'auto';
    localStorage.setItem('radius_auth', 'authorized');
}

if (authBtn) {
    authBtn.addEventListener('click', authorizeSession);
}

// Vérifier la session existante au chargement
document.addEventListener('DOMContentLoaded', () => {
    if (localStorage.getItem('radius_auth') === 'authorized') {
        authorizeSession();
    }
});


// ========== ERROR HANDLING ==========
const errorOverlay = document.getElementById('error-overlay');
const errorDetails = document.getElementById('error-details');
const errorRebootBtn = null; // Removed

function showError(message, source, lineno, colno, error) {
    if (errorOverlay && errorDetails) {
        errorOverlay.style.display = 'flex';
        let detailText = `Message: ${message}\n`;
        if (source) detailText += `Source: ${source}\n`;
        if (lineno) detailText += `Line: ${lineno}:${colno}\n`;
        if (error && error.stack) detailText += `Stack:\n${error.stack}`;
        errorDetails.textContent = detailText;
    }
}

window.onerror = function (message, source, lineno, colno, error) {
    showError(message, source, lineno, colno, error);
    return false;
};

window.onunhandledrejection = function (event) {
    showError(`Unhandled Promise Rejection: ${event.reason}`, null, null, null, event.reason);
};

// Reboot logic removed


// ========== NAVIGATION ==========
document.querySelectorAll('[data-view]').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const viewName = link.dataset.view;
        showView(viewName);
    });
});

// ========== WEBSOCKET ==========
let socket;
let isLive = false;
const liveBtn = document.getElementById('liveBtn');
const indicator = document.querySelector('.live-dot');
const connectionStatus = document.getElementById('statusBadge');

function connectWs() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

    socket.onopen = () => {
        connectionStatus.innerHTML = '<i class="bi bi-wifi"></i> Connecté';
        connectionStatus.className = 'badge bg-success py-2';
    };

    socket.onmessage = (event) => {
        if (!isLive) return;
        const tbody = document.querySelector('#logTableBody');
        if (!tbody) return;

        // On insère le fragment HTML reçu directement
        tbody.insertAdjacentHTML('afterbegin', event.data);

        // DOM PRUNING: On limite le nombre de lignes pour garder la fluidité
        while (tbody.rows.length > MAX_DOM_ROWS) {
            tbody.deleteRow(tbody.rows.length - 1);
        }
    };

    socket.onclose = () => {
        connectionStatus.innerHTML = '<i class="bi bi-wifi-off"></i> Déconnecté';
        connectionStatus.className = 'badge bg-danger py-2';
        setTimeout(connectWs, 3000);
    };

    socket.onerror = () => {
        connectionStatus.innerHTML = '<i class="bi bi-exclamation-triangle"></i> Erreur';
        connectionStatus.className = 'badge bg-warning py-2';
    };
}

liveBtn.addEventListener('click', () => {
    isLive = !isLive;
    liveBtn.classList.toggle('btn-success', isLive);
    liveBtn.classList.toggle('btn-outline-success', !isLive);
    if (indicator) indicator.classList.toggle('live-active', isLive);
    liveBtn.querySelector('.live-label').textContent = isLive ? 'Live (Actif)' : 'Live Mode';
});

connectWs();

// ========== MAIN LOGIC ==========
const fileSelect = document.getElementById('fileSelect');
const loadBtn = document.getElementById('loadBtn');
const searchInput = document.getElementById('searchInput');
const logTableBody = document.getElementById('logTableBody');
const modalElement = document.getElementById('detailModal');
const modal = modalElement ? {
    show: () => modalElement.classList.add('visible'),
    hide: () => modalElement.classList.remove('visible')
} : null;

// Performance-optimized log loading
async function loadData() {
    if (!fileSelect || !logTableBody) return;
    const path = fileSelect.value;
    if (!path || path.startsWith("Aucun") || path.startsWith("Erreur")) return;

    const search = searchInput.value;
    const sortBy = document.getElementById('sort_by')?.value || 'timestamp';
    const sortDesc = document.getElementById('sort_desc')?.value === 'true';
    const useRegex = document.getElementById('regexToggle')?.checked || false;
    const errorOnly = document.getElementById('errorToggle')?.checked || false;
    const limit = MAX_DOM_ROWS;

    // Afficher loader léger
    logTableBody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:20px; font-family:var(--font-code); color:var(--accent-cyan);">ANALYSE "BLAZING FAST" EN COURS...</td></tr>';

    const url = `/api/logs/rows?file=${encodeURIComponent(path)}&search=${encodeURIComponent(search)}&sort_by=${sortBy}&sort_desc=${sortDesc}&use_regex=${useRegex}&error_only=${errorOnly}&limit=${limit}`;
    const authHeader = localStorage.getItem('radius_auth') === 'authorized' ? 'authorized' : '';

    try {
        const response = await fetch(url, {
            headers: {
                'X-Radius-Auth': authHeader
            }
        });
        if (response.status === 403) {
            console.error('[DEBUG] Authentication failed (403)');
            logTableBody.innerHTML = '<tr><td colspan="9" class="text-center text-warning">SESSION NON AUTORISÉE. VEUILLEZ CLIQUER SUR "AUTHORIZE SESSION".</td></tr>';
            return;
        }
        if (!response.ok) throw new Error('Network response was not ok');

        // On récupère directement le HTML généré par le serveur
        const html = await response.text();
        logTableBody.innerHTML = html;
        updateSortIconsUI(sortBy, sortDesc);
    } catch (err) {
        console.error('Erreur:', err);
        logTableBody.innerHTML = '<tr><td colspan="9" class="text-center text-danger">ERREUR DE CHARGEMENT : ' + err.message + '</td></tr>';
    }
}

// Global exposure for event handlers
window.loadData = loadData;

function showDetails(row) {
    const modalBody = document.getElementById('modalBody');
    if (modalBody) {
        if (typeof row === 'string') {
            try {
                row = JSON.parse(row);
            } catch (e) {
                console.error("[DEBUG] Failed to parse row data:", e);
            }
        }
        modalBody.textContent = JSON.stringify(row, null, 2);
    }
    if (modal) modal.show();
}

// Event Delegation for Log Rows and Sorting
document.addEventListener('click', (e) => {
    // Log Details
    const row = e.target.closest('.log-row');
    if (row && row.dataset.log) {
        showDetails(row.dataset.log);
        return;
    }

    // Sorting
    const th = e.target.closest('th.sortable');
    if (th && th.dataset.col) {
        updateSort(th.dataset.col);
        return;
    }

    // Modal Close
    const closeBtn = e.target.closest('.btn-modal-close');
    if (closeBtn) {
        modal.hide();
        const secModal = document.getElementById('securityModal');
        if (secModal) secModal.classList.remove('open');
        return;
    }
});

function updateSort(col) {
    const sortBy = document.getElementById('sort_by');
    const sortDesc = document.getElementById('sort_desc');
    if (!sortBy || !sortDesc) return;

    if (sortBy.value === col) {
        sortDesc.value = sortDesc.value === 'true' ? 'false' : 'true';
    } else {
        sortBy.value = col;
        sortDesc.value = 'true';
    }
    // Icons update
    updateSortIconsUI(col, sortDesc.value === 'true');
    loadData(); // Re-load data after sort change
};

function updateSortIconsUI(col, desc) {
    document.querySelectorAll('th.sortable').forEach(th => {
        const icon = th.querySelector('i');
        if (!icon) return;
        if (th.dataset.col === col) {
            icon.className = `bi ${desc ? 'bi-arrow-down' : 'bi-arrow-up'} small ms-1`;
        } else {
            icon.className = 'bi bi-arrow-down-up small ms-1';
        }
    });
}

// Load Button Handler
if (loadBtn) {
    loadBtn.addEventListener('click', loadData);
}

// Debounced search for loadData
let searchTimeout;
if (searchInput) {
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(loadData, 500);
    });
}

// File change handler
if (fileSelect) {
    fileSelect.addEventListener('change', loadData);
}

// Toggles change handler
['regexToggle', 'errorToggle'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', loadData);
});

// Search Handler with Debounce - REMOVED (Handled by HTMX)

// Export Handler
const exportBtn = document.getElementById('exportBtn');
if (exportBtn) {
    exportBtn.addEventListener('click', () => {
        const path = fileSelect ? fileSelect.value : '';
        const search = searchInput ? searchInput.value : '';
        if (!path || path.startsWith("Aucun") || path.startsWith("Erreur")) {
            alert('Veuillez sélectionner un fichier valide');
            return;
        }
        // Pour l'export via window.location.href, on ne peut pas facilement ajouter un header personnalisé
        // Si le backend exige le header pour l'export, il faudra passer par un fetch et un Blob ou ajouter un token de session en query param
        window.location.href = `/api/export?file=${encodeURIComponent(path)}&search=${encodeURIComponent(search)}`;
    });
}

// HTMX Event Hooks
document.addEventListener('htmx:afterSwap', (event) => {
    if (event.detail.target.id === 'view-dashboard') {
        const dashboard = document.getElementById('view-dashboard');
        if (dashboard && dashboard.dataset.stats) {
            try {
                const stats = JSON.parse(dashboard.dataset.stats);
                renderDashboardCharts(stats);
            } catch (e) {
                console.error("[DEBUG] Failed to parse dashboard stats:", e);
            }
        }
    }
});

function showView(viewName) {
    // Remove active class from all nav links
    document.querySelectorAll('.btn-nav').forEach(el => {
        el.classList.remove('active');
    });


    // Toggle views using CSS classes
    const viewLogs = document.getElementById('view-logs');
    const viewDash = document.getElementById('view-dashboard');

    if (viewName === 'logs') {
        if (viewLogs) viewLogs.classList.remove('hidden');
        if (viewDash) viewDash.classList.add('hidden');
        const navLogs = document.querySelector('[data-view="logs"]');
        if (navLogs) navLogs.classList.add('active');
    } else if (viewName === 'dashboard') {
        if (viewLogs) viewLogs.classList.add('hidden');
        if (viewDash) viewDash.classList.remove('hidden');
        const navDash = document.querySelector('[data-view="dashboard"]');
        if (navDash) navDash.classList.add('active');
        // Trigger HTMX to load dashboard content if it's empty or needs refresh
        if (typeof htmx !== 'undefined') {
            htmx.ajax('GET', '/api/dashboard', { target: '#view-dashboard', headers: { 'X-Radius-Auth': 'authorized' } });
        } else {
            console.error('[DEBUG] HTMX not loaded');
        }
    }
};


// ========== CHARTS ==========
let chartInstances = {};

function renderDashboardCharts(stats) {
    console.log("[DEBUG] Rendering Dashboard Charts with stats:", stats);

    // Clear existing instances
    if (chartInstances.rejects) chartInstances.rejects.destroy();
    if (chartInstances.reasons) chartInstances.reasons.destroy();

    // Chart 1: Rejets par heure
    const ctxRejects = document.getElementById('chartRejects');
    if (ctxRejects) {
        chartInstances.rejects = new Chart(ctxRejects, {
            type: 'line',
            data: {
                labels: stats.rejections_by_hour.map(x => x[0]),
                datasets: [{
                    label: 'Rejets',
                    data: stats.rejections_by_hour.map(x => x[1]),
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: '#dc3545'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { display: true, position: 'top' }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { callback: (v) => Math.floor(v) }
                    }
                }
            }
        });
    }

    // Chart 2: Top Reasons (Pie Chart)
    const ctxReasons = document.getElementById('chartReasons');
    if (ctxReasons) {
        const colors = ['#dc3545', '#fd7e14', '#ffc107', '#198754', '#0dcaf0', '#6f42c1'];
        const labels = stats.top_reasons.map(x => x[0]);
        const data = stats.top_reasons.map(x => x[1]);

        chartInstances.reasons = new Chart(ctxReasons, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors.slice(0, labels.length),
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadData(); // Initial load for "God Mode"
});
