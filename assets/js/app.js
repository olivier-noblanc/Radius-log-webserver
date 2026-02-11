// assets/js/app.js

document.addEventListener('DOMContentLoaded', () => {

    // --- 1. CONFIGURATION COMPLÈTE DES THÈMES ---
    // C'est ici que tu personnalises l'UX de chaque thème
    const themeConfig = {
        'onyx-glass': {
            className: 'theme-onyx-glass',
            title: "SYSTEM INITIALIZING",
            sub: "PREPARING PREMIUM INTERFACE...",
            type: 'spinner'
        },
        'cyber-tactical': {
            className: 'theme-cyber-tactical',
            title: "TACTICAL BOOT",
            sub: "SCANNING PERIMETER...",
            type: 'spinner'
        },
        neon: {
            className: 'theme-neon',
            title: "SYSTEM INITIALIZING",
            sub: "CONNECTING TO NEURAL NET...",
            type: 'glitch'
        },
        terminal: {
            className: 'theme-terminal',
            title: "MATRIX ACCESS",
            sub: "DECRYPTING DATA STREAM...",
            type: 'spinner'
        },
        dos: {
            className: 'theme-dos',
            title: "C:\\>LOADING...",
            sub: "READING CONFIG.SYS...",
            type: 'spinner'
        },
        win31: {
            className: 'theme-win31',
            title: "SYSTEM BOOT", // Titre bleu
            sub: "LOADING SYSTEM FILES...\nCHECKING MEMORY...", // Texte DOS dans la boite grise
            type: 'box' // Type spécial pour Win31
        },
        win95: {
            className: 'theme-win95',
            title: "STARTING WINDOWS...",
            sub: "LOGGING IN USER...",
            type: 'progress'
        },
        xp: {
            className: 'theme-xp',
            title: "WELCOME",
            sub: "LOADING USER PROFILE...",
            type: 'progress'
        },
        macos: {
            className: 'theme-macos',
            title: "MAC OS STARTUP",
            sub: "INITIALIZING SYSTEM...",
            type: 'spinner'
        },
        c64: {
            className: 'theme-c64',
            title: "COMMODORE 64",
            sub: "LOADING KERNEL...",
            type: 'spinner'
        },
        nes: {
            className: 'theme-nes',
            title: "NINTENDO",
            sub: "LOADING CARTRIDGE...",
            type: 'spinner'
        },
        dsfr: {
            className: 'theme-dsfr',
            title: "Connexion en cours",
            sub: "Chargement de l'interface...",
            type: 'spinner'
        },
        compact: {
            className: 'theme-compact',
            title: "INITIALIZING",
            sub: "OPTIMIZING...",
            type: 'bar'
        }
    };

    // --- 2. GESTION DU LOADER GLOBAL ---
    const loaderOverlay = document.getElementById('global-loader');
    const loaderBox = document.querySelector('.loader-box');
    const loaderTitle = document.querySelector('.loader-title');
    const loaderSub = document.querySelector('.loader-sub');

    function showLoader() {
        if (!loaderOverlay || !loaderBox) return;

        const currentTheme = document.documentElement.getAttribute('data-theme') || 'neon';
        const config = themeConfig[currentTheme] || themeConfig['neon'];

        // Reset classes
        loaderBox.className = 'loader-box';
        if (config.className) loaderBox.classList.add(config.className);

        // Update Text
        if (loaderTitle) loaderTitle.innerText = config.title;
        if (loaderSub) loaderSub.innerText = config.sub;

        loaderOverlay.classList.add('active');
    }

    function hideLoader() {
        if (loaderOverlay) loaderOverlay.classList.remove('active');
    }

    // Écouteurs HTMX pour le Loader
    document.body.addEventListener('htmx:beforeRequest', (evt) => {
        const target = evt.detail.target;
        // On affiche le loader pour les chargements importants
        if (target && (target.id === 'logTableBody' || target.id === 'view-dashboard' || target.id === 'app-root')) {
            showLoader();
        }
    });

    document.body.addEventListener('htmx:afterRequest', () => {
        setTimeout(hideLoader, 300);
    });

    document.body.addEventListener('htmx:sendError', () => {
        hideLoader();
        alert("Erreur de communication avec le serveur.");
    });

    // --- 3. LOGIQUE D'ONGLETS (Instantanéité) ---
    const btnLogs = document.getElementById('btn-nav-logs');
    const btnDash = document.getElementById('btn-nav-dashboard');
    const viewLogs = document.getElementById('view-logs');
    const viewDash = document.getElementById('view-dashboard');

    function showView(viewName) {
        if (viewName === 'logs') {
            viewLogs.style.display = 'block';
            viewDash.style.display = 'none';
            btnLogs.classList.add('active');
            btnDash.classList.remove('active');
        } else {
            viewLogs.style.display = 'none';
            viewDash.style.display = 'block';
            btnLogs.classList.remove('active');
            btnDash.classList.add('active');
        }
    }

    if (btnLogs) btnLogs.addEventListener('click', () => showView('logs'));
    if (btnDash) btnDash.addEventListener('click', () => showView('dashboard'));

    // --- 4. LOGIQUE THÈME ---
    const themeSelect = document.getElementById('themeSelect');
    const gateThemeSelect = document.getElementById('gate-theme');

    window.setTheme = (themeName) => {
        document.documentElement.setAttribute('data-theme', themeName);
        document.cookie = `theme=${themeName}; path=/; max-age=31536000`;
        if (themeSelect) themeSelect.value = themeName;
        if (gateThemeSelect) gateThemeSelect.value = themeName;
    };

    if (themeSelect) themeSelect.addEventListener('change', (e) => window.setTheme(e.target.value));

    // --- 5. FILTRE ERRORS ONLY (Instantané) ---
    const errorToggle = document.getElementById('errorToggle');
    const tableBody = document.getElementById('logTableBody');

    function toggleErrors() {
        if (!tableBody) return;
        const isChecked = errorToggle.checked;
        const rows = tableBody.querySelectorAll('tr');

        rows.forEach(row => {
            const resultCell = row.querySelector('td[data-status]');
            if (resultCell) {
                const status = resultCell.getAttribute('data-status');
                if (isChecked && status === 'success') {
                    row.style.display = 'none';
                } else {
                    row.style.display = '';
                }
            }
        });
    }

    if (errorToggle) {
        errorToggle.addEventListener('change', toggleErrors);
        if (errorToggle.checked) toggleErrors();
    }

    // --- 6. LIVE BUTTON ---
    const liveBtn = document.getElementById('liveBtn');
    if (liveBtn) {
        liveBtn.addEventListener('click', () => {
            const dot = liveBtn.querySelector('.live-dot');
            const label = liveBtn.querySelector('.live-label');
            dot.classList.toggle('active');
            if (dot.classList.contains('active')) {
                label.innerText = "LIVE";
                label.style.color = "#39ff14";
            } else {
                label.innerText = "OFFLINE";
                label.style.color = "var(--text-muted)";
            }
        });
    }

});