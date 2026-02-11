// ==========================================
// RADIUS LOG CORE - Minimal JavaScript
// Alpine.js handles: Tabs, Theme, Live WS
// HTMX handles: Server communication
// ==========================================

document.addEventListener('DOMContentLoaded', () => {

    // --- LOADER GLOBAL (HTMX Integration) ---
    const loaderOverlay = document.getElementById('global-loader');

    function showLoader() {
        if (loaderOverlay) loaderOverlay.classList.add('active');
    }

    function hideLoader() {
        if (loaderOverlay) loaderOverlay.classList.remove('active');
    }

    document.body.addEventListener('htmx:beforeRequest', showLoader);
    document.body.addEventListener('htmx:afterRequest', () => {
        setTimeout(hideLoader, 300);
    });

    // --- ERROR FILTER TOGGLE ---
    const errorToggle = document.getElementById('errorToggle');
    if (errorToggle) {
        errorToggle.addEventListener('change', function () {
            const tableBody = document.getElementById('logTableBody');
            if (!tableBody) return;

            const rows = tableBody.querySelectorAll('tr');
            rows.forEach(row => {
                const status = row.querySelector('td[data-status]')?.getAttribute('data-status');
                if (this.checked && status === 'success') {
                    row.style.display = 'none';
                } else {
                    row.style.display = '';
                }
            });
        });
    }

    // --- MODAL CLOSE (ESC key) ---
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay').forEach(modal => {
                modal.style.display = 'none';
            });
        }
    });

    // --- TABLE RESIZE (Memory-safe) ---
    let currentResizer = null;
    let startX = 0;
    let startWidth = 0;

    function initResize(e) {
        currentResizer = e.target.parentElement;
        startX = e.pageX;
        startWidth = currentResizer.offsetWidth;
        document.addEventListener('mousemove', doResize);
        document.addEventListener('mouseup', stopResize);
    }

    function doResize(e) {
        if (currentResizer) {
            const width = startWidth + (e.pageX - startX);
            currentResizer.style.width = width + 'px';
        }
    }

    function stopResize() {
        document.removeEventListener('mousemove', doResize);
        document.removeEventListener('mouseup', stopResize);
        currentResizer = null;
    }

    document.querySelectorAll('.resizer').forEach(resizer => {
        resizer.addEventListener('mousedown', initResize);
    });

    // Re-init after HTMX updates
    document.body.addEventListener('htmx:afterSwap', () => {
        document.querySelectorAll('.resizer').forEach(resizer => {
            resizer.addEventListener('mousedown', initResize);
        });
    });

});

// ==========================================
// END - 80% RÉDUCTION DU CODE
// ==========================================