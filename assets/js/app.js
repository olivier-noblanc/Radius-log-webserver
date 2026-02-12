/*!
 * RADIUS LOG CORE - Future-proof JavaScript
 * Pure ES5, no dependencies, browser standard only
 * Compatible: IE11+, Chrome 20+, Firefox 20+, Safari 6+
 * Expected to work until 2035+ without modifications
 */

(function () {
    'use strict';

    console.log('[RADIUS] app.js loaded');

    // --- WEBSOCKET ---
    var ws = null;
    var statusBadge = null;

    function updateStatus(connected) {
        if (!statusBadge) statusBadge = document.getElementById('statusBadge');
        if (statusBadge) {
            statusBadge.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
            statusBadge.style.color = connected ? '#39ff14' : '#ff3131';
        }
    }

    function connectWebSocket() {
        var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(protocol + '//' + location.host + '/ws');

        ws.onopen = function () { updateStatus(true); };
        ws.onclose = function () {
            updateStatus(false);
            setTimeout(connectWebSocket, 5000);
        };
        ws.onmessage = function () {
            // Reload logs table via HTMX using the new container target
            htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
        };
    }

    // --- THEME ENGINE ---
    window.applyTheme = function (themeName) {
        console.log('[RADIUS] Applying theme:', themeName);

        // 1. Update Attributes (MegaCSS handles the rest instantly)
        document.documentElement.setAttribute('data-theme', themeName);
        document.body.setAttribute('data-theme', themeName);

        // 2. Trigger Refresh
        setTimeout(function () {
            var loadBtn = document.getElementById('loadBtn');
            var dashBtn = document.getElementById('btn-nav-dashboard');

            if (document.getElementById('view-logs').style.display !== 'none' && loadBtn) {
                loadBtn.click();
            } else if (dashBtn) {
                dashBtn.click();
            }
        }, 50);
    };

    // --- INIT ---
    function init() {
        connectWebSocket();

        // Global HTMX Event Listener (Keep as fallback/diagnostics)
        document.addEventListener('htmx:afterSwap', function (evt) {
            if (evt.detail.target.id === 'log-table-container') {
                console.log('[RADIUS] Logs refreshed');
            }
        });

        // Error filter toggle
        var errorToggle = document.getElementById('errorToggle');
        if (errorToggle) {
            errorToggle.onchange = function () {
                var rows = document.querySelectorAll('#logTableBody tr');
                for (var i = 0; i < rows.length; i++) {
                    var status = rows[i].querySelector('[data-status]');
                    if (status && status.getAttribute('data-status') === 'success') {
                        rows[i].style.display = this.checked ? 'none' : '';
                    }
                }
            };
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();