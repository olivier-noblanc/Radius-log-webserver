/*!
 * RADIUS LOG CORE - Pure HTMX, Minimal JS
 * Compatible: IE11+, Chrome 20+, Firefox 20+, Safari 6+
 */

(function () {
    'use strict';

    console.log('[RADIUS] app.js loaded - HTMX Pure Mode');

    // --- WEBSOCKET ---
    var ws = null;
    var statusBadge = null;

    function updateStatus(connected) {
        if (!statusBadge) statusBadge = document.getElementById('statusBadge');
        if (statusBadge) {
            statusBadge.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
            if (connected) {
                statusBadge.classList.add('connected');
                statusBadge.classList.remove('disconnected');
            } else {
                statusBadge.classList.add('disconnected');
                statusBadge.classList.remove('connected');
            }
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
            htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
        };
    }

    // --- HTMX GLOBAL EVENTS (Loader Management) ---
    document.addEventListener('htmx:beforeRequest', function () {
        var loader = document.getElementById('global-loader');
        if (loader) loader.classList.add('active');
    });

    document.addEventListener('htmx:afterRequest', function () {
        var loader = document.getElementById('global-loader');
        if (loader) loader.classList.remove('active');
    });

    // --- INIT ---
    function init() {
        connectWebSocket();

        // Error filter toggle (client-side only)
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