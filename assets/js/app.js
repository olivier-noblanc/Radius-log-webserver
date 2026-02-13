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

        // --- MINIMALIST CONTEXT MENU ---
        var menu = document.getElementById('context-menu');
        var targetCell = null;

        document.addEventListener('contextmenu', function (e) {
            targetCell = e.target.closest('td');
            if (targetCell && menu) {
                e.preventDefault();
                menu.style.display = 'block';
                menu.style.left = e.pageX + 'px';
                menu.style.top = e.pageY + 'px';
            } else if (menu) {
                menu.style.display = 'none';
            }
        });

        document.addEventListener('click', function () { if (menu) menu.style.display = 'none'; });

        if (menu) {
            document.getElementById('copy-cell').onclick = function () {
                if (targetCell) navigator.clipboard.writeText(targetCell.textContent.trim());
            };
            document.getElementById('copy-row').onclick = function () {
                if (targetCell) {
                    var row = targetCell.closest('tr');
                    var cells = Array.prototype.slice.call(row.querySelectorAll('td'));
                    var text = cells.map(function (c) { return c.textContent.trim(); }).join('\t');
                    navigator.clipboard.writeText(text);
                }
            };
        }

        // --- PERSISTENT COLUMN RESIZING ---
        var table = document.getElementById('logTable');
        if (table) {
            var headers = table.querySelectorAll('th');

            // Restore widths
            headers.forEach(function (th, idx) {
                var width = localStorage.getItem('col-width-' + idx);
                if (width) th.style.width = width + 'px';

                var resizer = th.querySelector('.resizer');
                if (!resizer) return;

                var startX, startWidth;

                resizer.addEventListener('mousedown', function (e) {
                    startX = e.pageX;
                    startWidth = th.offsetWidth;

                    document.addEventListener('mousemove', onMouseMove);
                    document.addEventListener('mouseup', onMouseUp);
                    resizer.classList.add('resizing');
                });

                function onMouseMove(e) {
                    var width = startWidth + (e.pageX - startX);
                    if (width > 50) {
                        th.style.width = width + 'px';
                    }
                }

                function onMouseUp() {
                    document.removeEventListener('mousemove', onMouseMove);
                    document.removeEventListener('mouseup', onMouseUp);
                    resizer.classList.remove('resizing');
                    localStorage.setItem('col-width-' + idx, th.offsetWidth);
                }
            });
        }
    }

    // --- COLUMN VISIBILITY ---
    window.toggleColumn = function (idx) {
        var show = event.target.checked;
        applyColumnVisibility(idx, show);
        localStorage.setItem('col-visible-' + idx, show);
    };

    function applyColumnVisibility(idx, show) {
        var table = document.getElementById('logTable');
        if (!table) return;

        var th = table.querySelectorAll('th')[idx];
        if (th) th.classList.toggle('col-hidden', !show);

        var rows = table.querySelectorAll('tbody tr');
        rows.forEach(function (row) {
            var td = row.querySelectorAll('td')[idx];
            if (td) td.classList.toggle('col-hidden', !show);
        });

        // Sync checkbox if it exists (for initialization)
        var cb = document.querySelector('input[data-col-idx="' + idx + '"]');
        if (cb) cb.checked = show;
    }

    function initColumnVisibility() {
        for (var i = 0; i < 9; i++) {
            var visible = localStorage.getItem('col-visible-' + i);
            if (visible !== null) {
                applyColumnVisibility(i, visible === 'true');
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            init();
            initColumnVisibility();
        });
    } else {
        init();
        initColumnVisibility();
    }
})();