/*!
 * RADIUS LOG CORE - Pure HTMX, Minimal JS
 * Compatible: IE11+, Chrome 20+, Firefox 20+, Safari 6+
 */

(function iife() {
    'use strict';

    // --- CONSTANTS ---
    const WS_RECONNECT_INTERVAL = 5000;
    const MIN_COLUMN_WIDTH = 50;
    const TOTAL_COLUMNS = 9;

    // --- STATE ---
    let webSocket;
    let statusBadgeElement;

    const updateStatus = (connected) => {
        if (!statusBadgeElement) {
            statusBadgeElement = globalThis.document.querySelector('#statusBadge');
        }

        if (statusBadgeElement) {
            if (connected) {
                statusBadgeElement.textContent = 'CONNECTED';
                statusBadgeElement.classList.add('connected');
                statusBadgeElement.classList.remove('disconnected');
            } else {
                statusBadgeElement.textContent = 'DISCONNECTED';
                statusBadgeElement.classList.add('disconnected');
                statusBadgeElement.classList.remove('connected');
            }
        }
    };

    const connectWebSocket = () => {
        let protocol = 'ws:';
        if (globalThis.location.protocol === 'https:') {
            protocol = 'wss:';
        }
        webSocket = new globalThis.WebSocket(`${protocol}//${globalThis.location.host}/ws`);

        webSocket.addEventListener('open', () => {
            updateStatus(true);
        });

        webSocket.addEventListener('close', () => {
            updateStatus(false);
            globalThis.setTimeout(connectWebSocket, WS_RECONNECT_INTERVAL);
        });

        const handleWebSocketMessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'new_logs') {
                    // Minimalist Alerts
                    const alertsToggle = globalThis.document.querySelector('#notifToggle');
                    const alertsEnabled = alertsToggle ? alertsToggle.checked : false;
                    if (alertsEnabled && globalThis.Notification.permission === 'granted') {
                        for (const req of data.requests) {
                            if (req.status === 'fail') {
                                const notif = new globalThis.Notification(`AUTH FAIL: ${req.user}`, {
                                    body: `${req.reason}\n${req.server}`,
                                    icon: '/favicon.svg'
                                });
                                notif.onclick = () => globalThis.focus();
                            }
                        }
                    }

                    if (globalThis.htmx) {
                        globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
                    }
                }
            } catch (error) {
                if (globalThis.htmx) {
                    globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
                }
            }
        };

        webSocket.addEventListener('message', handleWebSocketMessage);
    };

    const initLoaderManagement = () => {
        globalThis.document.addEventListener('htmx:beforeRequest', () => {
            const loader = globalThis.document.querySelector('#global-loader');
            if (loader) {
                loader.classList.add('active');
            }
        });

        globalThis.document.addEventListener('htmx:afterRequest', () => {
            const loader = globalThis.document.querySelector('#global-loader');
            if (loader) {
                loader.classList.remove('active');
            }
        });
    };

    const initErrorToggle = () => {
        const errorToggle = globalThis.document.querySelector('#errorToggle');
        if (errorToggle) {
            errorToggle.addEventListener('change', function handleErrorToggle() {
                const rows = globalThis.document.querySelectorAll('#logTableBody tr');
                for (const row of rows) {
                    const statusCell = row.querySelector('[data-status]');
                    if (statusCell && statusCell.dataset.status === 'success') {
                        if (this.checked) {
                            row.style.display = 'none';
                        } else {
                            row.style.display = '';
                        }
                    }
                }
            });
        }
    };

    const copyCellContent = (targetCell) => {
        if (targetCell) {
            globalThis.navigator.clipboard.writeText(targetCell.textContent.trim());
        }
    };

    const copyRowContent = (targetCell) => {
        if (targetCell) {
            const row = targetCell.closest('tr');
            const cells = Array.prototype.slice.call(row.querySelectorAll('td'));
            const text = cells.map((cell) => cell.textContent.trim()).join('\t');
            globalThis.navigator.clipboard.writeText(text);
        }
    };

    const initContextMenu = () => {
        const menu = globalThis.document.querySelector('#context-menu');
        let targetCell;

        globalThis.document.addEventListener('contextmenu', (event) => {
            targetCell = event.target.closest('td');
            if (targetCell && menu) {
                event.preventDefault();
                menu.style.display = 'block';
                menu.style.left = `${event.pageX}px`;
                menu.style.top = `${event.pageY}px`;
            } else if (menu) {
                menu.style.display = 'none';
            }
        });

        globalThis.document.addEventListener('click', () => {
            if (menu) {
                menu.style.display = 'none';
            }
        });

        if (menu) {
            globalThis.document.querySelector('#copy-cell')?.addEventListener('click', () => copyCellContent(targetCell));
            globalThis.document.querySelector('#copy-row')?.addEventListener('click', () => copyRowContent(targetCell));
        }
    };

    const setupResizer = (header, index) => {
        const resizer = header.querySelector('.resizer');
        if (!resizer || resizer.dataset.initialized) {
            return;
        }

        resizer.dataset.initialized = 'true';
        let startX = 0;
        let startWidth = 0;

        const onMouseMove = (event) => {
            const width = startWidth + (event.pageX - startX);
            if (width > MIN_COLUMN_WIDTH) {
                header.style.width = `${width}px`;
                header.style.minWidth = `${width}px`;
            }
        };

        const onMouseUp = () => {
            globalThis.document.removeEventListener('mousemove', onMouseMove);
            globalThis.document.removeEventListener('mouseup', onMouseUp);
            resizer.classList.remove('resizing');
            globalThis.localStorage.setItem(`col-width-${index}`, header.offsetWidth);
        };

        resizer.addEventListener('mousedown', (event) => {
            event.stopPropagation();
            event.preventDefault();

            startX = event.pageX;
            startWidth = header.offsetWidth;

            globalThis.document.addEventListener('mousemove', onMouseMove);
            globalThis.document.addEventListener('mouseup', onMouseUp);
            resizer.classList.add('resizing');
        });
    };

    const initResizers = () => {
        const table = globalThis.document.querySelector('#logTable');
        if (!table) {
            return;
        }

        const headers = table.querySelectorAll('th');

        for (const [index, header] of headers.entries()) {
            const savedWidth = globalThis.localStorage.getItem(`col-width-${index}`);
            if (savedWidth) {
                header.style.width = `${savedWidth}px`;
                header.style.minWidth = `${savedWidth}px`;
            }
            setupResizer(header, index);
        }
    };

    const applyColumnVisibility = (columnIndex, show) => {
        const table = globalThis.document.querySelector('#logTable');
        if (!table) {
            return;
        }

        const headers = table.querySelectorAll('th');
        if (headers[columnIndex]) {
            headers[columnIndex].classList.toggle('col-hidden', !show);
        }

        const rows = table.querySelectorAll('tbody tr');
        for (const row of rows) {
            const cell = row.querySelectorAll('td')[columnIndex];
            if (cell) {
                cell.classList.toggle('col-hidden', !show);
            }
        }

        const checkbox = globalThis.document.querySelector(`input[data-col-idx="${columnIndex}"]`);
        if (checkbox) {
            checkbox.checked = show;
        }
    };

    const initColumnVisibility = () => {
        for (let index = 0; index < TOTAL_COLUMNS; index += 1) {
            const visible = globalThis.localStorage.getItem(`col-visible-${index}`);
            if (visible !== null) {
                applyColumnVisibility(index, visible === 'true');
            }
        }
    };

    const init = () => {
        connectWebSocket();
        initLoaderManagement();
        initErrorToggle();
        initContextMenu();
        initResizers();
        initColumnVisibility();

        // Delegation for Alerts (Minimalist)
        globalThis.document.addEventListener('change', (e) => {
            const target = e.target;
            if (target.id === 'notifToggle' && target.checked && globalThis.Notification.permission !== 'granted') {
                globalThis.Notification.requestPermission().then((p) => {
                    if (p !== 'granted') {
                        target.checked = false;
                    }
                });
            }
        });

        // Delegation for Column Visibility
        globalThis.document.addEventListener('change', (e) => {
            const target = e.target;
            if (target.classList.contains('column-visibility-check')) {
                const idx = parseInt(target.dataset.colIdx, 10);
                const show = target.checked;
                applyColumnVisibility(idx, show);
                globalThis.localStorage.setItem(`col-visible-${idx}`, show);
            }
        });

        // Delegation for Modal Detail Hash
        globalThis.document.addEventListener('click', (e) => {
            const row = e.target.closest('.log-row');
            if (row) {
                globalThis.location.hash = 'detailModal';
            }
        });

        globalThis.document.addEventListener('htmx:afterOnLoad', (event) => {
            const { target } = event.detail;
            if (target.id === 'log-table-container' || target.id === 'logTable') {
                initResizers();
            }
        });
    };

    if (globalThis.document.readyState === 'loading') {
        globalThis.document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
