/*!
 * RADIUS LOG CORE - Pure HTMX, Minimal JS
 * Compatible: IE11+, Chrome 20+, Firefox 20+, Safari 6+
 */

(function () {
    'use strict';

    // --- CONSTANTS ---
    const WS_RECONNECT_INTERVAL = 5000;
    const MIN_COLUMN_WIDTH = 50;
    const TOTAL_COLUMNS = 9;

    // --- STATE ---
    let webSocket = null;
    let statusBadgeElement = null;

    const updateStatus = (connected) => {
        if (!statusBadgeElement) {
            statusBadgeElement = document.getElementById('statusBadge');
        }

        if (statusBadgeElement) {
            statusBadgeElement.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
            if (connected) {
                statusBadgeElement.classList.add('connected');
                statusBadgeElement.classList.remove('disconnected');
            } else {
                statusBadgeElement.classList.add('disconnected');
                statusBadgeElement.classList.remove('connected');
            }
        }
    };

    const connectWebSocket = () => {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        webSocket = new WebSocket(`${protocol}//${location.host}/ws`);

        webSocket.addEventListener('open', () => {
            updateStatus(true);
        });

        webSocket.addEventListener('close', () => {
            updateStatus(false);
            setTimeout(connectWebSocket, WS_RECONNECT_INTERVAL);
        });

        webSocket.addEventListener('message', () => {
            if (window.htmx) {
                window.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
            }
        });
    };

    const initLoaderManagement = () => {
        document.addEventListener('htmx:beforeRequest', () => {
            const loader = document.getElementById('global-loader');
            if (loader) {
                loader.classList.add('active');
            }
        });

        document.addEventListener('htmx:afterRequest', () => {
            const loader = document.getElementById('global-loader');
            if (loader) {
                loader.classList.remove('active');
            }
        });
    };

    const initErrorToggle = () => {
        const errorToggle = document.getElementById('errorToggle');
        if (errorToggle) {
            errorToggle.addEventListener('change', function () {
                const rows = document.querySelectorAll('#logTableBody tr');
                for (let i = 0; i < rows.length; i += 1) {
                    const statusCell = rows[i].querySelector('[data-status]');
                    if (statusCell && statusCell.getAttribute('data-status') === 'success') {
                        rows[i].style.display = this.checked ? 'none' : '';
                    }
                }
            });
        }
    };

    const initContextMenu = () => {
        const menu = document.getElementById('context-menu');
        let targetCell = null;

        document.addEventListener('contextmenu', (event) => {
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

        document.addEventListener('click', () => {
            if (menu) {
                menu.style.display = 'none';
            }
        });

        if (menu) {
            const copyCellBtn = document.getElementById('copy-cell');
            if (copyCellBtn) {
                copyCellBtn.addEventListener('click', () => {
                    if (targetCell) {
                        navigator.clipboard.writeText(targetCell.textContent.trim());
                    }
                });
            }

            const copyRowBtn = document.getElementById('copy-row');
            if (copyRowBtn) {
                copyRowBtn.addEventListener('click', () => {
                    if (targetCell) {
                        const row = targetCell.closest('tr');
                        const cells = Array.prototype.slice.call(row.querySelectorAll('td'));
                        const text = cells.map((cell) => cell.textContent.trim()).join('\t');
                        navigator.clipboard.writeText(text);
                    }
                });
            }
        }
    };

    const initResizers = () => {
        const table = document.getElementById('logTable');
        if (!table) {
            return;
        }

        const headers = table.querySelectorAll('th');

        headers.forEach((header, index) => {
            const savedWidth = localStorage.getItem(`col-width-${index}`);
            if (savedWidth) {
                header.style.width = `${savedWidth}px`;
                header.style.minWidth = `${savedWidth}px`;
            }

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
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                resizer.classList.remove('resizing');
                localStorage.setItem(`col-width-${index}`, header.offsetWidth);
            };

            resizer.addEventListener('mousedown', (event) => {
                event.stopPropagation();
                event.preventDefault();

                startX = event.pageX;
                startWidth = header.offsetWidth;

                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
                resizer.classList.add('resizing');
            });
        });
    };

    const applyColumnVisibility = (columnIndex, show) => {
        const table = document.getElementById('logTable');
        if (!table) {
            return;
        }

        const header = table.querySelectorAll('th')[columnIndex];
        if (header) {
            header.classList.toggle('col-hidden', !show);
        }

        const rows = table.querySelectorAll('tbody tr');
        rows.forEach((row) => {
            const cell = row.querySelectorAll('td')[columnIndex];
            if (cell) {
                cell.classList.toggle('col-hidden', !show);
            }
        });

        const checkbox = document.querySelector(`input[data-col-idx="${columnIndex}"]`);
        if (checkbox) {
            checkbox.checked = show;
        }
    };

    const initColumnVisibility = () => {
        for (let i = 0; i < TOTAL_COLUMNS; i += 1) {
            const visible = localStorage.getItem(`col-visible-${i}`);
            if (visible !== null) {
                applyColumnVisibility(i, visible === 'true');
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

        document.addEventListener('htmx:afterOnLoad', (event) => {
            if (event.detail.target.id === 'log-table-container' || event.detail.target.id === 'logTable') {
                initResizers();
            }
        });
    };

    // --- EXPOSED API ---
    window.toggleColumn = (columnIndex) => {
        const event = window.event;
        if (event && event.target) {
            const show = event.target.checked;
            applyColumnVisibility(columnIndex, show);
            localStorage.setItem(`col-visible-${columnIndex}`, show);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
