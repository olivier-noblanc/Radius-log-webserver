'use strict';

const WS_INTERVAL = 5000;
const MIN_WIDTH = 50;
const HALF = 0.5;
const NOT_SET = 0;
const KEYS = ['timestamp', 'req_type', 'server', 'ap_ip', 'ap_name', 'mac', 'user', 'resp_type', 'reason'];

let webSocket = { closed: true };
let badge = { textContent: '' };
let fallbackInterval = NOT_SET;

const stopFallback = () => {
    if (fallbackInterval) {
        clearInterval(fallbackInterval);
        fallbackInterval = NOT_SET;
    }
};

const startFallback = () => {
    if (fallbackInterval) {
        return;
    }
    fallbackInterval = setInterval(() => {
        if (globalThis.htmx) {
            globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
        }
    }, WS_INTERVAL);
};

const updateStatus = (connected) => {
    if (!badge.id) {
        badge = document.querySelector('#statusBadge') || badge;
    }
    if (badge.id) {
        let statusText = 'DISCONNECTED';
        if (connected) {
            statusText = 'CONNECTED';
        }
        badge.textContent = statusText;
        badge.classList.toggle('connected', connected);
        badge.classList.toggle('disconnected', !connected);
    }
};

const notifyFailure = (req) => {
    if (req.status === 'fail') {
        const failureNotif = new Notification(`FAIL: ${req.user}`, { body: req.reason });
        failureNotif.addEventListener('click', () => { focus(); });
    }
};

const handleWSData = (data) => {
    if (data.type !== 'new_logs') {
        return;
    }
    const toggle = document.querySelector('#notifToggle');
    const enabled = toggle && toggle.checked;
    if (enabled && Notification.permission === 'granted') {
        for (const req of data.requests) {
            notifyFailure(req);
        }
    }
    if (globalThis.htmx) {
        globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
    }
};

const handleWSMessage = (event) => {
    try {
        const data = JSON.parse(event.data);
        handleWSData(data);
    } catch {
        if (globalThis.htmx) {
            globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
        }
    }
};

const connectWS = () => {
    let proto = 'ws:';
    if (location.protocol === 'https:') {
        proto = 'wss:';
    }
    webSocket = new WebSocket(`${proto}//${location.host}/ws`);
    webSocket.addEventListener('open', () => {
        updateStatus(true);
        stopFallback();
    });
    webSocket.addEventListener('close', () => {
        updateStatus(false);
        startFallback();
        setTimeout(connectWS, WS_INTERVAL);
    });
    webSocket.addEventListener('message', handleWSMessage);
};

const copyCell = (cell) => {
    if (cell) {
        navigator.clipboard.writeText(cell.textContent.trim());
    }
};

const copyRow = (cell) => {
    if (cell) {
        const row = cell.closest('tr');
        const cellsList = [...row.querySelectorAll('td')];
        const content = cellsList.map((item) => item.textContent.trim()).join('\t');
        navigator.clipboard.writeText(content);
    }
};

const applyVisibility = (key, show) => {
    const tbl = document.querySelector('#logTable');
    if (!tbl) { return; }
    const cols = tbl.querySelectorAll(`[data-col-key="${key}"]`);
    for (const el of cols) {
        el.classList.toggle('col-hidden', !show);
    }
    const cb = document.querySelector(`input[data-col-key="${key}"]`);
    if (cb) { cb.checked = show; }
};

const applyOrder = (order) => {
    if (globalThis.htmx) {
        // Save order via server
        globalThis.htmx.ajax('GET', `/api/logs/columns?order=${encodeURIComponent(JSON.stringify(order))}`, {
            swap: 'none'
        }).then(() => {
            // Trigger HTMX reload to apply server-side order on the table
            const filters = document.querySelector('#log-filters');
            if (filters) {
                globalThis.htmx.trigger(filters, 'change');
            } else {
                globalThis.htmx.ajax('GET', '/api/logs/rows', '#log-table-container');
            }
        });
    }
};

const getColumnStorageKey = (head, idx) => {
    const key = head.dataset.colKey;
    if (key) {
        return `col-width-${key}`;
    }
    return `col-width-${idx}`;
};

const applyColumnWidth = (head, width) => {
    const colKey = head.dataset.colKey;
    if (colKey) {
        const colCells = document.querySelectorAll(`[data-col-key="${colKey}"]`);
        for (const cell of colCells) {
            cell.style.width = `${width}px`;
        }
        return;
    }
    head.style.width = `${width}px`;
};

const setupResizerListener = (head, idx, resizer) => {
    resizer.addEventListener('mousedown', (event) => {
        const startX = event.pageX;
        const startW = head.offsetWidth;
        const storageKey = getColumnStorageKey(head, idx);
        const onMove = (me) => {
            const width = startW + (me.pageX - startX);
            if (width > MIN_WIDTH) {
                applyColumnWidth(head, width);
            }
        };
        const onUp = () => {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            localStorage.setItem(storageKey, head.offsetWidth);
        };
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
};

const setupResizer = (head, idx) => {
    const res = head.querySelector('.resizer');
    if (!res || res.dataset.init) { return; }
    res.dataset.init = '1';
    setupResizerListener(head, idx, res);
};

const initResizers = () => {
    const tbl = document.querySelector('#logTable');
    if (!tbl) { return; }
    const heads = tbl.querySelectorAll('th');
    for (const [idx, head] of heads.entries()) {
        const storageKey = getColumnStorageKey(head, idx);
        const oldStorageKey = `col-width-${idx}`;
        const sw = localStorage.getItem(storageKey) || localStorage.getItem(oldStorageKey);
        if (sw) {
            const width = Number.parseInt(sw, 10);
            if (!Number.isNaN(width) && width > MIN_WIDTH) {
                applyColumnWidth(head, width);
                if (!localStorage.getItem(storageKey)) {
                    localStorage.setItem(storageKey, `${width}`);
                }
            }
        }
        setupResizer(head, idx);
    }
};

const setupReorder = (pick) => {
    let dragElement = { dataset: {} };
    pick.addEventListener('dragstart', (event) => {
        dragElement = event.target.closest('.column-checkbox');
    });
    pick.addEventListener('dragover', (event) => {
        event.preventDefault();
        const target = event.target.closest('.column-checkbox');
        if (target && target !== dragElement) {
            const rect = target.getBoundingClientRect();
            const threshold = rect.width * HALF;
            const isNext = (event.clientX - rect.left) > threshold;
            if (isNext) {
                (target.nextSibling || pick).before(dragElement);
            } else {
                target.before(dragElement);
            }
        }
    });
    pick.addEventListener('dragend', () => {
        const boxes = pick.querySelectorAll('.column-checkbox');
        const order = [...boxes].map((item) => item.dataset.colKey);
        applyOrder(order);
    });
};

const initReorder = () => {
    const pick = document.querySelector('.column-picker');
    if (pick) { setupReorder(pick); }
};

const handleDelegation = (event) => {
    const { target } = event;
    if (target.id === 'notifToggle' && target.checked && Notification.permission !== 'granted') {
        Notification.requestPermission().then((perm) => {
            if (perm !== 'granted') { target.checked = false; }
        });
    }
    if (target.classList.contains('column-visibility-check')) {
        const { colKey } = target.dataset;
        applyVisibility(colKey, target.checked);
        localStorage.setItem(`col-visible-${colKey}`, target.checked);
    }
};

const initDelegations = () => {
    document.addEventListener('change', handleDelegation);
    document.addEventListener('click', (event) => {
        if (event.target.closest('.log-row')) { location.hash = 'detailModal'; }
    });
    document.addEventListener('htmx:afterOnLoad', (event) => {
        if (['log-table-container', 'logTable'].includes(event.detail.target.id)) {
            initResizers();
            for (const key of KEYS) {
                const vis = localStorage.getItem(`col-visible-${key}`);
                if (vis) { applyVisibility(key, vis === 'true'); }
            }
        }
    });
};

const setupMenuListeners = (menu) => {
    let targetCell = { textContent: '' };
    document.addEventListener('contextmenu', (event) => {
        const cell = event.target.closest('td');
        if (cell) {
            targetCell = cell;
            event.preventDefault();
            menu.style.display = 'block';
            menu.style.left = `${event.pageX}px`;
            menu.style.top = `${event.pageY}px`;
        } else { menu.style.display = 'none'; }
    });
    document.addEventListener('click', () => { menu.style.display = 'none'; });
    const cCell = document.querySelector('#copy-cell');
    if (cCell) { cCell.addEventListener('click', () => { copyCell(targetCell); }); }
    const cRow = document.querySelector('#copy-row');
    if (cRow) { cRow.addEventListener('click', () => { copyRow(targetCell); }); }
};

const initMenu = () => {
    const menu = document.querySelector('#context-menu');
    if (menu) { setupMenuListeners(menu); }
};

const applyStored = () => {
    for (const key of KEYS) {
        const visibility = localStorage.getItem(`col-visible-${key}`);
        if (visibility) { applyVisibility(key, visibility === 'true'); }
    }
};

const init = () => {
    connectWS();
    initMenu();
    initResizers();
    initReorder();
    initDelegations();
    applyStored();
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else { init(); }
