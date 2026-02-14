'use strict';

const WS_INTERVAL = 5000;
const MIN_WIDTH = 50;
const HALF = 0.5;
const KEYS = ['timestamp', 'req_type', 'server', 'ap_ip', 'ap_name', 'mac', 'user', 'resp_type', 'reason'];

let webSocket = { closed: true };
let badge = { textContent: '' };

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
    webSocket.addEventListener('open', () => { updateStatus(true); });
    webSocket.addEventListener('close', () => {
        updateStatus(false);
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

const moveColumns = (key, thead, tbody) => {
    const head = thead.querySelector(`th[data-col-key="${key}"]`);
    if (head) { thead.append(head); }
    for (const row of tbody) {
        const cell = row.querySelector(`td[data-col-key="${key}"]`);
        if (cell) { row.append(cell); }
    }
};

const applyOrder = (order) => {
    const tbl = document.querySelector('#logTable');
    if (!tbl || !order) { return; }
    const thead = tbl.querySelector('thead tr');
    const tbody = tbl.querySelectorAll('tbody tr');
    for (const key of order) {
        moveColumns(key, thead, tbody);
    }
    initResizers();
};

const setupResizerListener = (head, idx, resizer) => {
    resizer.addEventListener('mousedown', (event) => {
        const startX = event.pageX;
        const startW = head.offsetWidth;
        const onMove = (me) => {
            const width = startW + (me.pageX - startX);
            if (width > MIN_WIDTH) {
                head.style.width = `${width}px`;
                head.style.minWidth = `${width}px`;
            }
        };
        const onUp = () => {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            localStorage.setItem(`col-width-${idx}`, head.offsetWidth);
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
        const sw = localStorage.getItem(`col-width-${idx}`);
        if (sw) {
            head.style.width = `${sw}px`;
            head.style.minWidth = `${sw}px`;
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
        localStorage.setItem('col-order', JSON.stringify(order));
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
            const saved = JSON.parse(localStorage.getItem('col-order') || 'null');
            if (saved) { applyOrder(saved); }
            initResizers();
            for (const key of KEYS) {
                const vis = localStorage.getItem(`col-visible-${key}`);
                if (vis !== null) { applyVisibility(key, vis === 'true'); }
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
    const savedOrder = JSON.parse(localStorage.getItem('col-order') || 'null');
    if (savedOrder) { applyOrder(savedOrder); }
    for (const key of KEYS) {
        const visibility = localStorage.getItem(`col-visible-${key}`);
        if (visibility !== null) { applyVisibility(key, visibility === 'true'); }
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
