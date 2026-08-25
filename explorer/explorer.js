/* ============================================================
   Dilithion Block Explorer - SPA with Hash-Based Routing
   ============================================================ */

'use strict';

// --- Configuration ---
const API_BASE = '/api';
const REFRESH_INTERVAL = 5000;
const ITEMS_PER_PAGE = 20;
const IONS_PER_DIL = 100000000;
const COLLAPSE_THRESHOLD = 5; // Show expand button when inputs/outputs exceed this

// --- Chain state ---
let activeChain = localStorage.getItem('explorerChain') || 'dil';
let UNIT = activeChain === 'dilv' ? 'DilV' : 'DIL';
let BLOCK_REWARD_FALLBACK = activeChain === 'dilv' ? 100 : 50;
// Source of truth: src/core/chainparams.cpp — DIL mainnet halvingInterval = 210000 (:42),
// DilV halvingInterval = 1050000 (:440). DilV's ~45s blocks give it a 5x longer interval.
let HALVING_INTERVAL = activeChain === 'dilv' ? 1050000 : 210000;

function switchExplorerChain(chain) {
    activeChain = chain;
    UNIT = chain === 'dilv' ? 'DilV' : 'DIL';
    BLOCK_REWARD_FALLBACK = chain === 'dilv' ? 100 : 50;
    HALVING_INTERVAL = chain === 'dilv' ? 1050000 : 210000;
    localStorage.setItem('explorerChain', chain);
    // Update toggle buttons
    const dilBtn = document.getElementById('chainBtnDil');
    const dilvBtn = document.getElementById('chainBtnDilv');
    if (dilBtn && dilvBtn) {
        dilBtn.classList.toggle('active', chain === 'dil');
        dilvBtn.classList.toggle('active', chain === 'dilv');
    }
    // Update title
    const titleEl = document.querySelector('.navbar-title');
    if (titleEl) titleEl.textContent = chain === 'dilv' ? 'DILV EXPLORER' : 'DILITHION EXPLORER';
    document.title = chain === 'dilv' ? 'DilV Explorer' : 'Dilithion Explorer';
    // Re-render current route
    router.route();
}

// --- State ---
let refreshTimer = null;
let currentRoute = '';
let sortState = {}; // { tableId: { column: idx, ascending: bool } }

// --- SVG Icons ---
const ICONS = {
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    chevronLeft: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
    chevronRight: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
    arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
    pickaxe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2.5L18 6l-4 4"/><path d="M2 22l10-10"/><path d="M18 6l4-4"/></svg>',
};

// ============================================================
// Router
// ============================================================

class Router {
    constructor() {
        this.routes = [];
        window.addEventListener('hashchange', () => this.route());
    }

    add(pattern, handler) {
        this.routes.push({ pattern, handler });
    }

    route() {
        const hash = window.location.hash || '#/';
        stopAutoRefresh();

        for (const { pattern, handler } of this.routes) {
            const regex = new RegExp('^' + pattern.replace(/:\w+/g, '([^/]+)') + '$');
            const match = hash.match(regex);
            if (match) {
                currentRoute = pattern;
                updateNavLinks(hash);
                handler(...match.slice(1));
                return;
            }
        }

        // Default fallback to home
        currentRoute = '#/';
        updateNavLinks('#/');
        renderHome();
    }
}

const router = new Router();

// --- Routes ---
router.add('#/', renderHome);
router.add('#/home', renderHome);
router.add('#/block/:id', renderBlock);
router.add('#/tx/:txid', renderTransaction);
router.add('#/address/:addr', renderAddress);
router.add('#/blocks', () => renderBlockList(1));
router.add('#/blocks/:page', (page) => renderBlockList(parseInt(page, 10)));
router.add('#/forks', renderForks);
router.add('#/nodes', renderNodes);
router.add('#/holders', renderHolders);
router.add('#/transactions', () => renderTransactions(1));
router.add('#/transactions/:page', (page) => renderTransactions(parseInt(page, 10)));
router.add('#/search/:query', handleSearch);

// ============================================================
// Helper Functions
// ============================================================

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function formatHash(hash, chars) {
    if (!hash) return '';
    chars = chars || 8;
    if (hash.length <= chars * 2 + 3) return hash;
    return hash.substring(0, chars) + '...' + hash.substring(hash.length - chars);
}

function formatAmount(ions) {
    if (ions === null || ions === undefined) return '0.00000000';
    const dil = Number(ions) / IONS_PER_DIL;
    return dil.toFixed(8);
}


function formatNumber(n) {
    if (n === null || n === undefined) return '0';
    return Number(n).toLocaleString('en-US');
}

function formatTime(timestamp) {
    if (!timestamp) return '';
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;

    if (diff < 0) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return formatAbsoluteTime(timestamp);
}

function formatAbsoluteTime(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp * 1000);
    return d.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    });
}

function formatHashRate(hps) {
    if (!hps || hps <= 0) return '0 H/s';
    const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'];
    let idx = 0;
    let val = Number(hps);
    while (val >= 1000 && idx < units.length - 1) {
        val /= 1000;
        idx++;
    }
    return val.toFixed(2) + ' ' + units[idx];
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

function setTitle(subtitle) {
    document.title = subtitle ? subtitle + ' - Dilithion Explorer' : 'Dilithion Explorer';
}

function getApp() {
    return document.getElementById('app');
}

function showLoading() {
    getApp().innerHTML = '<div class="loading"><div class="spinner"></div><span>Loading...</span></div>';
}

function showError(title, message) {
    getApp().innerHTML = `
        <div class="error-message">
            <h2>${escapeHtml(title)}</h2>
            <p>${escapeHtml(message)}</p>
            <a href="#/">Back to Home</a>
        </div>`;
}

function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

function updateNavLinks(hash) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        const route = link.getAttribute('data-route');
        if (route === 'home' && (hash === '#/' || hash === '#/home')) {
            link.classList.add('active');
        } else if (route === 'blocks' && hash.startsWith('#/blocks')) {
            link.classList.add('active');
        } else if (route === 'forks' && hash === '#/forks') {
            link.classList.add('active');
        } else if (route === 'nodes' && hash === '#/nodes') {
            link.classList.add('active');
        } else if (route === 'holders' && hash === '#/holders') {
            link.classList.add('active');
        } else if (route === 'transactions' && hash.startsWith('#/transactions')) {
            link.classList.add('active');
        }
    });
}

async function apiFetch(endpoint) {
    const sep = endpoint.includes('?') ? '&' : '?';
    const response = await fetch(API_BASE + endpoint + sep + 'chain=' + activeChain);
    if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'API error: ' + response.status);
    }
    return response.json();
}

function copyToClipboard(text) {
    return new Promise((resolve) => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(resolve).catch(() => {
                fallbackCopy(text);
                resolve();
            });
        } else {
            fallbackCopy(text);
            resolve();
        }
    });
}

function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
}

function showCopyToast(btn) {
    // Remove any existing toast
    const existing = document.querySelector('.copy-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = 'Copied!';
    document.body.appendChild(toast);

    // Position near the button
    const rect = btn.getBoundingClientRect();
    toast.style.left = rect.left + rect.width / 2 + 'px';
    toast.style.top = rect.top - 8 + 'px';

    // Trigger reflow then animate in
    toast.offsetHeight;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 1500);
}

function makeCopyButton(text) {
    return `<button class="copy-btn" data-copy="${escapeHtml(text)}" title="Copy to clipboard">${ICONS.copy}</button>`;
}

// Event delegation for all copy buttons - more robust than inline onclick
document.addEventListener('click', function(e) {
    const btn = e.target.closest('.copy-btn');
    if (!btn || !btn.dataset.copy) return;

    const text = btn.dataset.copy;
    copyToClipboard(text).then(() => {
        btn.innerHTML = ICONS.check;
        btn.classList.add('copied');
        showCopyToast(btn);
        setTimeout(() => {
            btn.innerHTML = ICONS.copy;
            btn.classList.remove('copied');
        }, 2000);
    });
});

function breadcrumb(items) {
    const parts = items.map((item, i) => {
        if (i === items.length - 1) {
            return `<span class="current">${escapeHtml(item.label)}</span>`;
        }
        return `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a><span class="separator">&rsaquo;</span>`;
    });
    return `<div class="breadcrumb">${parts.join('')}</div>`;
}

// ============================================================
// Sortable Tables
// ============================================================

function makeSortableHeader(tableId, columns) {
    const state = sortState[tableId];
    return columns.map((col, idx) => {
        if (!col.sortable) {
            return `<th class="${col.align || ''}">${escapeHtml(col.label)}</th>`;
        }
        const isActive = state && state.column === idx;
        const arrow = isActive ? (state.ascending ? ' ▲' : ' ▼') : '';
        const cls = [col.align || '', 'sortable-th', isActive ? 'sort-active' : ''].filter(Boolean).join(' ');
        return `<th class="${cls}" data-table="${escapeHtml(tableId)}" data-col="${idx}">${escapeHtml(col.label)}${arrow}</th>`;
    }).join('');
}

function sortTableRows(tableId, colIdx, getValue) {
    const prev = sortState[tableId];
    const ascending = (prev && prev.column === colIdx) ? !prev.ascending : false;
    sortState[tableId] = { column: colIdx, ascending };

    const table = document.querySelector(`[data-sort-table="${tableId}"]`);
    if (!table) return;
    const tbody = table.querySelector('tbody');
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
        const va = getValue(a, colIdx);
        const vb = getValue(b, colIdx);
        if (va < vb) return ascending ? -1 : 1;
        if (va > vb) return ascending ? 1 : -1;
        return 0;
    });

    for (const row of rows) tbody.appendChild(row);

    // Update header arrows
    const thead = table.querySelector('thead tr');
    if (thead) {
        thead.querySelectorAll('th.sortable-th').forEach(th => {
            const ci = parseInt(th.dataset.col, 10);
            const base = th.textContent.replace(/\s*[▲▼]$/, '');
            const isActive = ci === colIdx;
            th.textContent = base + (isActive ? (ascending ? ' ▲' : ' ▼') : '');
            th.classList.toggle('sort-active', isActive);
        });
    }
}

// Event delegation for sortable headers
document.addEventListener('click', function(e) {
    const th = e.target.closest('.sortable-th');
    if (!th) return;
    const tableId = th.dataset.table;
    const colIdx = parseInt(th.dataset.col, 10);
    if (isNaN(colIdx)) return;

    sortTableRows(tableId, colIdx, (row, ci) => {
        const cell = row.children[ci];
        if (!cell) return '';
        // Use data-sort-value if present, else parse text
        if (cell.dataset.sortValue !== undefined) {
            const num = parseFloat(cell.dataset.sortValue);
            return isNaN(num) ? cell.dataset.sortValue : num;
        }
        const num = parseFloat(cell.textContent.replace(/[^0-9.\-]/g, ''));
        if (!isNaN(num)) return num;
        return cell.textContent.trim().toLowerCase();
    });
});

// ============================================================
// Collapsible Sections
// ============================================================

document.addEventListener('click', function(e) {
    const btn = e.target.closest('.expand-btn');
    if (!btn) return;
    const target = btn.dataset.target;
    const container = document.getElementById(target);
    if (!container) return;
    const isHidden = container.style.display === 'none';
    container.style.display = isHidden ? '' : 'none';
    btn.textContent = isHidden ? btn.dataset.lessText : btn.dataset.moreText;
});

// ============================================================
// Transaction Type Detection
// ============================================================

function detectTxType(tx) {
    const isCoinbase = tx.vin && tx.vin.length > 0 && (tx.vin[0].coinbase || tx.vin[0].txid === '0000000000000000000000000000000000000000000000000000000000000000');
    if (isCoinbase) return { type: 'coinbase', label: 'Coinbase', badge: 'badge-success', icon: ICONS.pickaxe };

    const inputCount = tx.vin ? tx.vin.length : 0;
    const outputCount = tx.vout ? tx.vout.length : 0;

    // Consolidation: many inputs → 1-2 outputs
    if (inputCount > 5 && outputCount <= 2) {
        return { type: 'consolidation', label: 'Consolidation', badge: 'badge-info', icon: '' };
    }

    return { type: 'transfer', label: 'Transfer', badge: 'badge-muted', icon: '' };
}

// ============================================================
// View: Home
// ============================================================

// --- Dashboard helpers ---

const FLAG_EMOJI = { US: '\u{1F1FA}\u{1F1F8}', GB: '\u{1F1EC}\u{1F1E7}', SG: '\u{1F1F8}\u{1F1EC}', AU: '\u{1F1E6}\u{1F1FA}' };

function getBlockReward(height) {
    const halvings = Math.floor(height / HALVING_INTERVAL);
    if (halvings >= 64) return 0;
    return BLOCK_REWARD_FALLBACK / Math.pow(2, halvings);
}

function getBlocksUntilHalving(height) {
    return HALVING_INTERVAL - (height % HALVING_INTERVAL);
}

function formatLastBlockTime(blockTime) {
    if (!blockTime || blockTime <= 0) return 'N/A';
    const secondsAgo = Math.floor((Date.now() / 1000) - blockTime);
    if (secondsAgo < 10) return 'Just now';
    if (secondsAgo < 60) return secondsAgo + 's ago';
    if (secondsAgo < 3600) return Math.floor(secondsAgo / 60) + ' min ago';
    if (secondsAgo < 86400) return Math.floor(secondsAgo / 3600) + 'h ago';
    return Math.floor(secondsAgo / 86400) + 'd ago';
}

function buildStatsBarHTML(s, blocks) {
    const height = s.blocks || 0;
    const lastBlockTime = blocks && blocks.length > 0 ? blocks[0].time : 0;
    let html = '';
    html += statCard('Block Height', formatNumber(height));
    html += statCard(s.consensusType === 'VDF' ? 'Consensus' : 'Hashrate',
        s.consensusType === 'VDF' ? 'VDF (Proof of Time)' : formatHashRate(s.networkhashps));
    html += statCard('Difficulty', s.difficulty ? Number(s.difficulty).toFixed(4) : 'N/A');
    html += statCard('Supply', s.supply ? formatNumber(Math.floor(s.supply)) + ' ' + UNIT : 'N/A');
    html += statCard('Block Reward', getBlockReward(height) + ' ' + UNIT);
    html += statCard('Next Halving', formatNumber(getBlocksUntilHalving(height)) + ' blocks');
    html += statCard('Last Block', formatLastBlockTime(lastBlockTime));
    html += statCard('Avg Block Time', s.avgBlockTime ? s.avgBlockTime.toFixed(0) + 's' : 'N/A');
    return html;
}

function buildNodeCardsHTML(nodesData) {
    const nodes = nodesData.nodes || [];
    const consensusHeight = nodesData.consensusHeight || 0;
    let html = '<div class="nodes-grid">';
    for (const node of nodes) {
        const flag = FLAG_EMOJI[node.flag] || '';
        const isOnline = node.online;
        const statusClass = isOnline ? 'node-online' : 'node-offline';
        const statusText = isOnline ? 'Online' : 'Offline';
        const heightBehind = isOnline && consensusHeight > 0 && node.height !== null
            ? consensusHeight - node.height : 0;
        const syncStatus = heightBehind === 0 ? 'Synced' : heightBehind + ' behind';
        const syncClass = heightBehind === 0 ? 'synced' : 'behind';

        html += `<div class="node-card ${statusClass}">`;
        html += '<div class="node-card-header">';
        html += `<div class="node-card-title">${flag} ${escapeHtml(node.label)}${node.primary ? ' <span class="badge badge-info" style="font-size:0.65rem;vertical-align:middle;">PRIMARY</span>' : ''}</div>`;
        html += `<span class="node-status-badge ${statusClass}">${statusText}</span>`;
        html += '</div>';
        html += `<div class="node-card-ip mono">${escapeHtml(node.ip)}:${activeChain === 'dilv' ? '9444' : '8444'}</div>`;
        html += '<div class="node-card-stats">';
        html += `<div class="node-stat"><div class="node-stat-label">Block Height</div><div class="node-stat-value">${isOnline && node.height !== null ? formatNumber(node.height) : '\u2014'}</div></div>`;
        html += `<div class="node-stat"><div class="node-stat-label">Peers</div><div class="node-stat-value">${isOnline && node.peers !== null ? node.peers : '\u2014'}</div></div>`;
        html += `<div class="node-stat"><div class="node-stat-label">Sync</div><div class="node-stat-value node-sync-${syncClass}">${isOnline ? syncStatus : '\u2014'}</div></div>`;
        html += `<div class="node-stat"><div class="node-stat-label">Difficulty</div><div class="node-stat-value">${isOnline && node.difficulty != null ? Number(node.difficulty).toFixed(2) : '\u2014'}</div></div>`;
        html += '</div>';
        if (isOnline && node.version) {
            html += `<div class="node-card-version mono">${escapeHtml(node.version.replace(/\//g, ''))}</div>`;
        }
        html += '</div>';
    }
    html += '</div>';
    return html;
}

// ============================================================
// View: Home (with full dashboard)
// ============================================================

async function renderHome() {
    setTitle(null);
    showLoading();

    try {
        const [statsRes, blocksRes, nodesRes] = await Promise.all([
            apiFetch('/stats.php'),
            apiFetch('/blocks.php?limit=15'),
            apiFetch('/nodes.php'),
        ]);

        const stats = statsRes;
        let blocks = blocksRes.blocks || [];

        let html = '';

        // Network stats bar
        html += '<div class="stats-bar" id="home-stats-bar">';
        html += buildStatsBarHTML(stats, blocks);
        html += '</div>';

        // Seed node status panels
        html += '<div id="home-nodes">';
        html += buildNodeCardsHTML(nodesRes);
        html += '</div>';

        // Latest blocks table
        const homeCols = [
            { label: 'Height', sortable: true },
            { label: 'Hash', sortable: false },
            { label: 'Time', sortable: true },
            { label: 'Miner', sortable: false },
            { label: 'Txs', sortable: true, align: 'center' },
            { label: 'Reward', sortable: true, align: 'right' },
        ];

        html += '<div class="card">';
        html += '<div class="card-header"><h2>Latest Blocks</h2><a href="#/blocks" class="card-action">View all blocks &rarr;</a></div>';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table" data-sort-table="homeblocks">';
        html += '<thead><tr>' + makeSortableHeader('homeblocks', homeCols) + '</tr></thead>';
        html += '<tbody>';

        for (const block of blocks) {
            const height = block.height;
            const hash = block.hash || '';
            const time = block.time || block.mediantime || 0;
            const txCount = block.nTx || block.tx_count || (block.tx ? block.tx.length : 0);
            const miner = extractMiner(block);
            const reward = extractReward(block);

            html += '<tr>';
            html += `<td data-sort-value="${height}"><a href="#/block/${height}">${formatNumber(height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(hash)}" class="hash">${escapeHtml(formatHash(hash, 10))}</a></td>`;
            html += `<td data-sort-value="${time}" title="${escapeHtml(formatTime(time))}">${escapeHtml(formatAbsoluteTime(time))}</td>`;
            html += `<td>${miner ? `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(formatHash(miner, 8))}</a>` : '<span class="text-dim">Unknown</span>'}</td>`;
            html += `<td class="center" data-sort-value="${txCount}">${txCount}</td>`;
            html += `<td class="right amount" data-sort-value="${reward || 0}">${escapeHtml(formatAmount(reward))} ${UNIT}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div></div>';

        getApp().innerHTML = html;

        // Auto-refresh every 5 seconds (silent)
        refreshTimer = setInterval(async () => {
            if (currentRoute !== '#/' && currentRoute !== '#/home') return;
            try {
                const [freshStats, freshBlocks, freshNodes] = await Promise.all([
                    apiFetch('/stats.php'),
                    apiFetch('/blocks.php?limit=15'),
                    apiFetch('/nodes.php'),
                ]);

                // Update stats bar
                const statsEl = document.getElementById('home-stats-bar');
                if (statsEl) {
                    const newBlocks = freshBlocks.blocks || [];
                    statsEl.innerHTML = buildStatsBarHTML(freshStats, newBlocks);
                }

                // Update node cards
                const nodesEl = document.getElementById('home-nodes');
                if (nodesEl) {
                    nodesEl.innerHTML = buildNodeCardsHTML(freshNodes);
                }

                // Update blocks table when new block arrives
                const newBlocks = freshBlocks.blocks || [];
                if (newBlocks.length > 0 && blocks.length > 0 &&
                    newBlocks[0].height !== blocks[0].height) {
                    blocks = newBlocks;
                    const tbody = document.querySelector('.data-table tbody');
                    if (tbody) {
                        let rows = '';
                        for (const block of newBlocks) {
                            const miner = extractMiner(block);
                            const reward = extractReward(block);
                            const txCount = block.tx_count || block.nTx || (block.tx ? block.tx.length : 0);
                            rows += '<tr>';
                            rows += `<td><a href="#/block/${block.height}">${formatNumber(block.height)}</a></td>`;
                            rows += `<td><a href="#/block/${escapeHtml(block.hash)}" class="hash">${escapeHtml(formatHash(block.hash, 10))}</a></td>`;
                            rows += `<td title="${escapeHtml(formatTime(block.time))}">${escapeHtml(formatAbsoluteTime(block.time))}</td>`;
                            rows += `<td>${miner ? `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(formatHash(miner, 8))}</a>` : '<span class="text-dim">Unknown</span>'}</td>`;
                            rows += `<td class="center">${txCount}</td>`;
                            rows += `<td class="right amount">${escapeHtml(formatAmount(reward))} ${UNIT}</td>`;
                            rows += '</tr>';
                        }
                        tbody.innerHTML = rows;
                    }
                }
            } catch (e) {
                // Silent fail on refresh
            }
        }, REFRESH_INTERVAL);

    } catch (err) {
        showError('Failed to Load', err.message);
    }
}

function statCard(label, value, isMono) {
    return `<div class="stat-card"><div class="stat-label">${escapeHtml(label)}</div><div class="stat-value${isMono ? ' mono' : ''}">${escapeHtml(value)}</div></div>`;
}

function extractMiner(block) {
    // First check top-level miner field (available at all verbosity levels)
    if (block.miner) return block.miner;

    // Fallback: extract from coinbase tx outputs (verbosity=2 only)
    if (block.tx && block.tx.length > 0) {
        const coinbase = block.tx[0];
        if (typeof coinbase === 'object' && coinbase.vout) {
            for (const out of coinbase.vout) {
                const addr = out.address || out.scriptPubKey?.address || out.scriptPubKey?.addresses?.[0];
                if (addr && addr.startsWith('D')) return addr;
            }
        }
    }
    return null;
}

function extractReward(block) {
    // First try from coinbase tx outputs (verbosity=2)
    if (block.tx && block.tx.length > 0) {
        const coinbase = block.tx[0];
        if (typeof coinbase === 'object' && coinbase.vout) {
            let total = 0;
            for (const out of coinbase.vout) {
                total += out.value || 0;
            }
            return total;
        }
    }
    // Fallback block reward (in ions)
    return BLOCK_REWARD_FALLBACK * IONS_PER_DIL;
}

// ============================================================
// View: Block Detail
// ============================================================

async function renderBlock(id) {
    setTitle('Block ' + id);
    showLoading();

    try {
        let data;
        if (/^\d+$/.test(id)) {
            data = await apiFetch('/blocks.php?height=' + id + '&verbosity=2');
        } else {
            data = await apiFetch('/blocks.php?hash=' + encodeURIComponent(id) + '&verbosity=2');
        }

        const block = data.block;
        if (!block) throw new Error('Block not found');

        const height = block.height;
        setTitle('Block #' + formatNumber(height));

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Blocks', href: '#/blocks' },
            { label: 'Block #' + formatNumber(height) },
        ]);

        // Block header with nav
        html += '<div class="card">';
        html += '<div class="card-header">';
        html += '<h2>Block #' + escapeHtml(formatNumber(height)) + '</h2>';
        html += '<div class="block-nav">';
        if (height > 0) {
            html += `<a href="#/block/${height - 1}">${ICONS.chevronLeft} ${formatNumber(height - 1)}</a>`;
        } else {
            html += `<span class="disabled">${ICONS.chevronLeft} Prev</span>`;
        }
        if (block.nextblockhash) {
            html += `<a href="#/block/${height + 1}">${formatNumber(height + 1)} ${ICONS.chevronRight}</a>`;
        } else {
            html += `<span class="disabled">Next ${ICONS.chevronRight}</span>`;
        }
        html += '</div></div>';

        // Detail grid
        html += '<div class="detail-grid">';
        html += detailRow('Hash', `<span class="mono">${escapeHtml(block.hash)}</span>${makeCopyButton(block.hash)}`);
        html += detailRow('Previous Hash', block.previousblockhash ?
            `<a href="#/block/${escapeHtml(block.previousblockhash)}" class="hash mono">${escapeHtml(block.previousblockhash)}</a>${makeCopyButton(block.previousblockhash)}` :
            '<span class="text-dim">Genesis Block</span>');
        html += detailRow('Next Hash', block.nextblockhash ?
            `<a href="#/block/${escapeHtml(block.nextblockhash)}" class="hash mono">${escapeHtml(block.nextblockhash)}</a>${makeCopyButton(block.nextblockhash)}` :
            '<span class="text-dim">N/A (latest block)</span>');
        html += detailRow('Merkle Root', `<span class="mono">${escapeHtml(block.merkleroot)}</span>${makeCopyButton(block.merkleroot)}`);
        html += detailRow('Timestamp', escapeHtml(formatAbsoluteTime(block.time)) + ' <span class="text-muted">(' + escapeHtml(formatTime(block.time)) + ')</span>');
        html += detailRow('Confirmations', `<span class="badge badge-success">${escapeHtml(formatNumber(block.confirmations))}</span>`);
        html += detailRow('Difficulty', escapeHtml(block.difficulty != null ? Number(block.difficulty).toFixed(8) : 'N/A'));

        const miner = extractMiner(block);
        html += detailRow('Miner', miner ?
            `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(miner)}</a>${makeCopyButton(miner)}` :
            '<span class="text-dim">Unknown</span>');

        html += detailRow('Size', escapeHtml(formatSize(block.size)));
        html += detailRow('Nonce', `<span class="mono">${escapeHtml(String(block.nonce || ''))}</span>`);
        html += detailRow('nBits', `<span class="mono">${escapeHtml(block.bits || '')}</span>`);
        html += detailRow('Version', `<span class="mono">${escapeHtml(String(block.version || ''))}</span>`);
        html += '</div></div>';

        // Transactions
        const txs = block.tx || [];
        html += '<div class="card">';
        html += `<div class="card-header"><h2>Transactions (${txs.length})</h2></div>`;
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>#</th><th>TxID</th><th>From</th><th>To</th><th class="right">Amount</th></tr></thead>';
        html += '<tbody>';

        txs.forEach((tx, idx) => {
            if (typeof tx === 'string') {
                // verbosity=1 returns just txids
                html += `<tr><td>${idx + 1}</td><td><a href="#/tx/${escapeHtml(tx)}" class="hash">${escapeHtml(formatHash(tx, 12))}</a></td><td colspan="2" class="text-dim">Load transaction for details</td><td></td></tr>`;
                return;
            }

            const txid = tx.txid || tx.hash || '';
            const isCoinbase = tx.vin && tx.vin.length > 0 && tx.vin[0].coinbase;

            // From addresses
            let fromHtml = '';
            if (isCoinbase) {
                fromHtml = '<span class="coinbase-label">' + ICONS.pickaxe + ' Coinbase</span>';
            } else if (tx.vin) {
                const addrs = [];
                for (const vin of tx.vin) {
                    const addr = vin.prevout?.scriptPubKey?.address || vin.address;
                    if (addr && !addrs.includes(addr)) addrs.push(addr);
                }
                if (addrs.length > 0) {
                    fromHtml = addrs.slice(0, 3).map(a =>
                        `<a href="#/address/${escapeHtml(a)}" class="address">${escapeHtml(formatHash(a, 8))}</a>`
                    ).join(', ');
                    if (addrs.length > 3) fromHtml += ` <span class="text-dim">+${addrs.length - 3} more</span>`;
                } else {
                    // No prevout data - show input count as context
                    fromHtml = `<span class="text-muted">${tx.vin.length} input${tx.vin.length !== 1 ? 's' : ''}</span>`;
                }
            }

            // To addresses and amount
            let toHtml = '';
            let totalOut = 0;
            if (tx.vout) {
                const addrs = [];
                for (const vout of tx.vout) {
                    totalOut += vout.value || 0;
                    const addr = vout.address || vout.scriptPubKey?.address || vout.scriptPubKey?.addresses?.[0];
                    if (addr && !addrs.includes(addr)) addrs.push(addr);
                }
                toHtml = addrs.slice(0, 3).map(a =>
                    `<a href="#/address/${escapeHtml(a)}" class="address">${escapeHtml(formatHash(a, 8))}</a>`
                ).join(', ');
                if (addrs.length > 3) toHtml += ` <span class="text-dim">+${addrs.length - 3} more</span>`;
            }

            html += `<tr>`;
            html += `<td>${idx + 1}</td>`;
            html += `<td><a href="#/tx/${escapeHtml(txid)}" class="hash">${escapeHtml(formatHash(txid, 12))}</a></td>`;
            html += `<td>${fromHtml}</td>`;
            html += `<td>${toHtml}</td>`;
            html += `<td class="right amount">${escapeHtml(formatAmount(totalOut))} ${UNIT}</td>`;
            html += `</tr>`;
        });

        html += '</tbody></table></div></div></div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Block Not Found', err.message);
    }
}

function detailRow(label, valueHtml) {
    return `<div class="detail-row"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${valueHtml}</div></div>`;
}

// ============================================================
// View: Transaction Detail
// ============================================================

function renderTxIoItem(addr, val, hasValue) {
    let html = '<div class="tx-io-item">';
    if (addr) {
        html += `<a href="#/address/${escapeHtml(addr)}" class="address">${escapeHtml(formatHash(addr, 10))}</a>`;
    } else {
        html += '<span class="text-dim">OP_RETURN / Unreadable</span>';
    }
    if (hasValue) {
        html += `<span class="amount">${escapeHtml(formatAmount(val))} ${UNIT}</span>`;
    }
    return html + '</div>';
}

function renderTxInputItem(vin) {
    const addr = vin.prevout?.scriptPubKey?.address || vin.address || null;
    const val = vin.prevout?.value || vin.value || 0;
    const hasValue = !!(vin.prevout?.value || vin.value);

    // If we have address and value, show normally
    if (addr && hasValue) {
        return renderTxIoItem(addr, val, true);
    }

    // No prevout data - show a reference link to the source transaction
    const srcTxid = vin.txid;
    const srcVout = vin.vout;
    if (srcTxid && srcTxid !== '0000000000000000000000000000000000000000000000000000000000000000') {
        let html = '<div class="tx-io-item tx-io-item-ref">';
        html += `<a href="#/tx/${escapeHtml(srcTxid)}" class="hash" title="View source transaction">${escapeHtml(formatHash(srcTxid, 8))}:${srcVout}</a>`;
        if (hasValue) {
            html += `<span class="amount">${escapeHtml(formatAmount(val))} ${UNIT}</span>`;
        } else {
            html += `<span class="amount text-dim">view tx &#8594;</span>`;
        }
        html += '</div>';
        return html;
    }

    return renderTxIoItem(addr, val, hasValue);
}

function renderCollapsibleItems(items, containerId, renderFn) {
    if (items.length <= COLLAPSE_THRESHOLD) {
        return items.map(renderFn).join('');
    }

    let html = '';
    // Show first few items
    for (let i = 0; i < COLLAPSE_THRESHOLD; i++) {
        html += renderFn(items[i]);
    }

    // Expand button
    const remaining = items.length - COLLAPSE_THRESHOLD;
    html += `<button class="expand-btn" data-target="${escapeHtml(containerId)}" data-more-text="Show all ${items.length} items" data-less-text="Show less">Show all ${items.length} items (+${remaining} more)</button>`;

    // Hidden items
    html += `<div id="${escapeHtml(containerId)}" style="display:none">`;
    for (let i = COLLAPSE_THRESHOLD; i < items.length; i++) {
        html += renderFn(items[i]);
    }
    html += '</div>';

    return html;
}

async function renderTransaction(txid) {
    setTitle('Transaction ' + formatHash(txid, 12));
    showLoading();

    try {
        const data = await apiFetch('/tx.php?txid=' + encodeURIComponent(txid));
        const tx = data.transaction;
        if (!tx) throw new Error('Transaction not found');

        const realTxid = tx.txid || tx.hash || txid;
        setTitle('TX ' + formatHash(realTxid, 10));

        const txType = detectTxType(tx);
        const isCoinbase = txType.type === 'coinbase';
        const confirmations = tx.confirmations || 0;

        // Pre-calculate totals
        let totalIn = 0;
        let hasInputValues = false;
        if (!isCoinbase && tx.vin) {
            for (const vin of tx.vin) {
                const val = vin.prevout?.value || vin.value || 0;
                if (val > 0) hasInputValues = true;
                totalIn += val;
            }
        }
        let totalOut = 0;
        if (tx.vout) {
            for (const vout of tx.vout) {
                totalOut += vout.value || 0;
            }
        }
        const fee = isCoinbase ? 0 : (hasInputValues ? Math.max(0, totalIn - totalOut) : 0);

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Transaction' },
        ]);

        // Main card
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Transaction Details</h2>';
        html += '<div class="card-header-badges">';
        html += `<span class="badge ${txType.badge}">${txType.icon ? txType.icon + ' ' : ''}${escapeHtml(txType.label)}</span>`;
        if (confirmations > 0) {
            html += `<span class="badge badge-success">Confirmed (${formatNumber(confirmations)})</span>`;
        } else {
            html += '<span class="badge badge-warning">Pending</span>';
        }
        html += '</div></div>';

        // Detail grid
        html += '<div class="detail-grid">';
        html += detailRow('TxID', `<span class="mono">${escapeHtml(realTxid)}</span>${makeCopyButton(realTxid)}`);

        if (tx.blockhash) {
            html += detailRow('Block', `<a href="#/block/${escapeHtml(tx.blockhash)}" class="hash mono">${escapeHtml(formatHash(tx.blockhash, 16))}</a>`);
        }
        if (tx.blockheight != null) {
            html += detailRow('Block Height', `<a href="#/block/${tx.blockheight}">${formatNumber(tx.blockheight)}</a>`);
        }
        if (tx.time || tx.blocktime) {
            html += detailRow('Timestamp', escapeHtml(formatAbsoluteTime(tx.time || tx.blocktime)));
        }
        html += detailRow('Confirmations', confirmations > 0 ? formatNumber(confirmations) : '<span class="text-warning">Unconfirmed</span>');
        html += detailRow('Version', `<span class="mono">${escapeHtml(String(tx.version || ''))}</span>`);
        html += detailRow('Lock Time', `<span class="mono">${escapeHtml(String(tx.locktime || 0))}</span>`);
        html += '</div></div>';

        // Inputs / Outputs visualization
        html += '<div class="card">';

        // Summary bar at top showing totals
        html += '<div class="tx-summary-top">';
        if (isCoinbase) {
            html += `<div class="tx-summary-item"><span class="tx-summary-label">Type</span><span class="tx-summary-value">${ICONS.pickaxe} New coins mined</span></div>`;
            html += `<div class="tx-summary-item"><span class="tx-summary-label">Reward</span><span class="tx-summary-value">${escapeHtml(formatAmount(totalOut))} ${UNIT}</span></div>`;
        } else {
            const inputLabel = tx.vin ? `${tx.vin.length} Input${tx.vin.length !== 1 ? 's' : ''}` : '0 Inputs';
            const outputLabel = tx.vout ? `${tx.vout.length} Output${tx.vout.length !== 1 ? 's' : ''}` : '0 Outputs';
            html += `<div class="tx-summary-item"><span class="tx-summary-label">${escapeHtml(inputLabel)}</span>`;
            if (hasInputValues) {
                html += `<span class="tx-summary-value">${escapeHtml(formatAmount(totalIn))} ${UNIT}</span>`;
            }
            html += '</div>';
            html += `<div class="tx-summary-arrow">${ICONS.arrow}</div>`;
            html += `<div class="tx-summary-item"><span class="tx-summary-label">${escapeHtml(outputLabel)}</span><span class="tx-summary-value">${escapeHtml(formatAmount(totalOut))} ${UNIT}</span></div>`;
            if (hasInputValues && fee > 0) {
                html += `<div class="tx-summary-item"><span class="tx-summary-label">Fee</span><span class="tx-summary-value">${escapeHtml(formatAmount(fee))} ${UNIT}</span></div>`;
            }
        }
        html += '</div>';

        html += '<div class="card-body">';
        html += '<div class="tx-io">';

        // Inputs
        html += '<div class="tx-io-inputs">';
        html += `<div class="tx-io-label">Inputs${!isCoinbase && tx.vin ? ' (' + tx.vin.length + ')' : ''}</div>`;
        if (isCoinbase) {
            html += '<div class="tx-io-item"><span class="coinbase-label">' + ICONS.pickaxe + ' Coinbase (Newly Generated Coins)</span></div>';
        } else if (tx.vin) {
            html += renderCollapsibleItems(tx.vin, 'tx-inputs-more', renderTxInputItem);
        }
        html += '</div>';

        // Arrow
        html += `<div class="tx-io-arrow">${ICONS.arrow}</div>`;

        // Outputs
        html += '<div class="tx-io-outputs">';
        html += `<div class="tx-io-label">Outputs${tx.vout ? ' (' + tx.vout.length + ')' : ''}</div>`;
        if (tx.vout) {
            html += renderCollapsibleItems(tx.vout, 'tx-outputs-more', (vout) => {
                const addr = vout.address || vout.scriptPubKey?.address || vout.scriptPubKey?.addresses?.[0] || null;
                const val = vout.value || 0;
                return renderTxIoItem(addr, val, true);
            });
        }
        html += '</div>';
        html += '</div>'; // tx-io
        html += '</div>'; // card-body

        // Summary bar at bottom
        html += '<div class="summary-bar">';
        if (!isCoinbase && hasInputValues) {
            html += `<span><span class="label">Total Input: </span><span class="value">${escapeHtml(formatAmount(totalIn))} ${UNIT}</span></span>`;
        }
        html += `<span><span class="label">Total Output: </span><span class="value">${escapeHtml(formatAmount(totalOut))} ${UNIT}</span></span>`;
        if (!isCoinbase && hasInputValues && fee > 0) {
            html += `<span><span class="label">Fee: </span><span class="value">${escapeHtml(formatAmount(fee))} ${UNIT}</span></span>`;
        }
        html += '</div>';
        html += '</div>';

        // Explanation for consolidation transactions
        if (txType.type === 'consolidation') {
            html += '<div class="card"><div class="info-text">';
            html += '<strong>What is a consolidation transaction?</strong> This transaction combines many small inputs (UTXOs) into fewer, larger outputs. ';
            html += 'This is normal housekeeping &mdash; like exchanging a pile of small coins for a few large bills. ';
            html += 'All inputs come from previous transactions on the blockchain. No new coins are created.';
            html += '</div></div>';
        }

        getApp().innerHTML = html;

    } catch (err) {
        showError('Transaction Not Found', err.message);
    }
}

// ============================================================
// View: Address
// ============================================================

async function renderAddress(addr) {
    setTitle('Address ' + formatHash(addr, 10));
    showLoading();

    try {
        const data = await apiFetch('/address.php?addr=' + encodeURIComponent(addr));

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Address' },
        ]);

        // Address overview card
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Address</h2></div>';
        html += '<div class="detail-grid">';
        html += detailRow('Address', `<span class="mono address" style="color:var(--accent)">${escapeHtml(data.address)}</span>${makeCopyButton(data.address)}`);

        const balance = data.balance;
        if (balance !== null && balance !== undefined) {
            // Balance could be in satoshis or DIL depending on the REST API
            const balanceDisplay = typeof balance === 'object' ?
                formatAmount(balance.balance || balance.confirmed || 0) :
                formatAmount(balance);
            html += detailRow('Balance', `<span class="font-bold" style="font-size:18px">${escapeHtml(balanceDisplay)} ${UNIT}</span>`);
        } else {
            html += detailRow('Balance', '<span class="text-dim">Unable to fetch balance</span>');
        }

        const utxos = data.utxos;
        const utxoList = Array.isArray(utxos) ? utxos : (utxos?.utxos || []);
        html += detailRow('UTXO Count', String(utxoList.length));
        html += '</div></div>';

        // UTXO table
        if (utxoList.length > 0) {
            const utxoCols = [
                { label: 'TxID', sortable: false },
                { label: 'Output Index', sortable: true, align: 'center' },
                { label: 'Amount', sortable: true, align: 'right' },
                { label: 'Confirmations', sortable: true, align: 'center' },
            ];

            html += '<div class="card">';
            html += `<div class="card-header"><h2>UTXOs (${utxoList.length})</h2></div>`;
            html += '<div class="card-body-flush"><div class="table-container">';
            html += '<table class="data-table" data-sort-table="utxos">';
            html += '<thead><tr>' + makeSortableHeader('utxos', utxoCols) + '</tr></thead>';
            html += '<tbody>';

            for (const utxo of utxoList) {
                const utxoTxid = utxo.txid || utxo.tx_hash || '';
                const voutIdx = utxo.vout != null ? utxo.vout : (utxo.tx_pos != null ? utxo.tx_pos : '');
                const amount = utxo.value != null ? utxo.value : (utxo.amount || 0);
                const confs = utxo.confirmations || 0;

                html += '<tr>';
                html += `<td><a href="#/tx/${escapeHtml(utxoTxid)}" class="hash">${escapeHtml(formatHash(utxoTxid, 12))}</a></td>`;
                html += `<td class="center" data-sort-value="${voutIdx}">${escapeHtml(String(voutIdx))}</td>`;
                html += `<td class="right amount" data-sort-value="${amount}">${escapeHtml(formatAmount(amount))} ${UNIT}</td>`;
                html += `<td class="center" data-sort-value="${confs}">${confs ? escapeHtml(formatNumber(confs)) : '<span class="text-dim">N/A</span>'}</td>`;
                html += '</tr>';
            }

            html += '</tbody></table></div></div></div>';
        } else {
            html += '<div class="card"><div class="card-body"><div class="empty-state">No UTXOs found for this address.</div></div></div>';
        }

        getApp().innerHTML = html;

    } catch (err) {
        showError('Address Error', err.message);
    }
}

// ============================================================
// View: Block List (paginated)
// ============================================================

async function renderBlockList(page) {
    page = page || 1;
    setTitle('Blocks - Page ' + page);
    showLoading();

    try {
        const data = await apiFetch('/blocks.php?page=' + page + '&limit=' + ITEMS_PER_PAGE);
        const blocks = data.blocks || [];
        const totalHeight = data.totalHeight || 0;
        const totalPages = Math.ceil((totalHeight + 1) / ITEMS_PER_PAGE);

        let html = '';

        html += '<div class="page-header"><h1>All Blocks</h1><p>' + formatNumber(totalHeight + 1) + ' blocks on the Dilithion blockchain</p></div>';

        const blkCols = [
            { label: 'Height', sortable: true },
            { label: 'Hash', sortable: false },
            { label: 'Time', sortable: true },
            { label: 'Miner', sortable: false },
            { label: 'Txs', sortable: true, align: 'center' },
            { label: 'Reward', sortable: true, align: 'right' },
            { label: 'Size', sortable: true, align: 'right' },
        ];

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table" data-sort-table="blocklist">';
        html += '<thead><tr>' + makeSortableHeader('blocklist', blkCols) + '</tr></thead>';
        html += '<tbody>';

        for (const block of blocks) {
            const height = block.height;
            const hash = block.hash || '';
            const time = block.time || 0;
            const txCount = block.nTx || block.tx_count || (block.tx ? block.tx.length : 0);
            const miner = extractMiner(block);
            const reward = extractReward(block);

            html += '<tr>';
            html += `<td data-sort-value="${height}"><a href="#/block/${height}">${formatNumber(height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(hash)}" class="hash">${escapeHtml(formatHash(hash, 8))}</a></td>`;
            html += `<td data-sort-value="${time}" title="${escapeHtml(formatTime(time))}">${escapeHtml(formatAbsoluteTime(time))}</td>`;
            html += `<td>${miner ? `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(formatHash(miner, 6))}</a>` : '<span class="text-dim">Unknown</span>'}</td>`;
            html += `<td class="center" data-sort-value="${txCount}">${txCount}</td>`;
            html += `<td class="right amount" data-sort-value="${reward || 0}">${reward != null ? escapeHtml(formatAmount(reward)) + ' ' + UNIT : ''}</td>`;
            html += `<td class="right text-muted" data-sort-value="${block.size || 0}">${block.size ? escapeHtml(formatSize(block.size)) : ''}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';

        // Pagination
        html += '<div class="pagination">';

        if (page > 1) {
            html += `<a href="#/blocks/${page - 1}">${ICONS.chevronLeft} Prev</a>`;
        } else {
            html += `<span class="disabled">${ICONS.chevronLeft} Prev</span>`;
        }

        // Page numbers
        const maxVisible = 5;
        let startPage = Math.max(1, page - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }

        if (startPage > 1) {
            html += `<a href="#/blocks/1">1</a>`;
            if (startPage > 2) html += `<span class="disabled">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            if (i === page) {
                html += `<span class="active">${i}</span>`;
            } else {
                html += `<a href="#/blocks/${i}">${i}</a>`;
            }
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<span class="disabled">...</span>`;
            html += `<a href="#/blocks/${totalPages}">${totalPages}</a>`;
        }

        if (page < totalPages) {
            html += `<a href="#/blocks/${page + 1}">Next ${ICONS.chevronRight}</a>`;
        } else {
            html += `<span class="disabled">Next ${ICONS.chevronRight}</span>`;
        }

        html += '</div></div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Failed to Load Blocks', err.message);
    }
}

// ============================================================
// View: Forks (Chain Tips)
// ============================================================

async function renderForks() {
    setTitle('Chain Tips');
    showLoading();

    try {
        const data = await apiFetch('/stats.php');
        const chainTips = data.chainTips || [];

        let html = '';

        html += '<div class="page-header"><h1>Chain Tips</h1><p>All known chain tips, including forks and the active best chain.</p></div>';

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>Status</th><th>Height</th><th>Hash</th><th class="center">Branch Length</th></tr></thead>';
        html += '<tbody>';

        if (chainTips.length === 0) {
            html += '<tr><td colspan="4" class="text-center text-dim" style="padding:30px">No chain tip data available</td></tr>';
        }

        for (const tip of chainTips) {
            const status = tip.status || 'unknown';
            let badgeClass = 'badge-muted';
            if (status === 'active') badgeClass = 'badge-success';
            else if (status === 'valid-fork') badgeClass = 'badge-warning';
            else if (status === 'valid-headers') badgeClass = 'badge-info';
            else if (status === 'headers-only') badgeClass = 'badge-info';
            else if (status === 'invalid') badgeClass = 'badge-danger';

            html += '<tr>';
            html += `<td><span class="badge ${badgeClass}">${escapeHtml(status)}</span></td>`;
            html += `<td><a href="#/block/${tip.height}">${formatNumber(tip.height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(tip.hash)}" class="hash">${escapeHtml(formatHash(tip.hash, 16))}</a></td>`;
            html += `<td class="center">${tip.branchlen != null ? tip.branchlen : 'N/A'}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';

        // Explanation
        html += '<div class="info-text">';
        html += '<strong>What are chain tips?</strong> Chain tips represent the ends of all known blockchain branches. ';
        html += 'The <strong>"active"</strong> tip is the current best chain that nodes follow. ';
        html += '<strong>"valid-fork"</strong> tips are alternative chains with valid blocks that branched off from the main chain. ';
        html += '<strong>"valid-headers"</strong> means headers were received but blocks haven\'t been fully validated yet. ';
        html += 'A <strong>branch length</strong> of 0 means the tip is on the main chain.';
        html += '</div>';

        html += '</div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Failed to Load Chain Tips', err.message);
    }
}

// ============================================================
// Search Handler
// ============================================================

async function handleSearch(query) {
    query = decodeURIComponent(query).trim();
    if (!query) {
        window.location.hash = '#/';
        return;
    }

    setTitle('Search: ' + query);
    showLoading();

    try {
        const data = await apiFetch('/search.php?q=' + encodeURIComponent(query));

        if (data.type === 'block') {
            const blockHash = data.result?.hash;
            const blockHeight = data.result?.height;
            window.location.hash = '#/block/' + (blockHeight != null ? blockHeight : blockHash);
            return;
        }

        if (data.type === 'tx') {
            const txid = data.result?.txid || data.result?.hash || query;
            window.location.hash = '#/tx/' + txid;
            return;
        }

        if (data.type === 'address') {
            const addr = data.result?.address || query;
            window.location.hash = '#/address/' + addr;
            return;
        }

        if (data.type === 'address_prefix') {
            renderAddressPrefixResults(data.result);
            return;
        }

        // Unknown
        showError('Not Found', data.message || 'No results found for "' + query + '". Try a block height, block hash, transaction ID, or address.');

    } catch (err) {
        showError('Search Failed', err.message);
    }
}

// ============================================================
// View: Address Prefix Search Results
// ============================================================

function renderAddressPrefixResults(result) {
    const prefix = result.prefix || '';
    const matches = result.matches || [];
    const total = result.total_matches || 0;

    let totalBalance = 0;
    for (const m of matches) totalBalance += (m.balance || 0);

    let html = '';
    html += '<div class="page-header"><h1>Address Search: ' + escapeHtml(prefix) + '*</h1>';
    html += '<p>' + formatNumber(total) + ' address' + (total !== 1 ? 'es' : '') + ' found';
    if (total > 0) html += ' — total balance: ' + formatNumber(Math.floor(totalBalance)) + ' ' + UNIT;
    html += '</p></div>';

    if (total === 0) {
        html += '<div class="card"><div class="card-body"><p>No addresses with a balance match the prefix "' + escapeHtml(prefix) + '".</p></div></div>';
        getApp().innerHTML = html;
        return;
    }

    html += '<div class="card">';
    html += '<div class="card-body-flush"><div class="table-container">';
    html += '<table class="data-table">';
    html += '<thead><tr>';
    html += '<th class="center">Rank</th>';
    html += '<th>Address</th>';
    html += '<th class="right">Balance</th>';
    html += '</tr></thead>';
    html += '<tbody>';

    for (const m of matches) {
        const balance = m.balance || 0;
        html += '<tr>';
        html += '<td class="center">' + m.rank + '</td>';
        html += '<td><a href="#/address/' + escapeHtml(m.address) + '" class="address">' + escapeHtml(m.address) + '</a></td>';
        html += '<td class="right amount">' + formatNumber(Math.floor(balance)) + ' ' + UNIT + '</td>';
        html += '</tr>';
    }

    html += '</tbody></table></div></div>';
    html += '</div>';

    getApp().innerHTML = html;
}

// ============================================================
// Search Bar Event Listeners
// ============================================================

function initSearchBar() {
    const input = document.getElementById('search-input');
    if (!input) return;

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const query = input.value.trim();
            if (query) {
                window.location.hash = '#/search/' + encodeURIComponent(query);
                input.value = '';
                input.blur();
            }
        }
    });

    // Global keyboard shortcut: "/" focuses search
    document.addEventListener('keydown', function (e) {
        if (e.key === '/' && document.activeElement !== input && document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            input.focus();
        }
    });
}

// ============================================================
// View: Nodes (dedicated page)
// ============================================================

async function renderNodes() {
    setTitle('Seed Nodes');
    showLoading();

    try {
        const data = await apiFetch('/nodes.php');
        const nodes = data.nodes || [];
        const consensusHeight = data.consensusHeight || 0;

        let html = '';
        html += '<div class="page-header"><h1>Seed Node Status</h1>';
        html += `<p>Real-time status of the ${UNIT} mainnet seed nodes. Consensus height: <strong>${formatNumber(consensusHeight)}</strong></p>`;
        html += '</div>';

        const onlineCount = nodes.filter(n => n.online).length;
        html += '<div class="stats-bar">';
        html += statCard('Nodes Online', `${onlineCount} / ${nodes.length}`);
        html += statCard('Consensus Height', formatNumber(consensusHeight));
        const maxPeers = Math.max(...nodes.map(n => n.peers || 0));
        html += statCard('Max Peers', formatNumber(maxPeers));
        const versions = [...new Set(nodes.filter(n => n.version).map(n => n.version))];
        html += statCard('Version', versions.length === 1 ? versions[0].replace(/\//g, '') : versions.length > 0 ? 'Mixed' : 'N/A');
        html += '</div>';

        html += '<div id="nodes-cards">';
        html += buildNodeCardsHTML(data);
        html += '</div>';

        getApp().innerHTML = html;

        // Auto-refresh every 5 seconds
        refreshTimer = setInterval(async () => {
            if (currentRoute !== '#/nodes') return;
            try {
                const fresh = await apiFetch('/nodes.php');
                const el = document.getElementById('nodes-cards');
                if (el) el.innerHTML = buildNodeCardsHTML(fresh);
            } catch (e) { /* silent */ }
        }, REFRESH_INTERVAL);

    } catch (err) {
        showError('Failed to Load Node Status', err.message);
    }
}

// ============================================================
// Init
// ============================================================

document.addEventListener('DOMContentLoaded', function () {
    initSearchBar();
    // Apply saved chain state on load
    if (activeChain === 'dilv') {
        const titleEl = document.querySelector('.navbar-title');
        if (titleEl) titleEl.textContent = 'DILV EXPLORER';
        document.title = 'DilV Explorer';
    }
    const dilBtn = document.getElementById('chainBtnDil');
    const dilvBtn = document.getElementById('chainBtnDilv');
    if (dilBtn && dilvBtn) {
        dilBtn.classList.toggle('active', activeChain === 'dil');
        dilvBtn.classList.toggle('active', activeChain === 'dilv');
    }
    router.route();
});

// ============================================================
// Top Holders Page
// ============================================================

async function renderHolders() {
    setTitle('Top Holders');
    showLoading();

    try {
        const data = await apiFetch('/holders.php?count=100');
        const holders = data.top || [];
        const totalHolders = data.holders || 0;
        const supply = data.supply || 0;

        let html = '';
        html += '<div class="page-header"><h1>Top Holders</h1>';
        html += '<p>' + formatNumber(totalHolders) + ' unique addresses holding ' + UNIT + '</p></div>';

        const cols = [
            { label: 'Rank', sortable: true, align: 'center' },
            { label: 'Address', sortable: false },
            { label: 'Balance', sortable: true, align: 'right' },
            { label: '% of Supply', sortable: true, align: 'right' },
        ];

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table" data-sort-table="holders">';
        html += '<thead><tr>' + makeSortableHeader('holders', cols) + '</tr></thead>';
        html += '<tbody>';

        for (const h of holders) {
            const balance = h.balance || 0;
            const pct = supply > 0 ? (balance / supply * 100) : 0;

            html += '<tr>';
            html += `<td class="center" data-sort-value="${h.rank}">${h.rank}</td>`;
            const addrLabel = h.label ? ` <span class="badge badge-info" style="font-size:0.65rem;vertical-align:middle;">${escapeHtml(h.label)}</span>` : '';
            html += `<td><a href="#/address/${escapeHtml(h.address)}" class="address">${escapeHtml(h.address)}</a>${addrLabel}</td>`;
            html += `<td class="right amount" data-sort-value="${balance}">${formatNumber(Math.floor(balance))} ${UNIT}</td>`;
            html += `<td class="right" data-sort-value="${pct}">${pct.toFixed(2)}%</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';
        html += '</div>';

        getApp().innerHTML = html;
    } catch (e) {
        showError('Failed to load holders', e.message);
    }
}

// ============================================================
// Recent Transactions Page
// ============================================================

async function renderTransactions(page) {
    page = page || 1;
    setTitle('Transactions - Page ' + page);
    showLoading();

    try {
        const data = await apiFetch('/transactions.php?limit=50');
        const transactions = data.transactions || [];
        const tipHeight = data.tip_height || 0;

        let html = '';
        html += '<div class="page-header"><h1>Recent Transactions</h1>';
        html += '<p>Latest transactions from the ' + (activeChain === 'dilv' ? 'DilV' : 'Dilithion') + ' blockchain</p></div>';

        const cols = [
            { label: 'TxID', sortable: false },
            { label: 'Block', sortable: true, align: 'center' },
            { label: 'Time', sortable: true },
            { label: 'Type', sortable: false, align: 'center' },
            { label: 'Amount', sortable: true, align: 'right' },
            { label: 'To', sortable: false },
        ];

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table" data-sort-table="txlist">';
        html += '<thead><tr>' + makeSortableHeader('txlist', cols) + '</tr></thead>';
        html += '<tbody>';

        for (const tx of transactions) {
            const txid = tx.txid || '';
            const blockHeight = tx.block_height;
            const time = tx.time || 0;
            const isCoinbase = tx.coinbase;
            const totalOutput = tx.total_output || 0;
            const outputs = tx.outputs || [];

            // Primary recipient (first non-change output, or first output)
            const primaryTo = outputs.length > 0 ? outputs[0].address : '';

            html += '<tr>';
            html += `<td><a href="#/tx/${escapeHtml(txid)}" class="hash">${escapeHtml(formatHash(txid, 10))}</a></td>`;
            html += `<td class="center" data-sort-value="${blockHeight}"><a href="#/block/${blockHeight}">${formatNumber(blockHeight)}</a></td>`;
            html += `<td data-sort-value="${time}" title="${escapeHtml(formatTime(time))}">${escapeHtml(formatAbsoluteTime(time))}</td>`;
            html += `<td class="center"><span class="badge ${isCoinbase ? 'badge-reward' : 'badge-tx'}">${isCoinbase ? 'Reward' : 'Transfer'}</span></td>`;
            html += `<td class="right amount" data-sort-value="${totalOutput}">${formatNumber(Math.floor(totalOutput / IONS_PER_DIL))} ${UNIT}</td>`;
            html += `<td>${primaryTo ? `<a href="#/address/${escapeHtml(primaryTo)}" class="address">${escapeHtml(formatHash(primaryTo, 8))}</a>` : '<span class="text-dim">-</span>'}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';
        html += '</div>';

        getApp().innerHTML = html;
    } catch (e) {
        showError('Failed to load transactions', e.message);
    }
}
