'use strict';

const { Plugin, ItemView, Modal, Notice, Setting, PluginSettingTab } = require('obsidian');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const VIEW_TYPE = 'bitwarden-panel';
const DEFAULT_SETTINGS = {
    bwPath: 'bw',
    useIcons: true,
    iconServer: 'https://icons.bitwarden.net',
    viewMode: 'type', // 'type' | 'folder'
};

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
    'shield': '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    'alert-triangle': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    'alert-circle': '<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>',
    'lock': '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    'refresh-cw': '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>',
    'search': '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    'loader-2': '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>',
    'key-round': '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    'credit-card': '<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/>',
    'file-text': '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/>',
    'user': '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    'file': '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    'star': '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    'copy': '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    'eye': '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off': '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>',
    'clock': '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    'folder': '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
    'list': '<line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/>',
    'arrow-left': '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
};

function setIcon(el, name) {
    while (el.firstChild) el.removeChild(el.firstChild);
    const inner = ICONS[name];
    if (!inner) return;
    const svg = new DOMParser().parseFromString(
        `<svg xmlns="${SVG_NS}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`,
        'image/svg+xml'
    ).documentElement;
    el.appendChild(svg);
}

function extractDomain(uri) {
    if (!uri) return null;
    try {
        return new URL(uri.startsWith('http') ? uri : `https://${uri}`).hostname;
    } catch {
        return null;
    }
}

// --- TOTP ---

function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const s = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = '';
    for (const ch of s) {
        const idx = alphabet.indexOf(ch);
        if (idx < 0) continue;
        bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    return bytes;
}

function parseTotpUri(totpValue) {
    if (!totpValue) return null;
    let secret = totpValue, digits = 6, period = 30;
    if (totpValue.startsWith('otpauth://')) {
        try {
            const url = new URL(totpValue);
            secret = url.searchParams.get('secret') || '';
            digits = parseInt(url.searchParams.get('digits') || '6', 10);
            period = parseInt(url.searchParams.get('period') || '30', 10);
        } catch { return null; }
    }
    if (!secret) return null;
    return { secret, digits, period };
}

async function generateTotp(secret, digits = 6, period = 30) {
    const key = await crypto.subtle.importKey(
        'raw',
        base32Decode(secret),
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setUint32(4, counter, false);
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
    const offset = hmac[19] & 0xf;
    const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % (10 ** digits);
    return code.toString().padStart(digits, '0');
}

// ---

class BitwardenPlugin extends Plugin {
    sessionToken = null;

    async onload() {
        await this.loadSettings();
        this.registerView(VIEW_TYPE, (leaf) => new BitwardenView(leaf, this));
        this.addRibbonIcon('shield', 'Bitwarden', () => this.activateView());
        this.addCommand({
            id: 'open-bitwarden',
            name: 'Bitwardenパネルを開く',
            callback: () => this.activateView(),
        });
        this.addSettingTab(new BitwardenSettingTab(this.app, this));
    }

    async onunload() {
        this.sessionToken = null;
        this.app.workspace.detachLeavesOfType(VIEW_TYPE);
    }

    async activateView() {
        const { workspace } = this.app;
        let [leaf] = workspace.getLeavesOfType(VIEW_TYPE);
        if (!leaf) {
            leaf = workspace.getRightLeaf(false);
            if (leaf) await leaf.setViewState({ type: VIEW_TYPE, active: true });
        }
        if (leaf) workspace.revealLeaf(leaf);
    }

    async execBw(args) {
        try {
            const { stdout } = await execFileAsync(this.settings.bwPath || 'bw', args);
            return stdout.trim();
        } catch (err) {
            if (err.code === 'ENOENT') throw new Error('BW_NOT_FOUND');
            const text = (err.stderr || '') + (err.stdout || '') + (err.message || '');
            if (
                text.includes('Invalid refresh token') ||
                text.includes('Unable to refresh login credentials')
            ) {
                throw new Error('REFRESH_TOKEN_INVALID');
            }
            if (
                text.includes('mac failed') ||
                text.includes('Session key is invalid') ||
                text.includes('You are not logged in') ||
                text.includes('Not logged in')
            ) {
                throw new Error('SESSION_INVALID');
            }
            throw err;
        }
    }

    async getStatus() {
        try {
            return JSON.parse(await this.execBw(['status']));
        } catch (err) {
            if (err.message === 'BW_NOT_FOUND') return { status: 'not_found' };
            if (err.message === 'REFRESH_TOKEN_INVALID') return { status: 'refresh_token_invalid' };
            return { status: 'error' };
        }
    }

    async unlock(password) {
        const out = await this.execBw(['unlock', '--raw', password]);
        this.sessionToken = out;
        this.settings.sessionToken = out;
        await this.saveSettings();
    }

    async lock() {
        try { await this.execBw(['lock']); } catch {}
        this.sessionToken = null;
        this.settings.sessionToken = null;
        await this.saveSettings();
    }

    async sync() {
        await this.execBw(['sync', '--session', this.sessionToken]);
    }

    async listItems(search = '') {
        const args = ['list', 'items', '--session', this.sessionToken];
        if (search) args.push('--search', search);
        const out = await this.execBw(args);
        if (!out) return [];
        const parsed = JSON.parse(out);
        return Array.isArray(parsed) ? parsed : [];
    }

    async listFolders() {
        const out = await this.execBw(['list', 'folders', '--session', this.sessionToken]);
        if (!out) return [];
        const parsed = JSON.parse(out);
        return Array.isArray(parsed) ? parsed : [];
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        this.sessionToken = this.settings.sessionToken || null;
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }
}

class BitwardenView extends ItemView {
    constructor(leaf, plugin) {
        super(leaf);
        this.plugin = plugin;
        this.listContainer = null;
        this.searchBar = null;
        this.searchInput = null;
        this.searchTimer = null;
        this.folderNav = null; // null = folder home, { id, name } = inside a folder
        this.itemsCache = null;
        this.foldersCache = null;
    }

    getViewType() { return VIEW_TYPE; }
    getDisplayText() { return 'Bitwarden'; }
    getIcon() { return 'shield'; }

    async onOpen() {
        await this.render();
    }

    async render() {
        const container = this.containerEl.children[1];
        container.empty();
        container.addClass('bw-panel');

        if (this.plugin.sessionToken) {
            await this.renderUnlocked(container);
        } else {
            const status = await this.plugin.getStatus();
            this.renderLockScreen(container, status);
        }
    }

    renderLockScreen(container, status) {
        const screen = container.createDiv('bw-lock-screen');

        const iconEl = screen.createDiv('bw-lock-icon');
        setIcon(iconEl, status.status === 'not_found' ? 'alert-triangle' : 'lock');

        screen.createEl('h3', { text: 'Bitwarden', cls: 'bw-lock-title' });

        if (status.status === 'not_found') {
            screen.createEl('p', {
                text: 'Bitwarden CLIが見つかりません。インストール後、設定でパスを指定してください。',
                cls: 'bw-hint-text',
            });
            return;
        }

        if (status.status === 'refresh_token_invalid') {
            screen.createEl('p', {
                text: 'ログイン情報が期限切れです。ターミナルで bw logout → bw login を実行してください。',
                cls: 'bw-hint-text bw-hint-warning',
            });
            return;
        }

        if (status.status === 'unauthenticated') {
            screen.createEl('p', {
                text: 'ターミナルで bw login を実行してログインしてください。',
                cls: 'bw-hint-text',
            });
        }

        const form = screen.createDiv('bw-unlock-form');
        const passwordInput = form.createEl('input', {
            type: 'password',
            placeholder: 'マスターパスワード',
            cls: 'bw-password-input',
        });
        const submitBtn = form.createEl('button', {
            text: 'アンロック',
            cls: 'mod-cta bw-unlock-btn',
        });
        const errorEl = screen.createEl('p', { cls: 'bw-error-text' });

        const doUnlock = async () => {
            const pw = passwordInput.value;
            if (!pw) return;
            submitBtn.disabled = true;
            submitBtn.textContent = '処理中...';
            errorEl.textContent = '';
            try {
                await this.plugin.unlock(pw);
                await this.render();
            } catch {
                errorEl.textContent = 'アンロックに失敗しました。パスワードを確認してください。';
                submitBtn.disabled = false;
                submitBtn.textContent = 'アンロック';
            }
        };

        submitBtn.addEventListener('click', doUnlock);
        passwordInput.addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
        setTimeout(() => passwordInput.focus(), 50);
    }

    async renderUnlocked(container) {
        const header = container.createDiv('bw-header');
        const titleDiv = header.createDiv('bw-title');
        const titleIcon = titleDiv.createSpan('bw-title-icon');
        setIcon(titleIcon, 'shield');
        titleDiv.createSpan({ text: 'Bitwarden', cls: 'bw-title-text' });

        const btnGroup = header.createDiv('bw-btn-group');

        const syncBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: '同期', 'aria-label': '同期' },
        });
        setIcon(syncBtn, 'refresh-cw');
        syncBtn.addEventListener('click', async () => {
            syncBtn.disabled = true;
            syncBtn.addClass('bw-spinning');
            try {
                await this.plugin.sync();
                this.itemsCache = null;
                this.foldersCache = null;
                new Notice('Bitwarden: 同期完了');
                await this.loadItems(this.lastQuery || '');
            } catch {
                new Notice('Bitwarden: 同期に失敗しました');
            } finally {
                syncBtn.disabled = false;
                syncBtn.removeClass('bw-spinning');
            }
        });

        const lockBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'ロック', 'aria-label': 'ロック' },
        });
        setIcon(lockBtn, 'lock');
        lockBtn.addEventListener('click', async () => {
            await this.plugin.lock();
            await this.render();
        });

        const isFolder = this.plugin.settings.viewMode === 'folder';
        const viewModeBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: {
                title: isFolder ? 'タイプ別表示' : 'フォルダ別表示',
                'aria-label': 'ビュー切替',
            },
        });
        setIcon(viewModeBtn, isFolder ? 'list' : 'folder');
        viewModeBtn.addEventListener('click', async () => {
            this.plugin.settings.viewMode = this.plugin.settings.viewMode === 'type' ? 'folder' : 'type';
            await this.plugin.saveSettings();
            await this.render();
        });

        this.folderNav = null;
        this.itemsCache = null;
        this.foldersCache = null;

        this.searchBar = container.createDiv('bw-search-bar');
        const searchIconEl = this.searchBar.createSpan('bw-search-icon');
        setIcon(searchIconEl, 'search');
        this.searchInput = this.searchBar.createEl('input', {
            type: 'text',
            placeholder: 'アイテムを検索...',
            cls: 'bw-search-input',
        });
        this.searchInput.addEventListener('input', () => {
            clearTimeout(this.searchTimer);
            this.lastQuery = this.searchInput.value;
            this.searchTimer = setTimeout(() => this.loadItems(this.searchInput.value), 300);
        });

        this.listContainer = container.createDiv('bw-list-container');
        this.lastQuery = '';

        await this.loadItems();
        if (this.plugin.settings.viewMode !== 'folder') {
            setTimeout(() => this.searchInput.focus(), 50);
        }
    }

    async getItems(query = '') {
        if (!this.itemsCache) {
            this.itemsCache = await this.plugin.listItems('');
        }
        if (!query) return this.itemsCache;
        const q = query.toLowerCase();
        return this.itemsCache.filter(item =>
            item.name?.toLowerCase().includes(q) ||
            item.login?.username?.toLowerCase().includes(q) ||
            item.login?.uris?.[0]?.uri?.toLowerCase().includes(q)
        );
    }

    async getFolders() {
        if (!this.foldersCache) {
            this.foldersCache = await this.plugin.listFolders();
        }
        return this.foldersCache;
    }

    async loadItems(query = '') {
        if (!this.listContainer) return;
        this.listContainer.empty();

        const loadingEl = this.listContainer.createDiv('bw-loading');
        setIcon(loadingEl, 'loader-2');

        try {
            if (this.plugin.settings.viewMode === 'folder' && !this.folderNav) {
                if (this.searchBar) this.searchBar.style.display = 'none';
                await this.loadFolderHome();
            } else {
                if (this.searchBar) this.searchBar.style.display = '';
                const items = await this.getItems(query);
                this.listContainer.empty();

                if (this.plugin.settings.viewMode === 'folder' && this.folderNav) {
                    this.renderFolderBackButton();
                    const folderItems = items.filter(i => (i.folderId || null) === this.folderNav.id);
                    if (!folderItems.length) {
                        const emptyEl = this.listContainer.createDiv('bw-empty');
                        setIcon(emptyEl.createSpan(), 'search');
                        emptyEl.createSpan({ text: query ? '見つかりません' : 'アイテムがありません' });
                    } else {
                        this.renderByType(folderItems);
                    }
                } else {
                    if (!items.length) {
                        const emptyEl = this.listContainer.createDiv('bw-empty');
                        setIcon(emptyEl.createSpan(), 'search');
                        emptyEl.createSpan({ text: query ? '見つかりません' : 'アイテムがありません' });
                        return;
                    }
                    this.renderByType(items);
                }
            }
        } catch (err) {
            if (err.message === 'SESSION_INVALID' || err.message === 'REFRESH_TOKEN_INVALID') {
                this.plugin.sessionToken = null;
                this.plugin.settings.sessionToken = null;
                await this.plugin.saveSettings();
                await this.render();
                return;
            }
            this.listContainer.empty();
            const errEl = this.listContainer.createDiv('bw-error-state');
            setIcon(errEl.createSpan('bw-error-icon'), 'alert-circle');
            errEl.createEl('p', { text: err.message || '不明なエラーが発生しました' });
        }
    }

    async loadFolderHome() {
        const folders = await this.getFolders();
        this.listContainer.empty();

        if (!folders.length) {
            const emptyEl = this.listContainer.createDiv('bw-empty');
            setIcon(emptyEl.createSpan(), 'folder');
            emptyEl.createSpan({ text: 'フォルダがありません' });
            return;
        }

        folders.sort((a, b) => a.name.localeCompare(b.name, 'ja'));

        for (const folder of folders) {
            const el = this.listContainer.createDiv('bw-item');
            const iconEl = el.createDiv('bw-item-icon');
            setIcon(iconEl, 'folder');
            const info = el.createDiv('bw-item-info');
            info.createDiv({ text: folder.name, cls: 'bw-item-name' });
            el.addEventListener('click', () => {
                this.folderNav = { id: folder.id, name: folder.name };
                if (this.searchInput) { this.searchInput.value = ''; this.lastQuery = ''; }
                this.loadItems('');
            });
        }
    }

    renderFolderBackButton() {
        const row = this.listContainer.createDiv('bw-folder-back-row');
        const backBtn = row.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'フォルダ一覧に戻る', 'aria-label': '戻る' },
        });
        setIcon(backBtn, 'arrow-left');
        row.createSpan({ text: this.folderNav.name, cls: 'bw-folder-current-name' });
        backBtn.addEventListener('click', () => {
            this.folderNav = null;
            if (this.searchInput) { this.searchInput.value = ''; this.lastQuery = ''; }
            this.loadItems('');
        });
    }

    renderByType(items) {
        const favorites = items.filter(i => i.favorite);
        if (favorites.length) this.renderGroup('お気に入り', 'star', favorites);

        const groups = [
            { type: 1, label: 'ログイン', icon: 'key-round' },
            { type: 3, label: 'カード', icon: 'credit-card' },
            { type: 2, label: 'メモ', icon: 'file-text' },
            { type: 4, label: 'ID', icon: 'user' },
        ];

        for (const { type, label, icon } of groups) {
            const filtered = items.filter(i => i.type === type && !i.favorite);
            if (!filtered.length) continue;
            this.renderGroup(label, icon, filtered);
        }
    }

    renderGroup(label, icon, items) {
        const group = this.listContainer.createDiv('bw-group');
        if (icon === 'star') group.addClass('bw-group--favorites');
        const groupHeader = group.createDiv('bw-group-label');
        setIcon(groupHeader.createSpan('bw-group-icon'), icon);
        groupHeader.createSpan({ text: `${label}  ${items.length}` });

        for (const item of items) {
            const el = group.createDiv('bw-item');

            const itemIcon = el.createDiv('bw-item-icon');
            const typeIcon = { 1: 'key-round', 2: 'file-text', 3: 'credit-card', 4: 'user' }[item.type] || 'file';
            const domain = item.type === 1 ? extractDomain(item.login?.uris?.[0]?.uri) : null;
            if (domain && this.plugin.settings.useIcons) {
                const server = this.plugin.settings.iconServer || 'https://icons.bitwarden.net';
                const img = itemIcon.createEl('img', {
                    cls: 'bw-site-icon',
                    attr: { src: `${server}/${domain}/icon.png`, alt: '' },
                });
                img.addEventListener('error', () => { img.remove(); setIcon(itemIcon, typeIcon); });
            } else {
                setIcon(itemIcon, typeIcon);
            }

            const info = el.createDiv('bw-item-info');
            info.createDiv({ text: item.name, cls: 'bw-item-name' });

            const sub = item.type === 1
                ? (item.login?.username || item.login?.uris?.[0]?.uri || '')
                : '';
            if (sub) info.createDiv({ text: sub, cls: 'bw-item-sub' });

            const actions = el.createDiv('bw-item-actions');

            if (item.type === 1 && item.login?.username) {
                const btn = actions.createEl('button', {
                    cls: 'bw-copy-btn',
                    attr: { title: 'ユーザー名をコピー' },
                });
                setIcon(btn, 'user');
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(item.login.username);
                    new Notice('ユーザー名をコピーしました');
                });
            }

            if (item.type === 1 && item.login?.password) {
                const btn = actions.createEl('button', {
                    cls: 'bw-copy-btn',
                    attr: { title: 'パスワードをコピー' },
                });
                setIcon(btn, 'copy');
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(item.login.password);
                    new Notice('パスワードをコピーしました');
                });
            }

            if (item.type === 1 && item.login?.totp) {
                const btn = actions.createEl('button', {
                    cls: 'bw-copy-btn',
                    attr: { title: 'TOTPコードをコピー' },
                });
                setIcon(btn, 'clock');
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const parsed = parseTotpUri(item.login.totp);
                    if (!parsed) return;
                    try {
                        const code = await generateTotp(parsed.secret, parsed.digits, parsed.period);
                        await navigator.clipboard.writeText(code);
                        new Notice(`TOTPコード: ${code}`);
                    } catch {
                        new Notice('TOTPコードの生成に失敗しました');
                    }
                });
            }

            el.addEventListener('click', () => new BitwardenItemModal(this.app, item).open());
        }
    }
}

class BitwardenItemModal extends Modal {
    constructor(app, item) {
        super(app);
        this.item = item;
        this._totpInterval = null;
        this._lastCounter = -1;
    }

    async onOpen() {
        const { contentEl } = this;
        contentEl.addClass('bw-modal');
        contentEl.createEl('h2', { text: this.item.name, cls: 'bw-modal-title' });

        const { type, login, card, notes } = this.item;

        if (type === 1 && login) {
            this.addField('ユーザー名', login.username, { copyable: true });
            this.addField('パスワード', login.password, { copyable: true, masked: true });
            if (login.totp) await this.addTotpField(login.totp);
            if (login.uris?.length) {
                login.uris.forEach((u, i) =>
                    this.addField(i === 0 ? 'URL' : `URL ${i + 1}`, u.uri));
            }
        }

        if (type === 3 && card) {
            this.addField('カード番号', card.number, { copyable: true, masked: true });
            this.addField('カード名義', card.cardholderName);
            if (card.expMonth && card.expYear) {
                this.addField('有効期限', `${card.expMonth}/${card.expYear}`);
            }
            if (card.code) this.addField('CVV', card.code, { copyable: true, masked: true });
        }

        if (notes) this.addField('メモ', notes);
    }

    async addTotpField(totpValue) {
        const parsed = parseTotpUri(totpValue);
        if (!parsed) {
            this.addField('TOTP', totpValue, { copyable: true });
            return;
        }
        const { secret, digits, period } = parsed;

        const row = this.contentEl.createDiv('bw-field-row');
        row.createEl('label', { text: 'TOTP', cls: 'bw-field-label' });

        const box = row.createDiv('bw-totp-box');
        const topRow = box.createDiv('bw-totp-code-row');
        const codeEl = topRow.createEl('span', { cls: 'bw-totp-code', text: '--- ---' });
        const timerEl = topRow.createEl('span', { cls: 'bw-totp-timer', text: '' });
        const copyBtn = topRow.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'TOTPコードをコピー' },
        });
        setIcon(copyBtn, 'copy');

        const gaugeTrack = box.createDiv('bw-totp-gauge');
        const gaugeFill = gaugeTrack.createDiv('bw-totp-gauge-fill');

        let currentCode = '';

        const update = async () => {
            const now = Math.floor(Date.now() / 1000);
            const counter = Math.floor(now / period);
            const remaining = period - (now % period);
            const pct = (remaining / period) * 100;

            if (counter !== this._lastCounter) {
                this._lastCounter = counter;
                try {
                    currentCode = await generateTotp(secret, digits, period);
                } catch {
                    currentCode = '';
                }
                const fmt = digits === 6 && currentCode
                    ? `${currentCode.slice(0, 3)} ${currentCode.slice(3)}`
                    : (currentCode || '--- ---');
                codeEl.textContent = fmt;
            }

            timerEl.textContent = `${remaining}s`;
            gaugeFill.style.width = `${pct}%`;

            const warn = remaining <= 5;
            gaugeFill.classList.toggle('bw-totp-gauge-fill--warning', warn);
            timerEl.classList.toggle('bw-totp-timer--warning', warn);
        };

        copyBtn.addEventListener('click', () => {
            if (!currentCode) return;
            navigator.clipboard.writeText(currentCode);
            new Notice('TOTPコードをコピーしました');
        });

        await update();
        this._totpInterval = setInterval(update, 1000);
    }

    addField(label, value, opts = {}) {
        if (!value) return;
        const { copyable = false, masked = false } = opts;

        const row = this.contentEl.createDiv('bw-field-row');
        row.createEl('label', { text: label, cls: 'bw-field-label' });

        const valueArea = row.createDiv('bw-field-value-area');
        const valueEl = valueArea.createEl('span', { cls: 'bw-field-value' });

        let revealed = false;
        if (masked) {
            valueEl.textContent = '••••••••';
            const eyeBtn = valueArea.createEl('button', { cls: 'bw-icon-btn' });
            setIcon(eyeBtn, 'eye');
            eyeBtn.addEventListener('click', () => {
                revealed = !revealed;
                valueEl.textContent = revealed ? value : '••••••••';
                setIcon(eyeBtn, revealed ? 'eye-off' : 'eye');
            });
        } else {
            valueEl.textContent = value;
        }

        if (copyable) {
            const copyBtn = valueArea.createEl('button', { cls: 'bw-icon-btn' });
            setIcon(copyBtn, 'copy');
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(value);
                new Notice(`${label}をコピーしました`);
            });
        }
    }

    onClose() {
        if (this._totpInterval) {
            clearInterval(this._totpInterval);
            this._totpInterval = null;
        }
        this.contentEl.empty();
    }
}

class BitwardenSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'Bitwarden 設定' });

        new Setting(containerEl)
            .setName('Bitwarden CLI パス')
            .setDesc('bw コマンドのパス。PATHが通っていない場合はフルパスを入力してください。')
            .addText(text => text
                .setPlaceholder('bw')
                .setValue(this.plugin.settings.bwPath)
                .onChange(async value => {
                    this.plugin.settings.bwPath = value.trim() || 'bw';
                    await this.plugin.saveSettings();
                }));

        containerEl.createEl('h3', { text: '表示' });

        new Setting(containerEl)
            .setName('表示モード')
            .setDesc('アイテムをタイプ別またはフォルダ別にグループ表示します。パネルのボタンからも切り替えられます。')
            .addDropdown(drop => drop
                .addOption('type', 'タイプ別')
                .addOption('folder', 'フォルダ別')
                .setValue(this.plugin.settings.viewMode)
                .onChange(async value => {
                    this.plugin.settings.viewMode = value;
                    await this.plugin.saveSettings();
                }));

        containerEl.createEl('h3', { text: 'アイコン' });

        new Setting(containerEl)
            .setName('Webサイトアイコンを表示')
            .setDesc('Vaultのログインアイテムに登録されたURIのファビコンを取得して表示します。アイコンサーバーへのリクエストが発生します。')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.useIcons)
                .onChange(async value => {
                    this.plugin.settings.useIcons = value;
                    await this.plugin.saveSettings();
                    iconServerSetting.settingEl.style.display = value ? '' : 'none';
                }));

        const iconServerSetting = new Setting(containerEl)
            .setName('アイコンサーバー URL')
            .setDesc('Bitwarden icon server provides the delivery endpoint for website icons. If you are using website icons on a device, Bitwarden will issue requests to icons.bitwarden.net for each login in your vault that has a URI that resembles a website (for example, google.com or https://google.com, but not google or http://localhost).')
            .addText(text => text
                .setPlaceholder('https://icons.bitwarden.net')
                .setValue(this.plugin.settings.iconServer)
                .onChange(async value => {
                    this.plugin.settings.iconServer = value.trim() || 'https://icons.bitwarden.net';
                    await this.plugin.saveSettings();
                }));

        iconServerSetting.settingEl.style.display = this.plugin.settings.useIcons ? '' : 'none';
    }
}

module.exports = BitwardenPlugin;
