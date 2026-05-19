'use strict';

const { Plugin, ItemView, Modal, Notice, Setting, PluginSettingTab, setIcon } = require('obsidian');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const VIEW_TYPE = 'bitwarden-panel';
const DEFAULT_SETTINGS = {
    bwPath: 'bw',
    useIcons: true,
    iconServer: 'https://icons.bitwarden.net',
};

function extractDomain(uri) {
    if (!uri) return null;
    try {
        return new URL(uri.startsWith('http') ? uri : `https://${uri}`).hostname;
    } catch {
        return null;
    }
}

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
        this.searchTimer = null;
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

        const searchBar = container.createDiv('bw-search-bar');
        const searchIconEl = searchBar.createSpan('bw-search-icon');
        setIcon(searchIconEl, 'search');
        const searchInput = searchBar.createEl('input', {
            type: 'text',
            placeholder: 'アイテムを検索...',
            cls: 'bw-search-input',
        });
        searchInput.addEventListener('input', () => {
            clearTimeout(this.searchTimer);
            this.lastQuery = searchInput.value;
            this.searchTimer = setTimeout(() => this.loadItems(searchInput.value), 300);
        });

        this.listContainer = container.createDiv('bw-list-container');
        this.lastQuery = '';

        await this.loadItems();
        setTimeout(() => searchInput.focus(), 50);
    }

    async loadItems(query = '') {
        if (!this.listContainer) return;
        this.listContainer.empty();

        const loadingEl = this.listContainer.createDiv('bw-loading');
        setIcon(loadingEl, 'loader-2');

        try {
            const items = await this.plugin.listItems(query);
            this.listContainer.empty();

            if (!items.length) {
                const emptyEl = this.listContainer.createDiv('bw-empty');
                setIcon(emptyEl.createSpan(), 'search');
                emptyEl.createSpan({ text: query ? '見つかりません' : 'アイテムがありません' });
                return;
            }

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

            el.addEventListener('click', () => new BitwardenItemModal(this.app, item).open());
        }
    }
}

class BitwardenItemModal extends Modal {
    constructor(app, item) {
        super(app);
        this.item = item;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.addClass('bw-modal');
        contentEl.createEl('h2', { text: this.item.name, cls: 'bw-modal-title' });

        const { type, login, card, notes } = this.item;

        if (type === 1 && login) {
            this.addField('ユーザー名', login.username, { copyable: true });
            this.addField('パスワード', login.password, { copyable: true, masked: true });
            if (login.totp) this.addField('TOTP', login.totp, { copyable: true });
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
