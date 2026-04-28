document.addEventListener('DOMContentLoaded', () => {
    const $ = (s) => document.getElementById(s);
    const submitBtn = $('submit');
    const tokenInput = $('token');
    const toggleBtn = $('toggle-vis');
    const eyeIcon = $('eye-icon');
    const eyeOffIcon = $('eye-off-icon');
    const statusEl = $('status');
    const extractBtn = $('extract');
    const helpBtn = $('help-btn');
    const helpPanel = $('help-panel');
    const helpCloseBtn = $('help-close');
    const copyBtn = $('copy-token');
    const copyIcon = $('copy-icon');
    const copiedIcon = $('copied-icon');
    const userPreview = $('user-preview');
    const inputWrapper = document.querySelector('.input-wrapper');
    const sessionBar = $('session-bar');
    const sessionAvatar = $('session-avatar');
    const sessionName = $('session-name');
    const historySection = $('history-section');
    const historyToggle = $('history-toggle');
    const historyList = $('history-list');
    const historyChevron = $('history-chevron');
    const savedSection = $('saved-section');
    const savedList = $('saved-list');
    const savedSearch = $('saved-search');
    const savedSearchWrap = $('saved-search-wrap');
    const saveTokenBtn = $('save-token');
    const saveEditor = $('save-editor');
    const saveNameInput = $('save-name-input');
    const saveConfirmBtn = $('save-confirm');
    const saveCancelBtn = $('save-cancel');
    const themeBtn = $('theme-btn');
    const themeIconMoon = $('theme-icon-moon');
    const themeIconSun = $('theme-icon-sun');
    const undoToast = $('undo-toast');
    const undoToastText = $('undo-toast-text');
    const undoBtn = $('undo-btn');
    const undoProgress = $('undo-progress');
    const switchOverlay = $('switch-overlay');
    const switchOverlayAvatar = $('switch-overlay-avatar');
    const switchOverlayText = $('switch-overlay-text');
    const switchOverlayProgress = $('switch-overlay-progress');
    const speedBtn = $('speed-btn');
    const speedBadge = $('speed-badge');
    const themeBadge = $('theme-badge');
    const settingsBtn = $('settings-btn');
    const settingsDropdown = $('settings-dropdown');

    const MAX_HISTORY = 10;
    const MAX_SAVED = 20;
    const UNDO_DURATION = 4000;
    let copyResetTimer = null;
    let pendingSaveToken = null;
    let pendingSaveUser = null;
    let undoTimer = null;
    let undoCallback = null;

    // ══════════════════════════════════════════
    //  Token encryption (AES-GCM via Web Crypto)
    // ══════════════════════════════════════════

    const CRYPTO_SALT_KEY = '_cryptoSalt';
    const CRYPTO_MIGRATED_KEY = '_cryptoMigrated';

    async function getCryptoKey() {
        // Derive a stable AES-GCM key from chrome.runtime.id + a random salt
        let saltHex;
        const stored = await new Promise(r => chrome.storage.local.get(CRYPTO_SALT_KEY, r));
        if (stored[CRYPTO_SALT_KEY]) {
            saltHex = stored[CRYPTO_SALT_KEY];
        } else {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
            await new Promise(r => chrome.storage.local.set({ [CRYPTO_SALT_KEY]: saltHex }, r));
        }
        const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
        const source = chrome.runtime.id || 'discord-side-local';
        const raw = new TextEncoder().encode(source);
        const base = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            base,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptToken(token) {
        try {
            const key = await getCryptoKey();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoded = new TextEncoder().encode(token);
            const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
            const cipher = Array.from(new Uint8Array(cipherBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
            const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
            return ivHex + ':' + cipher;
        } catch (e) {
            console.error('Encrypt error:', e);
            return token; // fallback — store plain if crypto fails
        }
    }

    async function decryptToken(stored) {
        if (!stored || !stored.includes(':')) return stored; // plain text (legacy)
        try {
            const [ivHex, cipherHex] = stored.split(':');
            if (ivHex.length !== 24) return stored; // not encrypted (24 hex = 12 bytes IV)
            const key = await getCryptoKey();
            const iv = new Uint8Array(ivHex.match(/.{2}/g).map(h => parseInt(h, 16)));
            const cipher = new Uint8Array(cipherHex.match(/.{2}/g).map(h => parseInt(h, 16)));
            const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
            return new TextDecoder().decode(plain);
        } catch (e) {
            console.error('Decrypt error:', e);
            return stored; // return as-is if decryption fails
        }
    }

    function isEncrypted(val) {
        if (!val || typeof val !== 'string') return false;
        const parts = val.split(':');
        return parts.length === 2 && parts[0].length === 24 && /^[0-9a-f]+$/.test(parts[0]);
    }

    async function migrateTokenStorage() {
        const migrated = await new Promise(r => chrome.storage.local.get(CRYPTO_MIGRATED_KEY, r));
        if (migrated[CRYPTO_MIGRATED_KEY]) return;

        // Migrate saved accounts
        const savedData = await new Promise(r => chrome.storage.local.get({ savedAccounts: [] }, r));
        const accounts = savedData.savedAccounts;
        let changed = false;
        for (let i = 0; i < accounts.length; i++) {
            if (accounts[i].token && !isEncrypted(accounts[i].token)) {
                accounts[i].token = await encryptToken(accounts[i].token);
                changed = true;
            }
        }
        if (changed) await new Promise(r => chrome.storage.local.set({ savedAccounts: accounts }, r));

        // Migrate login history
        const histData = await new Promise(r => chrome.storage.local.get({ loginHistory: [] }, r));
        const history = histData.loginHistory;
        changed = false;
        for (let i = 0; i < history.length; i++) {
            if (history[i].token && !isEncrypted(history[i].token)) {
                history[i].token = await encryptToken(history[i].token);
                changed = true;
            }
        }
        if (changed) await new Promise(r => chrome.storage.local.set({ loginHistory: history }, r));

        await new Promise(r => chrome.storage.local.set({ [CRYPTO_MIGRATED_KEY]: true }, r));
    }

    // ══════════════════════════════════════════
    //  Switch overlay
    // ══════════════════════════════════════════

    function isSpeedMode() { return document.body.getAttribute('data-speed') === 'instant'; }

    function showSwitchOverlay(avatarUrl, displayName, onComplete) {
        // Speed mode — skip overlay entirely, execute immediately
        if (isSpeedMode()) {
            if (onComplete) onComplete();
            return;
        }
        switchOverlayAvatar.src = avatarUrl || '';
        switchOverlayAvatar.onerror = () => { switchOverlayAvatar.style.display = 'none'; };
        switchOverlayText.textContent = 'Switching to ' + displayName + '...';
        switchOverlayProgress.style.transition = 'none';
        switchOverlayProgress.style.width = '0%';
        switchOverlay.classList.add('visible');
        // Trigger progress bar
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                switchOverlayProgress.style.transition = 'width 1s cubic-bezier(.4,0,.2,1)';
                switchOverlayProgress.style.width = '100%';
            });
        });
        // Callback after animation
        setTimeout(() => {
            if (onComplete) onComplete();
        }, 1100);
    }

    // ══════════════════════════════════════════
    //  Init
    // ══════════════════════════════════════════

    tokenInput.focus();
    initTheme();
    initSpeed();
    checkPendingResult();
    detectCurrentSession();
    savedSection.classList.add('no-anim');
    // Run migration then load data
    migrateTokenStorage().then(() => {
        loadSavedAccounts();
        loadHistory();
    }).catch(() => {
        loadSavedAccounts();
        loadHistory();
    });
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            savedSection.classList.remove('no-anim');
        });
    });

    // ══════════════════════════════════════════
    //  Theme
    // ══════════════════════════════════════════

    function initTheme() {
        chrome.storage.local.get({ theme: 'auto' }, (data) => {
            applyTheme(data.theme);
        });
    }

    function applyTheme(pref) {
        let theme;
        if (pref === 'auto') {
            theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        } else {
            theme = pref;
        }
        document.documentElement.setAttribute('data-theme', theme);
        updateThemeIcon(theme);
        if (themeBadge) updateThemeBadge();
    }

    function updateThemeIcon(active) {
        if (active === 'light') {
            themeIconMoon.style.display = 'none';
            themeIconSun.style.display = 'block';
        } else {
            themeIconMoon.style.display = 'block';
            themeIconSun.style.display = 'none';
        }
    }

    themeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        chrome.storage.local.get({ theme: 'auto' }, (data) => {
            const current = document.documentElement.getAttribute('data-theme') || 'dark';
            const next = current === 'dark' ? 'light' : 'dark';
            chrome.storage.local.set({ theme: next });
            applyTheme(next);
        });
    });

    // Listen for system theme changes when in auto mode
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
        chrome.storage.local.get({ theme: 'auto' }, (data) => {
            if (data.theme === 'auto') applyTheme('auto');
        });
    });

    // ══════════════════════════════════════════
    //  Settings dropdown
    // ══════════════════════════════════════════

    settingsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = !settingsDropdown.classList.contains('hidden');
        if (open) {
            settingsDropdown.classList.add('hidden');
            settingsBtn.classList.remove('active');
        } else {
            settingsDropdown.classList.remove('hidden');
            settingsBtn.classList.add('active');
        }
    });

    // Close dropdown on click outside
    document.addEventListener('click', (e) => {
        if (!settingsDropdown.classList.contains('hidden') &&
            !settingsDropdown.contains(e.target) &&
            !settingsBtn.contains(e.target)) {
            settingsDropdown.classList.add('hidden');
            settingsBtn.classList.remove('active');
        }
    });

    // ── Speed mode ──

    function initSpeed() {
        chrome.storage.local.get({ speedMode: false }, (data) => {
            if (data.speedMode) {
                document.body.setAttribute('data-speed', 'instant');
                speedBtn.classList.add('active');
                speedBadge.textContent = 'ON';
            }
        });
    }

    function updateThemeBadge() {
        const t = document.documentElement.getAttribute('data-theme') || 'dark';
        themeBadge.textContent = t === 'light' ? 'Light' : 'Dark';
    }

    speedBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const on = document.body.getAttribute('data-speed') === 'instant';
        if (on) {
            document.body.removeAttribute('data-speed');
            speedBtn.classList.remove('active');
            speedBadge.textContent = 'OFF';
            chrome.storage.local.set({ speedMode: false });
        } else {
            document.body.setAttribute('data-speed', 'instant');
            speedBtn.classList.add('active');
            speedBadge.textContent = 'ON';
            chrome.storage.local.set({ speedMode: true });
        }
    });

    // ══════════════════════════════════════════
    //  Undo toast system
    // ══════════════════════════════════════════

    function showUndoToast(message, onConfirmDelete, onUndo) {
        // Cancel any previous undo
        clearUndoToast(true);

        undoToastText.textContent = message;
        undoCallback = onUndo;

        // Animate progress bar via transition
        undoProgress.style.transition = 'none';
        undoProgress.style.width = '100%';
        undoProgress.offsetHeight; // force reflow
        undoProgress.style.transition = 'width ' + UNDO_DURATION + 'ms linear';
        undoProgress.style.width = '0%';

        undoToast.classList.add('visible');

        undoTimer = setTimeout(() => {
            hideUndoToast();
            onConfirmDelete();
        }, UNDO_DURATION);
    }

    function hideUndoToast() {
        undoToast.classList.remove('visible');
        clearTimeout(undoTimer);
        undoTimer = null;
        undoCallback = null;
        undoProgress.style.transition = 'none';
        undoProgress.style.width = '0%';
    }

    function clearUndoToast(executeDelete) {
        if (undoTimer) {
            clearTimeout(undoTimer);
            undoTimer = null;
            // If there's a pending delete and we're replacing it, execute immediately
            // (not used in current flow, but safe)
        }
        undoToast.classList.remove('visible');
        undoCallback = null;
    }

    undoBtn.addEventListener('click', () => {
        if (undoCallback) undoCallback();
        hideUndoToast();
    });

    // ── Check for results from background worker ──

    function checkPendingResult() {
        chrome.storage.local.get({ pendingResult: null }, (data) => {
            const result = data.pendingResult;
            if (!result) return;

            chrome.storage.local.remove('pendingResult');
            chrome.action.setBadgeText({ text: '' });

            if (Date.now() - result.timestamp > 60000) return;

            if (result.type === 'extract') {
                if (result.success && result.token) {
                    tokenInput.value = result.token;
                    showToken();
                    updateInputButtons();
                    showStatus('Token extracted!', 'success', true);
                    validateAndShowUser(result.token);
                } else {
                    showStatus(result.error || 'Extraction failed', 'error');
                }
            }

            if (result.type === 'inject') {
                if (result.success) {
                    showStatus('Token applied! Discord should be loading', 'success', true);
                } else {
                    showStatus(result.error || 'Injection failed', 'error');
                }
            }
        });
    }

    // ── Toggles ──

    helpBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close settings dropdown
        settingsDropdown.classList.add('hidden');
        settingsBtn.classList.remove('active');
        // Toggle help
        helpPanel.classList.toggle('hidden');
    });

    helpCloseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        helpPanel.classList.add('hidden');
    });

    // Close help panel on click outside
    document.addEventListener('click', (e) => {
        if (!helpPanel.classList.contains('hidden') &&
            !helpPanel.contains(e.target) &&
            !helpBtn.contains(e.target)) {
            helpPanel.classList.add('hidden');
        }
    });

    historyToggle.addEventListener('click', () => {
        historyList.classList.toggle('hidden');
        historyChevron.classList.toggle('open', !historyList.classList.contains('hidden'));
    });

    toggleBtn.addEventListener('click', () => {
        const isPassword = tokenInput.type === 'password';
        tokenInput.type = isPassword ? 'text' : 'password';
        eyeIcon.style.display = isPassword ? 'none' : 'block';
        eyeOffIcon.style.display = isPassword ? 'block' : 'none';
    });

    tokenInput.addEventListener('input', () => {
        tokenInput.classList.remove('error');
        hideStatus();
        hideUserPreview();
        updateInputButtons();
    });

    tokenInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); handleLogin(); }
    });

    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey) {
            switch (e.key.toUpperCase()) {
                case 'L': e.preventDefault(); handleLogin(); break;
                case 'E': e.preventDefault(); extractBtn.click(); break;
                case 'C': e.preventDefault(); if (tokenInput.value.trim()) copyToClipboard(); break;
            }
        }
    });

    submitBtn.addEventListener('click', handleLogin);
    copyBtn.addEventListener('click', copyToClipboard);

    // ── Save token flow ──

    saveTokenBtn.addEventListener('click', () => {
        const token = tokenInput.value.trim();
        if (!token) { showStatus('Enter a token first', 'error'); return; }
        if (token.length < 30) { showStatus('Token is too short', 'error'); return; }

        saveTokenBtn.style.pointerEvents = 'none';
        showStatus('Validating token...', 'info');

        validateToken(token).then((user) => {
            saveTokenBtn.style.pointerEvents = '';
            if (!user) {
                showStatus('Token is invalid — cannot save', 'error');
                return;
            }
            pendingSaveToken = token;
            pendingSaveUser = user;
            saveNameInput.value = user.display;
            saveEditor.classList.remove('hidden');
            saveNameInput.focus();
            saveNameInput.select();
            hideStatus();
        }).catch((err) => {
            saveTokenBtn.style.pointerEvents = '';
            if (err && err.message === 'RATE_LIMITED') {
                showStatus('Too many requests — wait ' + err.retryAfter + 's and retry', 'error');
            } else {
                showStatusWithAction('Validation failed. ', 'Retry', () => saveTokenBtn.click(), 'error');
            }
        });
    });

    saveConfirmBtn.addEventListener('click', confirmSave);
    saveCancelBtn.addEventListener('click', cancelSave);
    saveNameInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); confirmSave(); }
        if (e.key === 'Escape') cancelSave();
    });

    function confirmSave() {
        if (!pendingSaveToken || !pendingSaveUser) return;
        const label = saveNameInput.value.trim() || pendingSaveUser.display;

        encryptToken(pendingSaveToken).then((encToken) => {
            chrome.storage.local.get({ savedAccounts: [] }, (data) => {
                let accounts = data.savedAccounts;
                accounts = accounts.filter((a) => a.id !== pendingSaveUser.id);
                accounts.unshift({
                    id: pendingSaveUser.id,
                    label: label,
                    display: pendingSaveUser.display,
                    tag: pendingSaveUser.tag,
                    avatar: pendingSaveUser.avatar,
                    token: encToken
                });
                accounts = accounts.slice(0, MAX_SAVED);

                chrome.storage.local.set({ savedAccounts: accounts }, () => {
                    cancelSave();
                    loadSavedAccounts();
                    showStatus('Account "' + label + '" saved!', 'success', true);
                });
            });
        });
    }

    function cancelSave() {
        saveEditor.classList.add('hidden');
        pendingSaveToken = null;
        pendingSaveUser = null;
    }

    // ── Saved accounts ──

    function loadSavedAccounts() {
        chrome.storage.local.get({ savedAccounts: [] }, (data) => {
            const accounts = data.savedAccounts;
            if (accounts.length === 0) {
                savedSection.classList.add('hidden');
                savedSearchWrap.classList.add('hidden');
                return;
            }
            savedSection.classList.remove('hidden');
            savedList.innerHTML = '';

            // Show search bar when 4+ accounts
            if (accounts.length >= 4) {
                savedSearchWrap.classList.remove('hidden');
            } else {
                savedSearchWrap.classList.add('hidden');
                savedSearch.value = '';
            }

            accounts.forEach((acc) => {
                const item = document.createElement('div');
                item.className = 'saved-item';
                item.title = 'Click to load token';
                item.setAttribute('data-account-id', acc.id);
                item.setAttribute('data-search', (acc.label + ' ' + acc.tag + ' ' + acc.display).toLowerCase());

                // Avatar
                const avatar = document.createElement('img');
                avatar.className = 's-avatar';
                avatar.src = acc.avatar;
                avatar.alt = '';
                avatar.onerror = () => { avatar.style.display = 'none'; };

                // Info
                const info = document.createElement('div');
                info.className = 's-info';
                const labelEl = document.createElement('div');
                labelEl.className = 's-label';
                labelEl.textContent = acc.label;
                const tagEl = document.createElement('div');
                tagEl.className = 's-tag';
                tagEl.textContent = acc.tag;
                info.appendChild(labelEl);
                info.appendChild(tagEl);

                // Action buttons container
                const actions = document.createElement('div');
                actions.className = 's-actions';

                // Quick switch
                const switchBtn = createIconBtn('s-switch', 'Quick login',
                    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                        '<polygon points="5 3 19 12 5 21 5 3"/>' +
                    '</svg>');
                switchBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    decryptToken(acc.token).then(plain => quickSwitch(plain, acc.display, acc.avatar));
                });

                // Copy
                const cpBtn = createIconBtn('s-copy', 'Copy token',
                    '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                        '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
                        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
                    '</svg>');
                cpBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    decryptToken(acc.token).then(plain => {
                        copyText(plain);
                        showStatus('Token copied!', 'success', true);
                    });
                });

                // Delete
                const delBtn = createIconBtn('s-delete', 'Remove account',
                    '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                        '<polyline points="3 6 5 6 21 6"/>' +
                        '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>' +
                        '<path d="M10 11v6"/><path d="M14 11v6"/>' +
                    '</svg>');
                delBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    deleteSavedAccount(acc.id, acc.label);
                });

                actions.appendChild(switchBtn);
                actions.appendChild(cpBtn);
                actions.appendChild(delBtn);

                // Click row — load token into input
                item.addEventListener('click', () => {
                    decryptToken(acc.token).then(plain => {
                        tokenInput.value = plain;
                        showToken();
                        updateInputButtons();
                        hideStatus();
                        showStatus('Loaded "' + acc.label + '" — press Log In', 'success', true);
                        tokenInput.focus();
                    });
                });

                item.appendChild(avatar);
                item.appendChild(info);
                item.appendChild(actions);
                savedList.appendChild(item);
            });
        });
    }

    savedSearch.addEventListener('input', () => {
        const q = savedSearch.value.toLowerCase().trim();
        const items = savedList.querySelectorAll('.saved-item');
        items.forEach((item) => {
            const match = !q || item.getAttribute('data-search').includes(q);
            item.style.display = match ? '' : 'none';
        });
    });

    function deleteSavedAccount(id, label) {
        // Visually dim the item
        const itemEl = savedList.querySelector('[data-account-id="' + id + '"]');
        if (itemEl) itemEl.classList.add('pending-delete');

        showUndoToast(
            '"' + (label || 'Account') + '" removed',
            // On confirm (timer expires) — animate collapse, then delete
            () => {
                let deleted = false;
                const doDelete = () => {
                    if (deleted) return;
                    deleted = true;
                    finalizeDelete(id);
                };
                if (itemEl) {
                    itemEl.classList.add('collapsing');
                    itemEl.addEventListener('transitionend', function handler(e) {
                        if (e.propertyName !== 'max-height') return;
                        itemEl.removeEventListener('transitionend', handler);
                        doDelete();
                    });
                    // Safety fallback if transitionend doesn't fire
                    setTimeout(doDelete, 400);
                } else {
                    doDelete();
                }
            },
            // On undo — restore the item
            () => {
                if (itemEl) itemEl.classList.remove('pending-delete');
                showStatus('Deletion cancelled', 'info');
            }
        );
    }

    function finalizeDelete(id) {
        chrome.storage.local.get({ savedAccounts: [] }, (data) => {
            const accounts = data.savedAccounts.filter((a) => a.id !== id);
            chrome.storage.local.set({ savedAccounts: accounts }, () => {
                loadSavedAccounts();
            });
        });
    }

    function quickSwitch(token, displayName, avatarUrl) {
        hideStatus();
        hideUserPreview();
        submitBtn.classList.add('loading');

        validateToken(token).then((user) => {
            if (!user) {
                submitBtn.classList.remove('loading');
                showStatus('Token expired — remove and re-save', 'error');
                return;
            }

            saveToHistory(user, token);
            saveLastAccount(user, token);
            submitBtn.classList.remove('loading');

            // Show overlay FIRST, inject AFTER animation completes
            showSwitchOverlay(user.avatar, displayName, () => {
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    const activeTab = tabs[0];

                    if (!activeTab || !activeTab.url || !activeTab.url.includes('discord.com')) {
                        chrome.runtime.sendMessage({ action: 'openAndInject', token: token });
                        setTimeout(() => window.close(), 200);
                        return;
                    }

                    chrome.scripting.executeScript({
                        target: { tabId: activeTab.id },
                        func: injectToken,
                        args: [token]
                    }, () => {
                        window.close();
                    });
                });
            });
        }).catch((err) => {
            submitBtn.classList.remove('loading');
            if (err && err.message === 'RATE_LIMITED') {
                showStatus('Too many requests — wait ' + err.retryAfter + 's and retry', 'error');
            } else {
                showStatusWithAction('Connection error. ', 'Retry', () => quickSwitch(token, displayName, avatarUrl), 'error');
            }
        });
    }

    function createIconBtn(cls, title, svgHtml) {
        const btn = document.createElement('button');
        btn.className = 's-btn ' + cls;
        btn.title = title;
        btn.type = 'button';
        btn.innerHTML = svgHtml;
        return btn;
    }

    // ── Session detection ──

    function detectCurrentSession() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (!tab || !tab.url || !tab.url.includes('discord.com')) return;
            chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    const raw = localStorage.getItem('token');
                    return raw ? raw.replace(/^"(.*)"$/, '$1') : null;
                }
            }, (results) => {
                if (chrome.runtime.lastError) return;
                const token = results && results[0] && results[0].result;
                if (!token) return;
                validateToken(token).then((user) => {
                    if (!user) return;
                    sessionAvatar.src = user.avatar;
                    sessionAvatar.onerror = () => { sessionAvatar.style.display = 'none'; };
                    sessionName.textContent = '';
                    sessionName.appendChild(document.createTextNode('Logged in as '));
                    const strong = document.createElement('strong');
                    strong.textContent = user.display;
                    sessionName.appendChild(strong);
                    sessionBar.classList.remove('hidden');
                }).catch(() => {});
            });
        });
    }

    // ── Copy ──

    function copyToClipboard() {
        const token = tokenInput.value.trim();
        if (!token) return;
        copyText(token);
        copyBtn.classList.add('copied');
        copyIcon.style.display = 'none';
        copiedIcon.style.display = 'block';
        clearTimeout(copyResetTimer);
        copyResetTimer = setTimeout(() => {
            copyBtn.classList.remove('copied');
            copyIcon.style.display = 'block';
            copiedIcon.style.display = 'none';
        }, 1500);
    }

    function copyText(text) {
        navigator.clipboard.writeText(text).catch(() => {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;opacity:0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        });
    }

    function updateInputButtons() {
        const hasValue = tokenInput.value.trim().length > 0;
        copyBtn.style.display = hasValue ? '' : 'none';
        inputWrapper.classList.toggle('has-copy', hasValue);
    }

    // ── Extract ──

    extractBtn.addEventListener('click', () => {
        extractBtn.classList.add('loading');
        hideStatus(); hideUserPreview();

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const activeTab = tabs[0];
            if (!activeTab || !activeTab.url) { extractBtn.classList.remove('loading'); showStatus('Could not access the current tab', 'error'); return; }

            if (activeTab.url.includes('discord.com')) {
                extractFromTab(activeTab.id);
            } else {
                showStatus('Opening Discord — reopen extension to get the token', 'info');
                chrome.runtime.sendMessage({ action: 'openAndExtract' });
                setTimeout(() => { extractBtn.classList.remove('loading'); }, 1000);
            }
        });
    });

    function extractFromTab(tabId) {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => {
                const raw = localStorage.getItem('token');
                if (raw) return raw.replace(/^"(.*)"$/, '$1');
                try {
                    const iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    document.body.appendChild(iframe);
                    const t = iframe.contentWindow.localStorage.getItem('token');
                    iframe.remove();
                    if (t) return t.replace(/^"(.*)"$/, '$1');
                } catch (e) {}
                return null;
            }
        }, (results) => {
            extractBtn.classList.remove('loading');
            if (chrome.runtime.lastError) { showStatus('Could not access Discord page', 'error'); return; }
            const token = results && results[0] && results[0].result;
            if (token) {
                tokenInput.value = token;
                showToken();
                updateInputButtons();
                showStatus('Token extracted!', 'success', true);
                validateAndShowUser(token);
            } else {
                showStatus('No active session found — log into Discord first', 'info');
            }
        });
    }

    // ── Login ──

    function handleLogin() {
        const token = tokenInput.value.trim();
        if (!token) { tokenInput.classList.add('error'); showStatus('Enter a token to log in', 'error'); tokenInput.focus(); return; }
        if (token.length < 30) { tokenInput.classList.add('error'); showStatus('Token is too short — double-check and try again', 'error'); tokenInput.focus(); return; }

        submitBtn.classList.add('loading');
        hideStatus(); hideUserPreview();

        validateToken(token).then((user) => {
            if (!user) { submitBtn.classList.remove('loading'); tokenInput.classList.add('error'); showStatus('Token is invalid or expired', 'error'); return; }
            saveToHistory(user, token);
            saveLastAccount(user, token);
            submitBtn.classList.remove('loading');

            // Show overlay FIRST, inject AFTER animation completes
            showSwitchOverlay(user.avatar, user.display, () => {
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    const activeTab = tabs[0];
                    if (!activeTab || !activeTab.url || !activeTab.url.includes('discord.com')) {
                        chrome.runtime.sendMessage({ action: 'openAndInject', token: token });
                        setTimeout(() => window.close(), 200);
                        return;
                    }
                    chrome.scripting.executeScript({ target: { tabId: activeTab.id }, func: injectToken, args: [token] }, () => {
                        window.close();
                    });
                });
            });
        }).catch((err) => { submitBtn.classList.remove('loading'); if (err && err.message === 'RATE_LIMITED') { showStatus('Too many requests — wait ' + err.retryAfter + 's and retry', 'error'); } else { showStatusWithAction('Validation failed. ', 'Retry', handleLogin, 'error'); } });
    }

    // ══════════════════════════════════════════
    //  Validation (expanded with Nitro/email/created)
    // ══════════════════════════════════════════

    function validateToken(token) {
        return fetch('https://discord.com/api/v9/users/@me', { headers: { 'Authorization': token } })
            .then((r) => {
                if (r.status === 429) {
                    const retryAfter = r.headers.get('Retry-After');
                    const wait = retryAfter ? Math.ceil(parseFloat(retryAfter)) : 5;
                    const err = new Error('RATE_LIMITED');
                    err.retryAfter = wait;
                    throw err;
                }
                return r.ok ? r.json() : null;
            })
            .then((d) => {
                if (!d) return null;
                const avatarUrl = d.avatar
                    ? 'https://cdn.discordapp.com/avatars/' + d.id + '/' + d.avatar + '.png?size=64'
                    : 'https://cdn.discordapp.com/embed/avatars/' + ((parseInt(d.id) >> 22) % 6) + '.png';

                // Nitro type: 0 = None, 1 = Nitro Classic, 2 = Nitro, 3 = Nitro Basic
                const nitroLabels = { 0: null, 1: 'Nitro Classic', 2: 'Nitro', 3: 'Nitro Basic' };
                const nitroType = d.premium_type || 0;

                // Account creation date from snowflake ID
                const snowflake = BigInt(d.id);
                const createdMs = Number((snowflake >> 22n) + 1420070400000n);
                const createdDate = new Date(createdMs);

                return {
                    display: d.global_name || d.username,
                    tag: d.discriminator && d.discriminator !== '0' ? d.username + '#' + d.discriminator : '@' + d.username,
                    avatar: avatarUrl,
                    id: d.id,
                    email: d.email || null,
                    nitro: nitroLabels[nitroType] || null,
                    nitroType: nitroType,
                    created: createdDate,
                    phone: d.phone || null
                };
            });
    }

    function validateAndShowUser(token) {
        validateToken(token).then((u) => { if (u) showUserPreview(u); }).catch(() => {});
    }

    function showUserPreview(user) {
        userPreview.innerHTML = '';

        // Main row
        const row = document.createElement('div');
        row.className = 'user-preview-row';

        const avatar = document.createElement('img');
        avatar.className = 'user-avatar';
        avatar.src = user.avatar;
        avatar.alt = '';
        avatar.addEventListener('error', () => { avatar.style.display = 'none'; });

        const info = document.createElement('div');
        info.className = 'user-info';
        const displayName = document.createElement('div');
        displayName.className = 'user-displayname';
        displayName.textContent = user.display;
        const tag = document.createElement('div');
        tag.className = 'user-tag';
        tag.textContent = user.tag;
        info.appendChild(displayName);
        info.appendChild(tag);

        const confirm = document.createElement('span');
        confirm.className = 'user-confirm';
        confirm.textContent = 'Verified';

        row.appendChild(avatar);
        row.appendChild(info);
        row.appendChild(confirm);
        userPreview.appendChild(row);

        // Meta badges
        const meta = document.createElement('div');
        meta.className = 'user-meta';

        function makeSvg(paths) {
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '10'); svg.setAttribute('height', '10');
            svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '2.5');
            svg.innerHTML = paths;
            return svg;
        }

        // Nitro
        const nitroBadge = document.createElement('span');
        if (user.nitro) {
            nitroBadge.className = 'meta-badge nitro';
            nitroBadge.appendChild(makeSvg('<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>'));
            nitroBadge.appendChild(document.createTextNode(user.nitro));
        } else {
            nitroBadge.className = 'meta-badge no-nitro';
            nitroBadge.textContent = 'No Nitro';
        }
        meta.appendChild(nitroBadge);

        // Created date
        if (user.created) {
            const dateStr = user.created.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
            const dateBadge = document.createElement('span');
            dateBadge.className = 'meta-badge created';
            dateBadge.appendChild(makeSvg('<rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>'));
            dateBadge.appendChild(document.createTextNode(dateStr));
            meta.appendChild(dateBadge);
        }

        // Email
        if (user.email) {
            const emailBadge = document.createElement('span');
            emailBadge.className = 'meta-badge email-badge';
            emailBadge.appendChild(makeSvg('<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>'));
            emailBadge.appendChild(document.createTextNode(user.email));
            meta.appendChild(emailBadge);
        }

        if (meta.children.length > 0) userPreview.appendChild(meta);

        userPreview.offsetHeight;
        userPreview.classList.remove('hidden');
    }

    function hideUserPreview() {
        userPreview.classList.add('hidden');
        var delay = isSpeedMode() ? 0 : 280;
        setTimeout(() => {
            if (userPreview.classList.contains('hidden')) userPreview.innerHTML = '';
        }, delay);
    }

    // ── History ──

    function saveLastAccount(user, token) {
        encryptToken(token).then((encToken) => {
            chrome.storage.local.set({ lastAccount: { id: user.id, display: user.display, token: encToken } });
        });
    }

    function saveToHistory(user, token) {
        encryptToken(token).then((encToken) => {
            chrome.storage.local.get({ loginHistory: [] }, (data) => {
                let history = data.loginHistory.filter((h) => h.id !== user.id);
                history.unshift({ id: user.id, display: user.display, tag: user.tag, avatar: user.avatar, token: encToken, time: Date.now() });
                history = history.slice(0, MAX_HISTORY);
                chrome.storage.local.set({ loginHistory: history }, () => loadHistory());
            });
        });
    }

    function loadHistory() {
        chrome.storage.local.get({ loginHistory: [] }, (data) => {
            const history = data.loginHistory;
            if (!history.length) { historySection.classList.add('hidden'); return; }
            historySection.classList.remove('hidden');
            historyList.innerHTML = '';

            history.forEach((entry) => {
                const item = document.createElement('div');
                item.className = 'history-item';
                item.title = 'Click to load token';

                const avatar = document.createElement('img');
                avatar.className = 'h-avatar'; avatar.src = entry.avatar; avatar.alt = '';
                avatar.onerror = () => { avatar.style.display = 'none'; };

                const name = document.createElement('span');
                name.className = 'h-name';
                name.textContent = entry.display + ' ';
                const tagSpan = document.createElement('span');
                tagSpan.style.cssText = 'color:var(--text-faint);font-size:10px';
                tagSpan.textContent = entry.tag;
                name.appendChild(tagSpan);

                const time = document.createElement('span');
                time.className = 'h-time';
                time.textContent = getTimeAgo(entry.time);

                const cpBtn = document.createElement('button');
                cpBtn.className = 'h-copy'; cpBtn.title = 'Copy token'; cpBtn.type = 'button';
                cpBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
                cpBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    decryptToken(entry.token).then(plain => {
                        copyText(plain);
                        showStatus('Token copied!', 'success', true);
                    });
                });

                item.addEventListener('click', () => {
                    decryptToken(entry.token).then(plain => {
                        tokenInput.value = plain;
                        showToken();
                        updateInputButtons();
                        hideStatus();
                        showStatus('Token loaded for ' + entry.display + ' — press Log In', 'success', true);
                        tokenInput.focus();
                    });
                });

                item.appendChild(avatar);
                item.appendChild(name);
                item.appendChild(time);
                item.appendChild(cpBtn);
                historyList.appendChild(item);
            });
        });
    }

    function getTimeAgo(ts) {
        const s = Math.floor((Date.now() - ts) / 1000);
        const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
        if (s < 60) return 'just now';
        if (m < 60) return m + 'm ago';
        if (h < 24) return h + 'h ago';
        if (d === 1) return 'yesterday';
        if (d < 7) return d + 'd ago';
        if (d < 30) return Math.floor(d / 7) + 'w ago';
        return new Date(ts).toLocaleDateString();
    }

    // ── Helpers ──

    function showToken() {
        tokenInput.type = 'text';
        eyeIcon.style.display = 'none';
        eyeOffIcon.style.display = 'block';
    }

    function openDiscordAndInject(token, statusLabel) {
        showStatus(statusLabel + ' — opening Discord...', 'info');
        chrome.runtime.sendMessage({ action: 'openAndInject', token: token });
        setTimeout(() => { submitBtn.classList.remove('loading'); }, 1000);
    }

    function injectToken(token) {
        const sanitized = token.replace(/"/g, '');
        localStorage.setItem('token', '"' + sanitized + '"');
        window.location.replace('https://discord.com/channels/@me');
    }

    function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }

    function showStatus(msg, type, chk) {
        // Set content while collapsed
        if (type === 'success' && chk) {
            statusEl.innerHTML =
                '<svg class="checkmark-icon" viewBox="0 0 24 24" fill="none"><circle class="check-circle" cx="12" cy="12" r="10" stroke="#57f287" stroke-width="2"/><path class="checkmark-path" d="M7 12.5l3.5 3.5 6.5-7" stroke="#57f287" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>' + msg + '</span>';
        } else { statusEl.textContent = msg; }
        // Apply type class but keep hidden to set starting state
        statusEl.className = 'status ' + type + ' hidden';
        statusEl.offsetHeight; // force reflow
        statusEl.classList.remove('hidden');
    }

    function showStatusWithAction(text, label, fn, type) {
        statusEl.innerHTML = '';
        const s = document.createElement('span'); s.textContent = text;
        const b = document.createElement('button'); b.className = 'status-action'; b.textContent = label;
        b.addEventListener('click', fn); s.appendChild(b); statusEl.appendChild(s);
        statusEl.className = 'status ' + (type || 'info') + ' hidden';
        statusEl.offsetHeight; // force reflow
        statusEl.classList.remove('hidden');
    }

    function hideStatus() {
        statusEl.classList.add('hidden');
        var delay = isSpeedMode() ? 0 : 280;
        setTimeout(() => {
            if (statusEl.classList.contains('hidden')) {
                statusEl.innerHTML = '';
                statusEl.className = 'status hidden';
            }
        }, delay);
    }
});
