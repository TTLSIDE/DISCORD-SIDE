// Background service worker — survives popup close

// ── Context menu ──

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'extract-token',
        title: 'Extract Token',
        contexts: ['action']
    });
    chrome.contextMenus.create({
        id: 'switch-last',
        title: 'Switch to Last Account',
        contexts: ['action']
    });
});

chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === 'extract-token') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (tab && tab.url && tab.url.includes('discord.com')) {
                extractTokenFromTab(tab.id);
            } else {
                openDiscordTab((tabId) => extractTokenFromTab(tabId));
            }
        });
    }
    if (info.menuItemId === 'switch-last') {
        chrome.storage.local.get({ lastAccount: null }, (data) => {
            if (!data.lastAccount || !data.lastAccount.token) {
                savePendingResult({ type: 'inject', success: false, error: 'No recent account — log in first' });
                return;
            }
            decryptToken(data.lastAccount.token).then((plain) => {
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    const tab = tabs[0];
                    if (tab && tab.url && tab.url.includes('discord.com')) {
                        injectTokenInTab(tab.id, plain);
                    } else {
                        openDiscordTab((tabId) => injectTokenInTab(tabId, plain));
                    }
                });
            }).catch(() => {
                savePendingResult({ type: 'inject', success: false, error: 'Could not decrypt token' });
            });
        });
    }
});

// ── Token decryption (mirrors popup.js) ──

const CRYPTO_SALT_KEY = '_cryptoSalt';

async function getCryptoKey() {
    const stored = await chrome.storage.local.get(CRYPTO_SALT_KEY);
    const saltHex = stored[CRYPTO_SALT_KEY];
    if (!saltHex) throw new Error('No crypto salt');
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

async function decryptToken(stored) {
    if (!stored || !stored.includes(':')) return stored;
    const [ivHex, cipherHex] = stored.split(':');
    if (ivHex.length !== 24) return stored;
    const key = await getCryptoKey();
    const iv = new Uint8Array(ivHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const cipher = new Uint8Array(cipherHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    return new TextDecoder().decode(plain);
}

// ── Messages from popup ──

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'openAndExtract') {
        openDiscordTab((tabId) => {
            extractTokenFromTab(tabId);
        });
    }

    if (msg.action === 'openAndInject') {
        openDiscordTab((tabId) => {
            injectTokenInTab(tabId, msg.token);
        });
    }
});

// On popup open, it will check chrome.storage for pendingResult

function openDiscordTab(callback) {
    chrome.tabs.create({ url: 'https://discord.com/channels/@me', active: true }, (tab) => {
        waitForTabLoad(tab.id, () => {
            // Extra delay for Discord JS to initialize
            setTimeout(() => callback(tab.id), 1500);
        });
    });
}

function waitForTabLoad(tabId, callback) {
    let resolved = false;
    const listener = (id, info) => {
        if (id === tabId && info.status === 'complete') {
            resolved = true;
            chrome.tabs.onUpdated.removeListener(listener);
            callback();
        }
    };
    chrome.tabs.onUpdated.addListener(listener);

    // Safety timeout — notify user if page never finishes loading
    setTimeout(() => {
        if (!resolved) {
            chrome.tabs.onUpdated.removeListener(listener);
            savePendingResult({ type: 'inject', success: false, error: 'Discord took too long to load — try again' });
        }
    }, 20000);
}

function extractTokenFromTab(tabId) {
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
        if (chrome.runtime.lastError) {
            savePendingResult({ type: 'extract', success: false, error: 'Could not access Discord page' });
            return;
        }
        const token = results && results[0] && results[0].result;
        if (token) {
            savePendingResult({ type: 'extract', success: true, token: token });
        } else {
            savePendingResult({ type: 'extract', success: false, error: 'No active session found — log into Discord first' });
        }
    });
}

function injectTokenInTab(tabId, token) {
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (t) => {
            const sanitized = t.replace(/"/g, '');
            localStorage.setItem('token', '"' + sanitized + '"');
            window.location.replace('https://discord.com/channels/@me');
        },
        args: [token]
    }, () => {
        if (chrome.runtime.lastError) {
            savePendingResult({ type: 'inject', success: false, error: chrome.runtime.lastError.message });
        } else {
            savePendingResult({ type: 'inject', success: true });
        }
    });
}

function savePendingResult(result) {
    result.timestamp = Date.now();
    chrome.storage.local.set({ pendingResult: result });
    // Show badge to indicate result is ready
    if (result.success) {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#57f287' });
    } else {
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#ed4245' });
    }
    // Clear badge after 30s
    setTimeout(() => {
        chrome.action.setBadgeText({ text: '' });
    }, 30000);
}
