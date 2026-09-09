// ==UserScript==
// @name         CTF Flag Scanner Suite
// @namespace    Violentmonkey Scripts
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @version      1.1.0
// @author       Antigravity
// @description  Automated scanner for capturing CTF flags across DOM text, hidden styles, comments, base64 strings, storage, cookies, scripts, and headers. Enable only on CTF hosts.
// @run-at       document-idle
// @noframes
// ==/UserScript==

(function () {
    'use strict';

    // TIP: enable only on your CTF host (Violentmonkey → match rules) to avoid
    // running on every site. Set LOOSE_MODE=true for custom-prefix challenges.
    const LOOSE_MODE = false;

    // Target window object (unsafeWindow for Violentmonkey sandbox, or fallback to window)
    const targetWindow = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;

    // Strict by default (known prefixes, low FP for early rounds).
    const STRICT_FLAG_SRC = '(?:flag|ctf|picoCTF|HTB|THM|kju|CHTB|SEKAI|UIUCTF|PatriotCTF)\\{[^}\\r\\n]{1,200}\\}';
    const LOOSE_FLAG_SRC = '[A-Za-z0-9_\\-]{3,25}\\{[A-Za-z0-9_\\-!@#$%^&*()+=~`|:\\;"\'<>,.?/\\\\ \\[\\]]{1,200}\\}';
    const FLAG_SRC = LOOSE_MODE ? LOOSE_FLAG_SRC : STRICT_FLAG_SRC;
    function flagRegex() { return new RegExp(FLAG_SRC, 'gi'); }

    // UUIDs are hints, not flags (separate console group to cut noise)
    const UUID_REGEX = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/gi;

    const B64_CANDIDATE_REGEX = /[A-Za-z0-9+/]{8,}={0,2}/g;

    let discoveredFlags = new Map(); // key: flag string, value: { category, location, raw }

    // Helper: Log and store discovered flags safely
    function logFlag(flag, category, location, raw = flag, element = null) {
        if (!discoveredFlags.has(flag)) {
            discoveredFlags.set(flag, { flag, category, location, raw, element });
            console.log(`%c[FLAG FOUND] [${category}] %c${flag} %c(Location: ${location})`,
                'color: #ff0055; font-weight: bold;',
                'color: #00ffcc; font-weight: bold;',
                'color: #bbbbbb;');
        }
    }

    // Helper: Extract plain flags from text (strict; UUIDs logged as hints only)
    function findFlags(text) {
        if (typeof text !== 'string') return [];
        const braced = text.match(flagRegex());
        const out = braced ? Array.from(new Set(braced)) : [];
        const uuids = text.match(UUID_REGEX);
        if (uuids) {
            for (const u of new Set(uuids)) {
                console.log(`%c[HINT] [uuid] %c${u}`, 'color: #ffaa00; font-weight: bold;', 'color: #bbbbbb;');
            }
        }
        return out;
    }

    function padB64(s) {
        while (s.length % 4 !== 0) s += '=';
        return s;
    }

    function isValidB64(s) {
        s = s.replace(/\s+/g, '');
        if (s.length < 8 || s.length % 4 === 1) return false;
        try {
            const padded = padB64(s);
            const dec = atob(padded);
            // round-trip: re-encode must match (ignoring padding)
            const re = btoa(dec).replace(/=+$/, '');
            return re === s.replace(/=+$/, '');
        } catch (e) {
            return false;
        }
    }

    // Helper: Extract Base64 encoded flags (validated round-trip, up to 3 nested layers)
    function findBase64Flags(text) {
        if (typeof text !== 'string' || text.length < 8) return [];
        const candidates = new Set(text.match(B64_CANDIDATE_REGEX) || []);
        const found = [];

        const scanLayers = (token, depth, chain) => {
            if (depth > 3) return;
            if (!isValidB64(token)) return;
            let decoded;
            try {
                decoded = atob(padB64(token.replace(/\s+/g, '')));
            } catch (e) { return; }
            if (!/[\x20-\x7E]{4,}/.test(decoded)) return;
            const flags = decoded.match(flagRegex()) || [];
            for (const flag of new Set(flags)) {
                found.push({ flag, encoded: chain });
            }
            // nested layer: first valid token inside decoded output
            const inner = new Set(decoded.match(B64_CANDIDATE_REGEX) || []);
            for (const tok of inner) {
                if (isValidB64(tok)) { scanLayers(tok, depth + 1, chain + ' > ' + tok.slice(0, 16) + '...'); break; }
            }
        };

        for (const candidate of candidates) {
            try {
                scanLayers(candidate, 1, candidate);
            } catch (e) {
                // Not valid base64 or decode error
            }
        }
        return found;
    }

    // Helper: Check if a DOM element is hidden via CSS or attributes
    function getHiddenReason(element) {
        if (!element || element.nodeType !== Node.ELEMENT_NODE) return null;
        if (element.hasAttribute('hidden')) return 'hidden attribute';

        const style = window.getComputedStyle(element);
        if (style.display === 'none') return 'display: none';
        if (style.visibility === 'hidden') return 'visibility: hidden';
        if (style.opacity === '0' || parseFloat(style.opacity) === 0) return 'opacity: 0';
        if (style.fontSize === '0px' || parseFloat(style.fontSize) === 0) return 'font-size: 0';
        if (style.color && style.backgroundColor && style.color === style.backgroundColor) {
            return 'same color/bg';
        }

        return null;
    }

    // 1. Scan DOM Text & Hidden Elements
    function scanDOM() {
        const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, null, false);
        let node;
        while (node = walker.nextNode()) {
            const parent = node.parentElement;
            if (!parent || parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE') continue;

            const text = node.nodeValue;
            const flags = findFlags(text);
            const hiddenReason = getHiddenReason(parent);
            const category = hiddenReason ? `Hidden DOM (${hiddenReason})` : 'DOM Text';

            flags.forEach(f => logFlag(f, category, `<${parent.tagName.toLowerCase()}>`, f, parent));

            const b64Flags = findBase64Flags(text);
            b64Flags.forEach(item => logFlag(item.flag, `Base64 (${category})`, `Encoded: ${item.encoded}`, item.flag, parent));
        }

        // Scan Element Attributes & Hidden Inputs
        const allElements = document.querySelectorAll('*');
        allElements.forEach(el => {
            for (const attr of el.attributes) {
                const val = attr.value;
                const flags = findFlags(val);
                flags.forEach(f => {
                    const tag = el.tagName.toLowerCase();
                    const isHiddenInput = tag === 'input' && el.type === 'hidden';
                    const cat = isHiddenInput ? 'Hidden Form Input' : `Attribute (${attr.name})`;
                    logFlag(f, cat, `<${tag} ${attr.name}="${val}">`, f, el);
                });

                const b64Flags = findBase64Flags(val);
                b64Flags.forEach(item => {
                    logFlag(item.flag, `Base64 Attribute (${attr.name})`, `Encoded: ${item.encoded}`, item.flag, el);
                });
            }
        });
    }

    // 2. Scan HTML Comments
    function scanComments() {
        const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT, null, false);
        let node;
        while (node = walker.nextNode()) {
            const flags = findFlags(node.nodeValue);
            flags.forEach(f => logFlag(f, 'HTML Comment', 'Comment Node'));

            const b64Flags = findBase64Flags(node.nodeValue);
            b64Flags.forEach(item => logFlag(item.flag, 'Base64 Comment', `Encoded: ${item.encoded}`));
        }
    }

    // 3. Scan Storage (Cookies, LocalStorage, SessionStorage)
    function scanStorage() {
        // Cookies
        if (document.cookie) {
            const cookies = document.cookie.split(';');
            cookies.forEach(c => {
                const trimmed = c.trim();
                findFlags(trimmed).forEach(f => logFlag(f, 'Cookie', `document.cookie (${trimmed})`));
                findBase64Flags(trimmed).forEach(item => logFlag(item.flag, 'Base64 Cookie', `Encoded in cookie: ${item.encoded}`));
            });
        }

        // LocalStorage
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const val = localStorage.getItem(key);
                findFlags(`${key}=${val}`).forEach(f => logFlag(f, 'LocalStorage', `Key: ${key}`));
                findBase64Flags(`${key}=${val}`).forEach(item => logFlag(item.flag, 'Base64 LocalStorage', `Key: ${key}`));
            }
        } catch (e) {}

        // SessionStorage
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const val = sessionStorage.getItem(key);
                findFlags(`${key}=${val}`).forEach(f => logFlag(f, 'SessionStorage', `Key: ${key}`));
                findBase64Flags(`${key}=${val}`).forEach(item => logFlag(item.flag, 'Base64 SessionStorage', `Key: ${key}`));
            }
        } catch (e) {}
    }

    // 4. Scan Inline Scripts and Global JS Variables
    function scanScriptsAndGlobals() {
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
            const content = script.textContent;
            if (content) {
                findFlags(content).forEach(f => logFlag(f, 'Script Tag', 'Inline <script>'));
                findBase64Flags(content).forEach(item => logFlag(item.flag, 'Base64 Script', `Encoded: ${item.encoded}`));
            }
            // external script source-map hint (common in small web CTFs)
            const src = script.getAttribute && script.getAttribute('src');
            if (src && /\.js($|\?)/.test(src)) {
                const mapUrl = src + '.map';
                fetch(mapUrl, { method: 'GET' }).then(r => r.ok ? r.text() : '').then(t => {
                    if (t) {
                        findFlags(t).forEach(f => logFlag(f, 'SourceMap', mapUrl));
                        findBase64Flags(t).forEach(item => logFlag(item.flag, 'Base64 SourceMap', mapUrl));
                    }
                }).catch(() => {});
            }
        });

        // Scan custom global properties attached to window/unsafeWindow
        const standardProps = new Set([
            'window', 'self', 'document', 'name', 'location', 'customElements', 'history',
            'locationbar', 'menubar', 'personalbar', 'scrollbars', 'statusbar', 'toolbar',
            'status', 'closed', 'frames', 'length', 'top', 'opener', 'parent', 'frameElement',
            'navigator', 'origin', 'external', 'screen', 'innerWidth', 'innerHeight',
            'scrollX', 'pageXOffset', 'scrollY', 'pageYOffset', 'visualViewport', 'screenX',
            'screenY', 'outerWidth', 'outerHeight', 'devicePixelRatio', 'clientInformation',
            'screenLeft', 'screenTop', 'styleMedia', 'isSecureContext', 'performance', 'discoveredFlags'
        ]);

        try {
            const keys = Object.keys(targetWindow);
            for (const key of keys) {
                if (standardProps.has(key) || key.startsWith('webkit') || key.startsWith('chrome')) continue;
                try {
                    const val = targetWindow[key];
                    let sval = '';
                    if (typeof val === 'string') sval = val;
                    else if (val && typeof val === 'object') {
                        try { sval = JSON.stringify(val).slice(0, 20000); } catch (e) { continue; }
                    } else continue;
                    if (sval) {
                        findFlags(sval).forEach(f => logFlag(f, 'JS Global Variable', `window.${key}`));
                        findBase64Flags(sval).forEach(item => logFlag(item.flag, 'Base64 JS Global', `window.${key}`));
                    }
                } catch (e) {}
            }
        } catch (e) {}
    }

    // 4b. Hook fetch/XHR to scan async API responses (React/SPA flags)
    function hookNetwork() {
        const scanBody = (text, where) => {
            if (typeof text !== 'string' || !text) return;
            findFlags(text).forEach(f => logFlag(f, 'Network Response', where));
            findBase64Flags(text).forEach(item => logFlag(item.flag, 'Base64 Network', `${where} Encoded: ${item.encoded}`));
        };
        try {
            const origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function (...args) {
                    return origFetch.apply(this, args).then(res => {
                        try {
                            const clone = res.clone();
                            clone.text().then(t => scanBody(t.slice(0, 200000), String(args[0]).slice(0, 120))).catch(() => {});
                        } catch (e) {}
                        return res;
                    });
                };
            }
        } catch (e) {}
        try {
            const origOpen = XMLHttpRequest.prototype.open;
            const origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function (m, u, ...rest) { this._ctfUrl = u; return origOpen.call(this, m, u, ...rest); };
            XMLHttpRequest.prototype.send = function (...args) {
                this.addEventListener('load', function () {
                    try { scanBody(String(this.responseText || '').slice(0, 200000), String(this._ctfUrl || 'XHR').slice(0, 120)); } catch (e) {}
                });
                return origSend.apply(this, args);
            };
        } catch (e) {}
    }

    // 5. Scan HTTP Response Headers (using GM_xmlhttpRequest to bypass CORS header restrictions)
    function scanHeaders() {
        const processHeadersText = (headersText) => {
            if (!headersText) return;
            findFlags(headersText).forEach(f => logFlag(f, 'HTTP Header', 'HTTP Response Header'));
            findBase64Flags(headersText).forEach(item => logFlag(item.flag, 'Base64 HTTP Header', `Encoded: ${item.encoded}`));

            // Also check individual header lines
            const lines = headersText.split('\r\n');
            lines.forEach(line => {
                const parts = line.split(':');
                if (parts.length >= 2) {
                    const key = parts[0].trim();
                    const val = parts.slice(1).join(':').trim();
                    findFlags(val).forEach(f => logFlag(f, 'HTTP Header', `Header [${key}]`));
                    findBase64Flags(val).forEach(item => logFlag(item.flag, 'Base64 HTTP Header', `Header [${key}] Encoded: ${item.encoded}`));
                }
            });
        };

        if (typeof GM_xmlhttpRequest !== 'undefined') {
            try {
                GM_xmlhttpRequest({
                    method: 'GET',
                    url: window.location.href,
                    onload: function (response) {
                        processHeadersText(response.responseHeaders);
                    }
                });
            } catch (e) {}
        } else {
            try {
                fetch(window.location.href, { method: 'HEAD' })
                    .then(res => {
                        let headerStr = '';
                        res.headers.forEach((val, key) => {
                            headerStr += `${key}: ${val}\r\n`;
                        });
                        processHeadersText(headerStr);
                    })
                    .catch(() => {});
            } catch (e) {}
        }
    }

    // Run all scanning functions
    let debounceTimer = null;
    function rescan(reason) {
        scanDOM();
        scanComments();
        scanStorage();
        scanScriptsAndGlobals();
        targetWindow.discoveredFlags = discoveredFlags;
        if (discoveredFlags.size > 0) {
            console.log(`%c[+] [${reason}] Total Flags: ${discoveredFlags.size}. Type 'discoveredFlags' to view.`, 'color: #ffff00; font-weight: bold;');
        }
    }
    function initScanner() {
        console.log('%c[+] CTF Flag Scanner Suite Activated (strict mode)...', 'color: #00ff00; font-weight: bold;');
        scanDOM();
        scanComments();
        scanStorage();
        scanScriptsAndGlobals();
        scanHeaders();
        hookNetwork();

        // Re-scan on SPA/DOM mutations (debounced 800ms)
        try {
            const obs = new MutationObserver(() => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => rescan('mutation'), 800);
            });
            obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
        } catch (e) {}

        // Expose flags map to targetWindow for console access
        targetWindow.discoveredFlags = discoveredFlags;
        targetWindow.CTF_rescan = () => rescan('manual');
        if (discoveredFlags.size > 0) {
            console.log(`%c[+] Total Flags Found: ${discoveredFlags.size}. Type 'discoveredFlags' in console to view all.`, 'color: #ffff00; font-weight: bold;');
        }
    }

    // Execute scanner
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(initScanner, 300);
    } else {
        window.addEventListener('DOMContentLoaded', () => setTimeout(initScanner, 300));
    }
})();
