// ==UserScript==
// @name         CTF Flag Scanner Suite
// @namespace    Violentmonkey Scripts
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setClipboard
// @grant        unsafeWindow
// @version      1.0.0
// @author       Antigravity
// @description  Automated scanner for capturing CTF flags across DOM text, hidden styles, comments, base64 strings, storage, cookies, scripts, and headers.
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    // Target window object (unsafeWindow for Violentmonkey sandbox, or fallback to window)
    const targetWindow = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;

    // Universal Flag Pattern: Matches ANY prefix (e.g. HTB{...}, picoCTF{...}, THM{...}, custom_flag{...})
    const GENERIC_BRACED_FLAG_REGEX = /[A-Za-z0-9_\-]{1,25}\{[^}\s\r\n]+\}/gi;

    // Optional Hex Hashes & UUID flag patterns (MD5 / SHA256 / UUID)
    const UUID_REGEX = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/gi;
    const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/gi;

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

    // Helper: Extract plain flags from text
    function findFlags(text) {
        if (typeof text !== 'string') return [];
        let results = [];
        
        // 1. Generic Braced Flags (matches ANY_PREFIX{...})
        const braced = text.match(GENERIC_BRACED_FLAG_REGEX);
        if (braced) results.push(...braced);

        // 2. UUID Formats
        const uuids = text.match(UUID_REGEX);
        if (uuids) results.push(...uuids);

        // 3. SHA-256 Hashes
        const hashes = text.match(SHA256_REGEX);
        if (hashes) results.push(...hashes);

        return Array.from(new Set(results));
    }

    // Helper: Extract Base64 encoded flags
    function findBase64Flags(text) {
        if (typeof text !== 'string') return [];
        const candidates = text.match(B64_CANDIDATE_REGEX) || [];
        const found = [];

        for (const candidate of candidates) {
            try {
                // Normalize base64 padding
                let padCandidate = candidate;
                while (padCandidate.length % 4 !== 0) padCandidate += '=';

                const decoded = atob(padCandidate);
                const flags = findFlags(decoded);
                for (const flag of flags) {
                    found.push({ flag, encoded: candidate });
                }
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
                    if (typeof val === 'string') {
                        findFlags(val).forEach(f => logFlag(f, 'JS Global Variable', `window.${key}`));
                        findBase64Flags(val).forEach(item => logFlag(item.flag, 'Base64 JS Global', `window.${key}`));
                    }
                } catch (e) {}
            }
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
    function initScanner() {
        console.log('%c[+] CTF Flag Scanner Suite Activated...', 'color: #00ff00; font-weight: bold;');
        scanDOM();
        scanComments();
        scanStorage();
        scanScriptsAndGlobals();
        scanHeaders();

        // Expose flags map to targetWindow for console access
        targetWindow.discoveredFlags = discoveredFlags;
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
