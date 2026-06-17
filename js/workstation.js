/* =====================================================================
   Delock Workstation — local encryption / hashing / encoding engine
   All crypto runs in-browser via the Web Crypto API (+ a small MD5).
   ===================================================================== */
(function () {
  'use strict';

  /* ----------------------- Algorithm registry ----------------------- */
  const ALGOS = [
    { id: 'delock',  name: 'Delock',   tag: 'Hybrid', container: 'algoList', type: 'gcm',
      category: 'Symmetric', spec: 'AES-256 · GCM', reversible: true, key: true, iv: 12,
      about: ['Delock Hybrid wraps AES-256-GCM with a PBKDF2-derived key and a random salt + IV, then packages everything into one portable blob.',
              'Pros: authenticated, tamper-evident, only needs your passphrase to decrypt.',
              'Cons: not a published standard name — interoperate using the AES-GCM option instead.'] },
    { id: 'aes-gcm', name: 'AES-GCM',  tag: 'AEAD', container: 'algoList', type: 'gcm',
      category: 'Symmetric', spec: 'AES-256 · GCM', reversible: true, key: true, iv: 12,
      about: ['AES-256 in Galois/Counter Mode — authenticated encryption that protects both confidentiality and integrity.',
              'Pros: fast, tamper-evident, the modern default for symmetric encryption.',
              'Cons: a nonce must never be reused with the same key (Delock randomizes it for you).'] },
    { id: 'aes-cbc', name: 'AES-CBC',  tag: 'IV', container: 'algoList', type: 'cbc',
      category: 'Symmetric', spec: 'AES-256 · CBC', reversible: true, key: true, iv: 16,
      about: ['AES-256 in Cipher Block Chaining mode with a random IV and PKCS#7 padding.',
              'Pros: widely supported and well understood.',
              'Cons: not authenticated on its own — prefer AES-GCM when you can.'] },

    { id: 'sha-256', name: 'SHA-256',  tag: '1-way', container: 'hashList', type: 'hash', subtle: 'SHA-256',
      category: 'Hashing', spec: '256-bit digest', reversible: false, key: false,
      about: ['SHA-256 produces a fixed 256-bit fingerprint of any input.',
              'Pros: collision-resistant, ideal for integrity checks and checksums.',
              'Cons: one-way — you cannot recover the original input from the digest.'] },
    { id: 'sha-512', name: 'SHA-512',  tag: '1-way', container: 'hashList', type: 'hash', subtle: 'SHA-512',
      category: 'Hashing', spec: '512-bit digest', reversible: false, key: false,
      about: ['SHA-512 produces a 512-bit fingerprint, part of the SHA-2 family.',
              'Pros: large output space, strong integrity guarantees.',
              'Cons: one-way; longer output than usually needed for simple checks.'] },
    { id: 'md5',     name: 'MD5',      tag: '1-way', container: 'hashList', type: 'md5',
      category: 'Hashing', spec: '128-bit digest', reversible: false, key: false,
      about: ['MD5 produces a 128-bit digest. Handy for non-security checksums and legacy compatibility.',
              'Pros: fast and ubiquitous.',
              'Cons: cryptographically broken — never use it for security or passwords.'] },

    { id: 'base64',  name: 'Base64',   tag: 'rev', container: 'encList', type: 'base64',
      category: 'Encoding', spec: 'RFC 4648', reversible: true, key: false,
      about: ['Base64 represents binary data as ASCII text using 64 symbols.',
              'Pros: transport-safe, reversible, great for embedding binary in text.',
              'Cons: not encryption — anyone can decode it.'] },
    { id: 'hex',     name: 'Hex',      tag: 'rev', container: 'encList', type: 'hex',
      category: 'Encoding', spec: 'Base16', reversible: true, key: false,
      about: ['Hexadecimal encodes each byte as two characters (0-9, a-f).',
              'Pros: human-readable byte view, reversible.',
              'Cons: doubles the size; not encryption.'] },
    { id: 'url',     name: 'URL',      tag: 'rev', container: 'encList', type: 'url',
      category: 'Encoding', spec: 'Percent-encoding', reversible: true, key: false,
      about: ['URL (percent) encoding escapes characters that are unsafe in URLs.',
              'Pros: makes arbitrary text query-string safe, reversible.',
              'Cons: not encryption; only escapes reserved characters.'] }
  ];

  /* ------------------------------ State ----------------------------- */
  let current = ALGOS[1];          // AES-GCM default (matches screenshot)
  let mode = 'encrypt';            // encrypt | decrypt
  let inputTab = 'text';           // text | file | api
  let format = 'base64';           // base64 | hex
  let fileBytes = null, fileName = '';
  let gridEl = null;               // .ws-grid (mobile app-view switching)

  /* ----------------------------- Helpers ---------------------------- */
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function base64ToBytes(b64) {
    const bin = atob(b64.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }
  function hexToBytes(hex) {
    const h = hex.trim().replace(/\s+/g, '');
    if (h.length % 2) throw new Error('Invalid hex length');
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) {
      const b = parseInt(h.substr(i * 2, 2), 16);
      if (Number.isNaN(b)) throw new Error('Invalid hex characters');
      out[i] = b;
    }
    return out;
  }
  const encodeOut = (bytes) => format === 'hex' ? bytesToHex(bytes) : bytesToBase64(bytes);
  const decodeIn  = (str)   => format === 'hex' ? hexToBytes(str)   : base64ToBytes(str);

  function concat(...arrs) {
    const len = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }

  /* --------------------------- AES via PBKDF2 ----------------------- */
  async function deriveKey(passphrase, salt, algoName) {
    const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
      base,
      { name: algoName, length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function symEncrypt(algo, passphrase, dataBytes) {
    const algoName = algo.type === 'cbc' ? 'AES-CBC' : 'AES-GCM';
    const salt = rnd(16);
    const iv = rnd(algo.iv);
    const key = await deriveKey(passphrase, salt, algoName);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: algoName, iv }, key, dataBytes));
    return concat(salt, iv, ct);          // package = salt | iv | ciphertext
  }

  async function symDecrypt(algo, passphrase, packaged) {
    const algoName = algo.type === 'cbc' ? 'AES-CBC' : 'AES-GCM';
    if (packaged.length < 16 + algo.iv + 1) throw new Error('Input too short to be valid ciphertext');
    const salt = packaged.slice(0, 16);
    const iv = packaged.slice(16, 16 + algo.iv);
    const ct = packaged.slice(16 + algo.iv);
    const key = await deriveKey(passphrase, salt, algoName);
    return new Uint8Array(await crypto.subtle.decrypt({ name: algoName, iv }, key, ct));
  }

  /* ------------------------------- MD5 ------------------------------ */
  function md5bytes(input) {
    function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
    function add(a, b) { return (a + b) & 0xffffffff; }
    const s = [7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
               5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
               4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
               6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21];
    const K = [];
    for (let i = 0; i < 64; i++) K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0;

    const ml = input.length * 8;
    const withOne = concat(input, new Uint8Array([0x80]));
    let padLen = (56 - withOne.length % 64 + 64) % 64;
    const msg = concat(withOne, new Uint8Array(padLen), new Uint8Array(8));
    const dv = new DataView(msg.buffer);
    dv.setUint32(msg.length - 8, ml & 0xffffffff, true);
    dv.setUint32(msg.length - 4, Math.floor(ml / 4294967296), true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let off = 0; off < msg.length; off += 64) {
      const M = [];
      for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16)      { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
        F = add(add(add(F, A), K[i]), M[g]);
        A = D; D = C; C = B;
        B = add(B, rol(F, s[i]));
      }
      a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
    }
    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0, true); odv.setUint32(4, b0, true);
    odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
    return out;
  }

  /* --------------------------- Core run ----------------------------- */
  async function run(dataBytes) {
    const t = current.type;

    // Encoding algorithms
    if (t === 'base64') {
      return mode === 'encrypt' ? bytesToBase64(dataBytes) : dec.decode(base64ToBytes(dec.decode(dataBytes)));
    }
    if (t === 'hex') {
      return mode === 'encrypt' ? bytesToHex(dataBytes) : dec.decode(hexToBytes(dec.decode(dataBytes)));
    }
    if (t === 'url') {
      const text = dec.decode(dataBytes);
      return mode === 'encrypt' ? encodeURIComponent(text) : decodeURIComponent(text);
    }

    // Hashing
    if (t === 'hash') {
      const digest = new Uint8Array(await crypto.subtle.digest(current.subtle, dataBytes));
      return encodeOut(digest);
    }
    if (t === 'md5') {
      return encodeOut(md5bytes(dataBytes));
    }

    // Symmetric encryption
    const passphrase = $('keyInput').value;
    if (!passphrase) throw new Error('Enter a secret key to ' + mode);
    if (mode === 'encrypt') {
      const packaged = await symEncrypt(current, passphrase, dataBytes);
      return encodeOut(packaged);
    } else {
      const packaged = decodeIn(dec.decode(dataBytes));
      const plain = await symDecrypt(current, passphrase, packaged);
      return plain;   // return bytes; caller decides text/download
    }
  }

  /* ---------------------------- UI render --------------------------- */
  function renderLists() {
    ['algoList', 'hashList', 'encList'].forEach((c) => { $(c).innerHTML = ''; });
    ALGOS.forEach((a) => {
      const li = document.createElement('li');
      li.className = 'ws-item' + (a.id === current.id ? ' active' : '');
      li.dataset.id = a.id;
      li.innerHTML = `<span class="ws-name">${a.name}</span><span class="ws-tag">${a.tag}</span>`;
      li.addEventListener('click', () => selectAlgo(a.id));
      $(a.container).appendChild(li);
    });
  }

  function selectAlgo(id) {
    current = ALGOS.find((a) => a.id === id) || current;
    document.querySelectorAll('.ws-item').forEach((el) =>
      el.classList.toggle('active', el.dataset.id === id));

    // badge + parameters
    $('badgeText').textContent = `${current.name} · ${current.spec}`;
    $('pCategory').textContent = current.category;
    $('pSpec').textContent = current.spec;
    $('pReversible').textContent = current.reversible ? 'Yes' : 'No';

    // mode availability (one-way algos cannot decrypt)
    const canDecrypt = current.reversible;
    $('modeDecrypt').disabled = !canDecrypt;
    if (!canDecrypt && mode === 'decrypt') setMode('encrypt');

    // field availability
    $('keyField').classList.toggle('dim-disabled', !current.key);
    $('strengthField').classList.toggle('dim-disabled', !current.key);
    // format only meaningful for binary output (sym + hash)
    const usesFormat = current.key || current.type === 'hash' || current.type === 'md5';
    $('formatField').classList.toggle('dim-disabled', !usesFormat);

    $('algosCurrent').textContent = current.name;
    const algosEl = $('wsAlgos');
    if (algosEl) algosEl.classList.remove('open');   // collapse selector after picking (mobile)

    updateRunLabel();
    updateExplain();
    updateApiSnippet();
    clearOutput();
    updateTabState();
  }

  /* bottom-tab / view switching (Vault / Encrypt / Decrypt / More) */
  const VIEW_TITLES = { vault: 'Vault', encrypt: 'Encrypt', decrypt: 'Decrypt', more: 'More', me: 'Me' };
  function setView(v) {
    if (!gridEl) return;
    if (v === 'decrypt' && !current.reversible) v = 'encrypt';   // one-way algos can't decrypt
    gridEl.dataset.view = v;
    document.querySelectorAll('#wsTabbar button').forEach((b) =>
      b.classList.toggle('active', b.dataset.view === v));
    const title = $('viewTitle');
    if (title) title.textContent = VIEW_TITLES[v] || 'Encrypt';
    if (v === 'vault') renderVault();
    else if (v === 'me') renderMe();
    else if (v === 'encrypt') setMode('encrypt');
    else if (v === 'decrypt') setMode('decrypt');
  }
  function updateTabState() {
    const dec = document.querySelector('#wsTabbar button[data-view="decrypt"]');
    if (dec) dec.classList.toggle('disabled', !current.reversible);
    if (!current.reversible && gridEl && gridEl.dataset.view === 'decrypt') setView('encrypt');
  }

  function setMode(m) {
    mode = m;
    $('modeEncrypt').classList.toggle('active', m === 'encrypt');
    $('modeDecrypt').classList.toggle('active', m === 'decrypt');
    updateRunLabel();
    updateApiSnippet();
    clearOutput();
  }

  function updateRunLabel() {
    let label;
    if (current.type === 'hash' || current.type === 'md5') label = 'Hash';
    else if (['base64', 'hex', 'url'].includes(current.type)) label = mode === 'encrypt' ? 'Encode' : 'Decode';
    else label = mode === 'encrypt' ? 'Encrypt' : 'Decrypt';
    $('runLabel').textContent = label;
  }

  function updateExplain() {
    $('explainBody').innerHTML =
      `<h5>${current.name} — ${current.category}</h5>` +
      current.about.map((p) => `<p>${p}</p>`).join('');
  }

  function updateApiSnippet() {
    const fmt = format;
    let code;
    if (current.key) {
      code =
`POST https://api.delock.app/v1/${mode}
Content-Type: application/json

{
  "algorithm": "${current.id}",
  "format": "${fmt}",
  "key": "<your-secret-key>",
  "input": "<your-${mode === 'encrypt' ? 'plaintext' : 'ciphertext'}>"
}`;
    } else if (current.type === 'hash' || current.type === 'md5') {
      code =
`POST https://api.delock.app/v1/hash

{
  "algorithm": "${current.id}",
  "format": "${fmt}",
  "input": "<your-data>"
}`;
    } else {
      code =
`POST https://api.delock.app/v1/${mode === 'encrypt' ? 'encode' : 'decode'}

{
  "algorithm": "${current.id}",
  "input": "<your-data>"
}`;
    }
    $('apiCode').textContent = code;
  }

  /* ---------------------------- Output ------------------------------ */
  function clearOutput() {
    const box = $('outputBox');
    box.classList.remove('err', 'ok');
    $('outputText').innerHTML = '<span class="ws-output-ph">Output appears here after you run</span>';
    $('downloadLink').hidden = true;
  }
  function showOutput(text, ok) {
    const box = $('outputBox');
    box.classList.remove('err', 'ok');
    box.classList.add(ok ? 'ok' : 'err');
    $('outputText').textContent = text;
  }

  /* ----------------------------- Execute ---------------------------- */
  async function execute() {
    const btn = $('runBtn');
    if (inputTab === 'api') { showOutput('API mode shows the request to send — run it from your own client.', true); return; }
    try {
      btn.classList.add('busy');
      let dataBytes;
      if (inputTab === 'file') {
        if (!fileBytes) throw new Error('Choose a file first');
        dataBytes = fileBytes;
      } else {
        const txt = $('inputText').value;
        if (!txt) throw new Error('Enter some input first');
        dataBytes = enc.encode(txt);
      }

      const result = await run(dataBytes);

      // Symmetric decrypt returns raw bytes
      if (result instanceof Uint8Array) {
        if (inputTab === 'file') {
          offerDownload(result, (fileName || 'output').replace(/\.delock\.txt$/, '') || 'decrypted.bin');
          showOutput(`Decrypted ${result.length} bytes — download ready.`, true);
        } else {
          showOutput(dec.decode(result), true);
        }
        recordItem();
        return;
      }

      // Text/encoded string result
      if (inputTab === 'file' && (current.key || ['base64', 'hex'].includes(current.type))) {
        const blob = new Blob([result], { type: 'text/plain' });
        const dlName = (fileName || 'output') + '.delock.txt';
        offerDownloadBlob(blob, dlName);
      }
      showOutput(result, true);
      recordItem();
    } catch (e) {
      showOutput((mode === 'decrypt' ? 'Decryption failed — check your key, format and input. ' : '') + (e.message || e), false);
    } finally {
      btn.classList.remove('busy');
    }
  }

  function offerDownload(bytes, name) {
    offerDownloadBlob(new Blob([bytes], { type: 'application/octet-stream' }), name);
  }
  function offerDownloadBlob(blob, name) {
    const link = $('downloadLink');
    const url = URL.createObjectURL(blob);
    link.href = url; link.download = name; link.hidden = false;
    link.textContent = `Download ${name}`;
  }

  /* -------------------------- Key strength -------------------------- */
  function scoreKey(k) {
    if (!k) return { pct: 0, txt: '—' };
    let pool = 0;
    if (/[a-z]/.test(k)) pool += 26;
    if (/[A-Z]/.test(k)) pool += 26;
    if (/[0-9]/.test(k)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(k)) pool += 32;
    const bits = k.length * Math.log2(pool || 1);
    const pct = Math.max(6, Math.min(100, Math.round(bits / 128 * 100)));
    let txt = 'Weak';
    if (bits >= 96) txt = 'Excellent';
    else if (bits >= 72) txt = 'Strong';
    else if (bits >= 48) txt = 'Good';
    else if (bits >= 32) txt = 'Fair';
    return { pct, txt: `${txt} · ~${Math.round(bits)} bits` };
  }
  function updateStrength() {
    const { pct, txt } = scoreKey($('keyInput').value);
    $('strengthBar').style.width = pct + '%';
    $('strengthBar').style.background = pct < 33 ? '#ff5a3c' : pct < 66 ? '#ffb454' : 'var(--grad)';
    $('strengthTxt').textContent = txt;
  }

  /* ------------------------------ Toast ----------------------------- */
  let toastTimer;
  function toast(msg) {
    const el = $('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
  }

  /* --------------------------- Input helpers ------------------------ */
  function setInputTab(tab) {
    inputTab = tab;
    document.querySelectorAll('#inputTabs button').forEach((x) => x.classList.toggle('active', x.dataset.tab === tab));
    $('paneText').hidden = tab !== 'text';
    $('paneFile').hidden = tab !== 'file';
    $('paneApi').hidden = tab !== 'api';
  }
  function setFormat(f) {
    format = f;
    document.querySelectorAll('#formatToggle button').forEach((x) => x.classList.toggle('active', x.dataset.fmt === f));
    updateApiSnippet();
  }

  /* ===================== Vault (files & resources) ================== */
  const VKEY = 'delock.vault';
  let vault = [];
  let vaultFilter = 'all', vaultQuery = '';
  const KIND = {
    decrypt: { label: 'Unlocked', cls: 'decrypt' },
    decode:  { label: 'Decoded',  cls: 'decode' },
    encrypt: { label: 'Encrypted', cls: 'encrypt' },
    encode:  { label: 'Encoded',  cls: 'encode' },
    hash:    { label: 'Hash',     cls: 'hash' }
  };

  // sample "unlocked products" so the vault shows examples on first visit
  const SAMPLE_ITEMS = [
    { id: 'sample-web', ts: Date.now() - 3600e3, kind: 'decrypt', algo: 'AES-GCM', fmt: 'base64', source: 'text',
      title: 'Premium report · 2026 Threat Landscape',
      input: 'k3F9vR2bQ8w1Lp7m4nX…',
      output: 'https://reports.delock.app/2026-threat-landscape' },
    { id: 'sample-file', ts: Date.now() - 2 * 3600e3, kind: 'decrypt', algo: 'AES-CBC', fmt: 'base64', source: 'file',
      title: 'confidential-keys.pdf',
      input: 'confidential-keys.pdf',
      output: 'Decrypted 248 KB — download ready.' },
    { id: 'sample-text', ts: Date.now() - 5 * 3600e3, kind: 'decode', algo: 'Base64', fmt: 'base64', source: 'text',
      title: 'Unlocked note',
      input: 'VGhpcyBpcyBhIHNhbXBsZSB1bmxvY2tlZCBub3Rl',
      output: 'This is a sample unlocked note. Your decrypted text, files and links all appear here in the Vault.' }
  ];
  function loadVault() {
    try { vault = JSON.parse(localStorage.getItem(VKEY) || '[]'); } catch (e) { vault = []; }
    // seed example items once, so new visitors see what unlocked content looks like
    if (!vault.length && !localStorage.getItem('delock.vault.seeded')) {
      vault = SAMPLE_ITEMS.slice();
      saveVault();
      try { localStorage.setItem('delock.vault.seeded', '1'); } catch (e) { /* ignore */ }
    }
  }
  function saveVault() { try { localStorage.setItem(VKEY, JSON.stringify(vault.slice(0, 200))); } catch (e) { /* quota */ } }
  function kindOf() {
    if (current.type === 'hash' || current.type === 'md5') return 'hash';
    if (['base64', 'hex', 'url'].includes(current.type)) return mode === 'encrypt' ? 'encode' : 'decode';
    return mode === 'encrypt' ? 'encrypt' : 'decrypt';
  }
  function defaultTitle(e) {
    if (e.source === 'file') return e.input || 'File';
    const o = (e.output || '').trim().replace(/\s+/g, ' ');
    return o ? (o.length > 44 ? o.slice(0, 44) + '…' : o) : ((KIND[e.kind] || {}).label || 'Item');
  }
  function saveItem(e) {
    e.id = 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    e.ts = Date.now();
    e.title = defaultTitle(e);
    vault.unshift(e);
    vault = vault.slice(0, 200);
    saveVault();
    updateVaultCount();
  }
  function recordItem() {
    if (!autosave) return;   // honor the Me › Settings toggle
    saveItem({
      kind: kindOf(),
      algoId: current.id, algo: current.name, fmt: format,
      source: inputTab === 'file' ? 'file' : 'text',
      input: inputTab === 'file' ? (fileName || '(file)') : $('inputText').value,
      output: $('outputText').textContent
    });
  }
  function updateVaultCount() {
    const n = vault.length;
    $('vaultCount').textContent = n + (n === 1 ? ' item' : ' items');
    const top = $('vaultBadgeTop');
    top.textContent = n > 99 ? '99+' : n; top.hidden = n === 0;
    const tb = $('vaultBadgeTab');
    tb.textContent = n > 99 ? '99+' : n; tb.hidden = n === 0;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }
  function vaultFiltered() {
    const q = vaultQuery.toLowerCase();
    return vault.filter((e) => {
      const f = vaultFilter;
      const okF = f === 'all' ? true
        : f === 'file' ? e.source === 'file'
        : f === 'decrypt' ? (e.kind === 'decrypt' || e.kind === 'decode')
        : f === 'encrypt' ? (e.kind === 'encrypt' || e.kind === 'encode')
        : f === 'hash' ? e.kind === 'hash' : true;
      const okQ = !q || (e.title || '').toLowerCase().includes(q) ||
        (e.algo || '').toLowerCase().includes(q) || (e.output || '').toLowerCase().includes(q);
      return okF && okQ;
    });
  }
  const GLOBE_SVG = '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18" stroke="currentColor" stroke-width="1.7"/></svg>';
  const FILE_SVG = '<svg viewBox="0 0 24 24" fill="none"><path d="M7 3h7l5 5v13H7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.7"/></svg>';
  const isUrl = (s) => /^https?:\/\/[^\s]+$/i.test((s || '').trim());
  function hostOf(u) { try { return new URL(u.trim()).hostname; } catch (e) { return u; } }
  function thumbHtml(e) {
    if (e.source === 'file') {
      return `<div class="vault-thumb-file">${FILE_SVG}<div class="fname">${escapeHtml(e.input || 'File')}</div></div>`;
    }
    const out = e.output || '';
    if (isUrl(out)) {
      return `<div class="vault-thumb-web">${GLOBE_SVG}<div class="host">${escapeHtml(hostOf(out))}</div></div>`;
    }
    return `<div class="vault-thumb-text">${escapeHtml(out.slice(0, 280)) || '(empty)'}</div>`;
  }
  function renderVault() {
    const box = $('vaultList');
    const items = vaultFiltered();
    if (!items.length) {
      box.innerHTML = '<div class="vault-empty">' + (vault.length
        ? 'No items match your search or filter.'
        : 'Your vault is empty.<br>Encrypt, decrypt or encode something and it will be saved here.') + '</div>';
      return;
    }
    box.innerHTML = items.map((e) => {
      const k = KIND[e.kind] || { label: e.kind, cls: 'hash' };
      const t = new Date(e.ts).toLocaleString();
      return `<div class="vault-card" data-id="${e.id}">
        <div class="vault-thumb">
          <span class="vault-badge ${k.cls}">${k.label}</span>
          ${thumbHtml(e)}
        </div>
        <div class="vault-card-body">
          <div class="vault-card-title">${escapeHtml(e.title)}</div>
          <div class="vault-card-meta"><span class="vault-algo">${escapeHtml(e.algo)}</span><span class="vault-date">${t}</span></div>
          <div class="vault-card-actions">
            <button data-act="open">Open</button>
            <button data-act="copy">Copy</button>
            <button data-act="download">Download</button>
            <button data-act="rename">Rename</button>
            <button data-act="delete">Delete</button>
          </div>
        </div>
      </div>`;
    }).join('');
  }
  function clearVault() {
    if (!vault.length) return;
    if (!confirm('Clear all items from your vault? This cannot be undone.')) return;
    vault = []; saveVault(); updateVaultCount(); renderVault();
  }
  function sanitizeName(s) { return (s || 'delock').replace(/[^\w.-]+/g, '_').slice(0, 40); }
  function vaultAction(id, act) {
    const e = vault.find((x) => x.id === id);
    if (!e) return;
    if (act === 'copy') {
      navigator.clipboard.writeText(e.output || '').then(() => toast('Copied to clipboard'));
    } else if (act === 'download') {
      offerDownloadBlob(new Blob([e.output || ''], { type: 'text/plain' }), sanitizeName(e.title) + '.txt');
      $('downloadLink').click();
      toast('Downloading…');
    } else if (act === 'delete') {
      vault = vault.filter((x) => x.id !== id); saveVault(); updateVaultCount(); renderVault();
    } else if (act === 'rename') {
      const name = prompt('Rename item', e.title);
      if (name && name.trim()) { e.title = name.trim().slice(0, 80); saveVault(); renderVault(); }
    } else if (act === 'open') {
      if (e.source !== 'text') { toast('File items — use Download'); return; }
      selectAlgo(e.algoId);
      setFormat(e.fmt || 'base64');
      setInputTab('text');
      $('inputText').value = e.input || '';
      const view = (e.kind === 'encrypt' || e.kind === 'encode') ? 'encrypt'
        : (e.kind === 'decrypt' || e.kind === 'decode') ? 'decrypt' : 'encrypt';
      setView(view);
      showOutput(e.output || '', true);
      toast('Loaded from vault');
    }
  }

  /* ===================== Me / account / membership ================== */
  const AKEY = 'delock.account';
  const PLAN_INFO = {
    basic:   { name: 'Basic',   fee: '$1 / mo',    monthly: 10 },
    premium: { name: 'Premium', fee: '$19.9 / mo', monthly: 1000 }
  };
  const CREDIT_RATE = 0.10;        // $ per credit (10 credits = $1)
  const PREMIUM_OFF = 0.9;         // Premium: 10% off
  const PACKS = [100, 500, 1000];
  let account = { id: '', plan: 'basic', credits: 10, linked: false, email: '' };
  let autosave = true;

  function genId() { return 'DLK-' + Math.random().toString(36).slice(2, 8).toUpperCase(); }
  function loadAccount() {
    try { account = Object.assign(account, JSON.parse(localStorage.getItem(AKEY) || '{}')); } catch (e) { /* ignore */ }
    if (!account.id) { account.id = genId(); saveAccount(); }
    autosave = localStorage.getItem('delock.autosave') !== '0';
  }
  function saveAccount() { try { localStorage.setItem(AKEY, JSON.stringify(account)); } catch (e) { /* ignore */ } }
  function creditPrice(n) { return n * CREDIT_RATE * (account.plan === 'premium' ? PREMIUM_OFF : 1); }

  function renderMe() {
    const info = PLAN_INFO[account.plan] || PLAN_INFO.basic;
    const linked = !!account.linked;
    $('meName').textContent = linked ? (account.email || 'Google account') : 'Guest account';
    $('meSubline').textContent = info.name + ' plan · ' + account.id;
    $('meAvatar').textContent = linked && account.email ? account.email[0].toUpperCase() : 'D';
    $('meGoogle').hidden = linked;
    $('meAccountNote').hidden = linked;
    $('meLinked').hidden = !linked;
    $('meGoogleChip').hidden = !linked;
    $('meCredits').textContent = (account.credits || 0).toLocaleString();
    const per10 = (10 * CREDIT_RATE * (account.plan === 'premium' ? PREMIUM_OFF : 1)).toFixed(2);
    $('meRate').innerHTML = account.plan === 'premium'
      ? `10 credits = <b style="color:#fff">$${per10}</b> · Premium 10% off`
      : `10 credits = <b style="color:#fff">$${per10}</b>`;

    $('mePlans').innerHTML = ['basic', 'premium'].map((id) => {
      const p = PLAN_INFO[id];
      const isCur = account.plan === id;
      let btn;
      if (isCur) btn = '<button class="me-plan-btn current" type="button" disabled>Current plan</button>';
      else if (id === 'premium') btn = '<button class="me-plan-btn primary" type="button" data-plan="premium">Upgrade</button>';
      else btn = '<button class="me-plan-btn" type="button" data-plan="basic">Switch</button>';
      return `<div class="me-plan ${isCur ? 'active' : ''}">
        <div class="me-plan-top"><b>${p.name}</b><span class="me-plan-fee">${p.fee}</span></div>
        <div class="me-plan-sub">${p.monthly.toLocaleString()} credits / month</div>
        ${btn}
      </div>`;
    }).join('');

    $('mePacks').innerHTML = PACKS.map((n) => {
      const price = creditPrice(n).toFixed(2);
      const was = account.plan === 'premium' ? `<span class="me-pack-was">$${(n * CREDIT_RATE).toFixed(2)}</span>` : '';
      return `<button class="me-pack" type="button" data-credits="${n}"><b>${n}</b><span>${was}$${price}</span></button>`;
    }).join('');
  }

  function buyCredits(n) {
    const price = creditPrice(n).toFixed(2);
    if (!confirm('Buy ' + n + ' credits for $' + price + '?')) return;
    account.credits = (account.credits || 0) + n;
    saveAccount(); renderMe();
    toast('Added ' + n + ' credits');
  }
  function openSupport() {
    const subject = encodeURIComponent('Delock support request');
    const body = encodeURIComponent(
      'Account ID: ' + account.id + '\n' +
      (account.linked && account.email ? 'Email: ' + account.email + '\n' : 'Account: temporary (not signed in)\n') +
      'Plan: ' + ((PLAN_INFO[account.plan] || {}).name || 'Basic') + '\n' +
      'Credits: ' + (account.credits || 0) + '\n\n' +
      'Please describe your issue below:\n');
    window.location.href = 'mailto:support@delock.app?subject=' + subject + '&body=' + body;
  }
  function linkGoogle() {
    const email = prompt('Sign in with Google\n\nEnter your Google email to link this account:', 'you@gmail.com');
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) return;
    account.linked = true; account.email = email.trim();
    saveAccount(); renderMe(); toast('Signed in with Google');
  }
  function unlinkGoogle() {
    if (!confirm('Disconnect your Google account? Your temporary account, plan and credits stay on this device.')) return;
    account.linked = false; account.email = '';
    saveAccount(); renderMe(); toast('Google disconnected');
  }

  /* ----------------------------- Wiring ----------------------------- */
  function init() {
    renderLists();
    loadVault();
    updateVaultCount();
    loadAccount();
    renderMe();

    // mobile bottom tab bar
    gridEl = document.querySelector('.ws-grid');
    setView('encrypt');
    document.querySelectorAll('#wsTabbar button[data-view]').forEach((b) =>
      b.addEventListener('click', () => { if (!b.classList.contains('disabled')) setView(b.dataset.view); }));

    // mobile algorithm selector (collapsible)
    $('algosToggle').addEventListener('click', () => $('wsAlgos').classList.toggle('open'));

    // me / account: entry points + controls
    $('meBtn').addEventListener('click', () => setView('me'));
    $('meClose').addEventListener('click', () => setView('encrypt'));
    $('meLogout').addEventListener('click', () => { if (confirm('Log out of Delock?')) location.href = 'index.html'; });
    $('meClearVault').addEventListener('click', () => { clearVault(); toast('Vault cleared'); });
    $('meSupport').addEventListener('click', openSupport);
    $('meGoogle').addEventListener('click', linkGoogle);
    $('meUnlink').addEventListener('click', unlinkGoogle);
    $('autosaveToggle').checked = autosave;
    $('autosaveToggle').addEventListener('change', (e) => {
      autosave = e.target.checked;
      try { localStorage.setItem('delock.autosave', autosave ? '1' : '0'); } catch (err) { /* ignore */ }
    });
    $('mePlans').addEventListener('click', (e) => {
      const b = e.target.closest('button[data-plan]');
      if (b) location.href = 'pricing.html?plan=' + b.dataset.plan;
    });
    $('mePacks').addEventListener('click', (e) => {
      const b = e.target.closest('button[data-credits]');
      if (b) buyCredits(+b.dataset.credits);
    });

    // vault: entry points (desktop button) + controls; the mobile Vault tab
    // is a data-view button handled by the tab handler above
    $('vaultBtn').addEventListener('click', () => setView('vault'));
    $('vaultClose').addEventListener('click', () => setView('encrypt'));
    $('vaultClear').addEventListener('click', clearVault);
    $('vaultSearch').addEventListener('input', (e) => { vaultQuery = e.target.value; renderVault(); });
    document.querySelectorAll('#vaultFilters button').forEach((b) => {
      b.addEventListener('click', () => {
        vaultFilter = b.dataset.filter;
        document.querySelectorAll('#vaultFilters button').forEach((x) => x.classList.toggle('active', x === b));
        renderVault();
      });
    });
    $('vaultList').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-act]');
      const card = e.target.closest('.vault-card');
      if (btn && card) vaultAction(card.dataset.id, btn.dataset.act);
    });

    $('modeEncrypt').addEventListener('click', () => setMode('encrypt'));
    $('modeDecrypt').addEventListener('click', () => { if (!$('modeDecrypt').disabled) setMode('decrypt'); });

    // input tabs
    document.querySelectorAll('#inputTabs button').forEach((b) => {
      b.addEventListener('click', () => { setInputTab(b.dataset.tab); clearOutput(); });
    });

    // format toggle
    document.querySelectorAll('#formatToggle button').forEach((b) => {
      b.addEventListener('click', () => { setFormat(b.dataset.fmt); clearOutput(); });
    });

    // explain accordion
    $('explainBtn').addEventListener('click', () => {
      const open = $('explainBtn').classList.toggle('open');
      $('explainBody').hidden = !open;
    });

    // key strength
    $('keyInput').addEventListener('input', updateStrength);

    // file input
    const fileInput = $('inputFile'), drop = $('fileDrop');
    fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
    drop.addEventListener('drop', (e) => { if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); });

    // run + copy
    $('runBtn').addEventListener('click', execute);
    $('copyBtn').addEventListener('click', () => {
      const txt = $('outputText').textContent;
      if (!txt || txt.startsWith('Output appears')) return;
      navigator.clipboard.writeText(txt).then(() => toast('Copied to clipboard'));
    });

    // keyboard: Cmd/Ctrl+Enter to run
    $('inputText').addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') execute();
    });

    selectAlgo(current.id);
    updateStrength();
  }

  function handleFile(file) {
    if (!file) return;
    fileName = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      fileBytes = new Uint8Array(reader.result);
      const drop = $('fileDrop');
      drop.classList.add('has-file');
      $('fileLabel').textContent = `${file.name} · ${formatBytes(file.size)}`;
    };
    reader.readAsArrayBuffer(file);
  }
  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
