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

    updateRunLabel();
    updateExplain();
    updateApiSnippet();
    clearOutput();
    updateTabState();
  }

  /* mobile bottom-tab view switching (Encrypt / Decrypt / More) */
  const VIEW_TITLES = { encrypt: 'Encrypt', decrypt: 'Decrypt', more: 'More' };
  function setView(v) {
    if (!gridEl) return;
    if (v === 'decrypt' && !current.reversible) v = 'encrypt';   // one-way algos can't decrypt
    gridEl.dataset.view = v;
    document.querySelectorAll('#wsTabbar button').forEach((b) =>
      b.classList.toggle('active', b.dataset.view === v));
    const title = $('viewTitle');
    if (title) title.textContent = VIEW_TITLES[v] || 'Encrypt';
    if (v === 'encrypt') setMode('encrypt');
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
        return;
      }

      // Text/encoded string result
      if (inputTab === 'file' && (current.key || ['base64', 'hex'].includes(current.type))) {
        const blob = new Blob([result], { type: 'text/plain' });
        const dlName = (fileName || 'output') + '.delock.txt';
        offerDownloadBlob(blob, dlName);
      }
      showOutput(result, true);
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

  /* ----------------------------- Wiring ----------------------------- */
  function init() {
    renderLists();

    // mobile bottom tab bar
    gridEl = document.querySelector('.ws-grid');
    setView('encrypt');
    document.querySelectorAll('#wsTabbar button').forEach((b) =>
      b.addEventListener('click', () => { if (!b.classList.contains('disabled')) setView(b.dataset.view); }));

    $('modeEncrypt').addEventListener('click', () => setMode('encrypt'));
    $('modeDecrypt').addEventListener('click', () => { if (!$('modeDecrypt').disabled) setMode('decrypt'); });

    // input tabs
    document.querySelectorAll('#inputTabs button').forEach((b) => {
      b.addEventListener('click', () => {
        inputTab = b.dataset.tab;
        document.querySelectorAll('#inputTabs button').forEach((x) => x.classList.toggle('active', x === b));
        $('paneText').hidden = inputTab !== 'text';
        $('paneFile').hidden = inputTab !== 'file';
        $('paneApi').hidden = inputTab !== 'api';
        clearOutput();
      });
    });

    // format toggle
    document.querySelectorAll('#formatToggle button').forEach((b) => {
      b.addEventListener('click', () => {
        format = b.dataset.fmt;
        document.querySelectorAll('#formatToggle button').forEach((x) => x.classList.toggle('active', x === b));
        updateApiSnippet();
        clearOutput();
      });
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
