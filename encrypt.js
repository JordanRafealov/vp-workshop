#!/usr/bin/env node
/**
 * Encrypts the VP Workshop HTML using AES-256-GCM with PBKDF2 key derivation.
 * The output is a self-contained HTML file with a password prompt that decrypts
 * the content client-side. No hash stored, no content visible without the password.
 *
 * Usage: node encrypt.js <input.html> <password> <output.html>
 */

const fs = require('fs');
const crypto = require('crypto');

const [,, inputFile, password, outputFile] = process.argv;

if (!inputFile || !password || !outputFile) {
  console.error('Usage: node encrypt.js <input.html> <password> <output.html>');
  process.exit(1);
}

const html = fs.readFileSync(inputFile, 'utf8');

// Generate random salt and IV
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);

// Derive key using PBKDF2 (100,000 iterations, SHA-256)
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

// Encrypt with AES-256-GCM
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(html, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);
const authTag = cipher.getAuthTag();

// Combine: salt (16) + iv (12) + authTag (16) + ciphertext
const payload = Buffer.concat([salt, iv, authTag, encrypted]);
const payloadBase64 = payload.toString('base64');

// Build the decryption HTML page
const decryptorHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Value Proposition Workshop</title>
<style>
  :root {
    --bg-page: #0a0a12; --bg-card: #12121c; --bg-input: #181824;
    --border: #222236; --text-primary: #e6e6f0; --text-muted: #5c5c76;
    --accent: #7c3aed; --accent-hover: #9b5de5; --danger: #ef4444;
    --radius: 10px; --radius-sm: 8px;
    --banner-grad: linear-gradient(135deg, #6d28d9 0%, #a855f7 50%, #7c3aed 100%);
    --font: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
  }
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: var(--font); background: var(--bg-page); color: var(--text-primary);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .pw-box {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 40px 36px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.25); text-align: center;
    max-width: 380px; width: 90%;
  }
  .pw-lock-icon { font-size: 32px; margin-bottom: 12px; opacity: 0.6; }
  .pw-box h2 {
    font-size: 18px; font-weight: 700; margin-bottom: 4px;
    background: var(--banner-grad); -webkit-background-clip: text;
    -webkit-text-fill-color: transparent; background-clip: text;
  }
  .pw-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 24px; }
  .pw-box input {
    width: 100%; padding: 12px 16px; font-size: 15px;
    background: var(--bg-input); border: 1px solid var(--border);
    border-radius: var(--radius-sm); color: var(--text-primary);
    font-family: var(--font); text-align: center; letter-spacing: 1px;
    transition: border-color 0.2s;
  }
  .pw-box input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(124,58,237,0.08); }
  .pw-box input.pw-error { border-color: var(--danger); animation: pwShake 0.4s ease; }
  @keyframes pwShake {
    0%,100%{transform:translateX(0)} 20%{transform:translateX(-8px)}
    40%{transform:translateX(8px)} 60%{transform:translateX(-4px)} 80%{transform:translateX(4px)}
  }
  .pw-box button {
    margin-top: 16px; width: 100%; padding: 12px;
    background: var(--accent); color: #fff; border: none;
    border-radius: var(--radius-sm); font-size: 14px; font-weight: 600;
    cursor: pointer; transition: background 0.2s; font-family: var(--font);
  }
  .pw-box button:hover { background: var(--accent-hover); }
  .pw-box button:disabled { opacity: 0.5; cursor: not-allowed; }
  .pw-hint { font-size: 11px; color: var(--danger); margin-top: 12px; min-height: 16px; }
  .pw-security {
    font-size: 10px; color: var(--text-muted); margin-top: 16px;
    opacity: 0.5; border-top: 1px solid var(--border); padding-top: 12px;
  }
</style>
</head>
<body>
<div class="pw-box" id="pwBox">
  <div class="pw-lock-icon">&#128274;</div>
  <h2>Value Proposition Workshop</h2>
  <div class="pw-sub">Enter password to access</div>
  <form id="pwForm">
    <input type="password" id="pwInput" placeholder="Password" autocomplete="off" autofocus>
    <button type="submit" id="pwBtn">Unlock</button>
  </form>
  <div class="pw-hint" id="pwHint"></div>
  <div class="pw-security">AES-256-GCM encrypted</div>
</div>

<script>
const ENCRYPTED_PAYLOAD = "${payloadBase64}";

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function decrypt(password) {
  try {
    const raw = Uint8Array.from(atob(ENCRYPTED_PAYLOAD), c => c.charCodeAt(0));
    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const authTag = raw.slice(28, 44);
    const ciphertext = raw.slice(44);

    // Combine ciphertext + authTag for WebCrypto (it expects them concatenated)
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      combined
    );

    return new TextDecoder().decode(decrypted);
  } catch (e) {
    return null;
  }
}

document.getElementById('pwForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('pwInput');
  const btn = document.getElementById('pwBtn');
  const hint = document.getElementById('pwHint');

  btn.disabled = true;
  btn.textContent = 'Decrypting...';
  hint.textContent = '';

  // Small delay to let UI update
  await new Promise(r => setTimeout(r, 50));

  const result = await decrypt(input.value);

  if (result) {
    // Store for session persistence
    sessionStorage.setItem('vp_pw', input.value);
    // Replace entire page with decrypted content
    document.open();
    document.write(result);
    document.close();
  } else {
    btn.disabled = false;
    btn.textContent = 'Unlock';
    input.classList.add('pw-error');
    hint.textContent = 'Incorrect password';
    setTimeout(() => input.classList.remove('pw-error'), 500);
    input.value = '';
    input.focus();
  }
});

// Auto-unlock if password is in session storage
(async () => {
  const savedPw = sessionStorage.getItem('vp_pw');
  if (savedPw) {
    const result = await decrypt(savedPw);
    if (result) {
      document.open();
      document.write(result);
      document.close();
    } else {
      sessionStorage.removeItem('vp_pw');
    }
  }
})();
</script>
</body>
</html>`;

fs.writeFileSync(outputFile, decryptorHtml, 'utf8');

const sizeKB = (Buffer.byteLength(decryptorHtml) / 1024).toFixed(0);
console.log(`Encrypted successfully!`);
console.log(`  Input:  ${inputFile} (${(fs.statSync(inputFile).size / 1024).toFixed(0)} KB)`);
console.log(`  Output: ${outputFile} (${sizeKB} KB)`);
console.log(`  Cipher: AES-256-GCM, PBKDF2 100K iterations`);
console.log(`  Salt:   ${salt.toString('hex')}`);
console.log(`  IV:     ${iv.toString('hex')}`);
