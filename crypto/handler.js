'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { execFileSync } = require('child_process');

// ─── Constants ────────────────────────────────────────────────────────────────
const MAGIC         = Buffer.from('VLTX');
const VERSION       = 0x01;
const SALT_LEN      = 32;
const IV_LEN        = 12;
const TAG_LEN       = 16;
const PBKDF2_ITER   = 210_000;
const PBKDF2_DIGEST = 'sha256';

const O = { magic:0, ver:4, salt:5, iv:37, tag:49, data:65 };

const ALGO = {
  aes128: { alg: 'aes-128-gcm', keyLen: 16 },
  aes256: { alg: 'aes-256-gcm', keyLen: 32 },
};

// ─── KDF ──────────────────────────────────────────────────────────────────────
function deriveKey(password, salt, keyLen) {
  return crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, PBKDF2_ITER, keyLen, PBKDF2_DIGEST);
}

// ─── AES-GCM ──────────────────────────────────────────────────────────────────
function aesEncrypt(plaintext, password, mode, onProgress) {
  const { alg, keyLen } = ALGO[mode];
  onProgress && onProgress(10);
  const salt   = crypto.randomBytes(SALT_LEN);
  const iv     = crypto.randomBytes(IV_LEN);
  const key    = deriveKey(password, salt, keyLen);
  onProgress && onProgress(40);
  const cipher = crypto.createCipheriv(alg, key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();
  key.fill(0);
  onProgress && onProgress(80);

  const header = Buffer.allocUnsafe(O.data);
  MAGIC.copy(header, O.magic); header[O.ver] = VERSION;
  salt.copy(header, O.salt); iv.copy(header, O.iv); tag.copy(header, O.tag);
  onProgress && onProgress(95);
  return Buffer.concat([header, enc]);
}

function aesDecrypt(buf, password, mode, onProgress) {
  const { alg, keyLen } = ALGO[mode];
  if (buf.length < O.data) throw new Error('File too short or corrupted');
  if (!buf.slice(O.magic, O.ver).equals(MAGIC)) throw new Error('Not a valid Mola Vault encrypted file');
  if (buf[O.ver] !== VERSION) throw new Error(`Unsupported file version v${buf[O.ver]}`);
  onProgress && onProgress(15);

  const salt = buf.slice(O.salt, O.iv);
  const iv   = buf.slice(O.iv,   O.tag);
  const tag  = buf.slice(O.tag,  O.data);
  const ct   = buf.slice(O.data);
  if (ct.length === 0) throw new Error('Empty encrypted data');

  const key = deriveKey(password, salt, keyLen);
  onProgress && onProgress(60);
  try {
    const d = crypto.createDecipheriv(alg, key, iv);
    d.setAuthTag(tag);
    const plain = Buffer.concat([d.update(ct), d.final()]);
    key.fill(0);
    onProgress && onProgress(95);
    return plain;
  } catch {
    key.fill(0);
    throw new Error('Wrong password or file tampered (GCM auth failed)');
  }
}

// ─── Safe output path ─────────────────────────────────────────────────────────
function safeOut(dir, name) {
  let p = path.join(dir, name), n = 1;
  while (fs.existsSync(p)) {
    const ext  = path.extname(name);
    const base = path.basename(name, ext);
    p = path.join(dir, `${base} (${n++})${ext}`);
  }
  return p;
}

// ─── ZIP ──────────────────────────────────────────────────────────────────────
function zipEncrypt(filePath, outputDir, password, onProgress) {
  const outPath = safeOut(outputDir, path.basename(filePath) + '.zip');
  onProgress && onProgress(20);
  try {
    execFileSync('zip', ['-j', '-P', password, outPath, filePath], { stdio: 'pipe', timeout: 120_000 });
  } catch (e) {
    if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
    throw new Error('ZIP encryption failed: ' + (e.stderr?.toString() || e.message).slice(0, 200));
  }
  onProgress && onProgress(95);
  return outPath;
}

function zipDecrypt(filePath, outputDir, password, onProgress) {
  if (!filePath.toLowerCase().endsWith('.zip')) throw new Error('File is not a .zip');
  onProgress && onProgress(20);
  try {
    execFileSync('unzip', ['-o', '-P', password, filePath, '-d', outputDir], { stdio: 'pipe', timeout: 120_000 });
  } catch (e) {
    const msg = ((e.stderr?.toString() || '') + (e.stdout?.toString() || '')).toLowerCase();
    if (msg.includes('incorrect password') || msg.includes('bad password')) throw new Error('Wrong password');
    throw new Error('ZIP decryption failed: ' + msg.slice(0, 200));
  }
  onProgress && onProgress(95);
  return outputDir;
}

// ─── Auto-detect mode ─────────────────────────────────────────────────────────
function detectMode(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith('.aes256')) return 'aes256';
  if (name.endsWith('.aes128')) return 'aes128';
  if (name.endsWith('.zip'))    return 'zip';
  // Peek magic bytes
  try {
    const fd  = fs.openSync(filePath, 'r');
    const buf = Buffer.allocUnsafe(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    if (buf.equals(MAGIC)) return 'aes256';
  } catch {}
  throw new Error('Cannot detect encryption type. Rename to .aes256, .aes128, or .zip');
}

// ─── Public API ───────────────────────────────────────────────────────────────
exports.encrypt = async function ({ filePath, outputDir, mode, password, onProgress }) {
  if (!fs.existsSync(filePath))  throw new Error(`File not found: ${path.basename(filePath)}`);
  if (!fs.existsSync(outputDir)) throw new Error('Output directory not found');
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('Target is not a file');
  if (stat.size > 2 * 1024 * 1024 * 1024) throw new Error('File exceeds 2 GB limit');

  if (mode === 'zip') return zipEncrypt(filePath, outputDir, password, onProgress);

  const plain   = fs.readFileSync(filePath);
  onProgress && onProgress(5);
  const enc     = aesEncrypt(plain, password, mode, onProgress);
  const outName = path.basename(filePath) + (mode === 'aes128' ? '.aes128' : '.aes256');
  const outPath = safeOut(outputDir, outName);
  fs.writeFileSync(outPath, enc, { mode: 0o600 });
  return outPath;
};

exports.decryptAuto = async function ({ filePath, outputDir, password, forceMode, onProgress }) {
  if (!fs.existsSync(filePath))  throw new Error(`File not found: ${path.basename(filePath)}`);
  if (!fs.existsSync(outputDir)) throw new Error('Output directory not found');

  const mode = forceMode || detectMode(filePath);
  if (mode === 'zip') return zipDecrypt(filePath, outputDir, password, onProgress);

  const buf   = fs.readFileSync(filePath);
  onProgress && onProgress(5);
  const plain = aesDecrypt(buf, password, mode, onProgress);

  const ext     = mode === 'aes128' ? '.aes128' : '.aes256';
  let outName   = path.basename(filePath);
  if (outName.toLowerCase().endsWith(ext)) outName = outName.slice(0, -ext.length);

  const outPath = safeOut(outputDir, outName);
  fs.writeFileSync(outPath, plain, { mode: 0o600 });
  return outPath;
};

exports.decrypt = exports.decryptAuto;
