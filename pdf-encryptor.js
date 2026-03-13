/**
 * pdf-encryptor.js
 * Pure Node.js PDF encrypt + decrypt. No binaries, no Python.
 * Works on Windows. Requires: pdfkit, pdf-lib
 *
 * npm install pdfkit pdf-lib
 */

const crypto = require('crypto');
const { PDFDocument } = require('pdf-lib');
const PDFKitDoc = require('pdfkit');

// ── RC4 (pure JS, symmetric — same fn encrypts and decrypts) ─────────────────
function rc4(keyBuf, dataBuf) {
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + keyBuf[i % keyBuf.length]) & 0xff;
        const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    const out = Buffer.alloc(dataBuf.length);
    let a = 0, b = 0;
    for (let i = 0; i < dataBuf.length; i++) {
        a = (a + 1) & 0xff; b = (b + S[a]) & 0xff;
        const tmp = S[a]; S[a] = S[b]; S[b] = tmp;
        out[i] = dataBuf[i] ^ S[(S[a] + S[b]) & 0xff];
    }
    return out;
}

const PAD32 = Buffer.from('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A', 'hex');

function padPass(pwd) {
    const src = Buffer.from(pwd || '', 'latin1');
    const out = Buffer.alloc(32);
    const n = Math.min(src.length, 32);
    src.copy(out, 0, 0, n);
    PAD32.copy(out, n, 0, 32 - n);
    return out;
}

// Reconstruct encryption key from PDF /Encrypt values (PDF spec Algorithm 2)
function computeEncKey(password, O, perms, fileId, keyLen, revision) {
    const md5 = crypto.createHash('md5');
    md5.update(padPass(password));
    md5.update(O);
    const p = Buffer.alloc(4); p.writeInt32LE(perms, 0);
    md5.update(p);
    md5.update(fileId);
    let key = md5.digest();
    if (revision >= 3) {
        for (let i = 0; i < 50; i++)
            key = crypto.createHash('md5').update(key.slice(0, keyLen)).digest();
    }
    return key.slice(0, keyLen);
}

// Verify password against stored /U entry
function verifyPassword(password, O, perms, fileId, U, keyLen, revision) {
    const encKey = computeEncKey(password, O, perms, fileId, keyLen, revision);
    if (revision === 2) {
        return rc4(encKey, PAD32).slice(0, 16).equals(U.slice(0, 16));
    } else {
        const hash = crypto.createHash('md5').update(PAD32).update(fileId).digest();
        let result = rc4(encKey, hash);
        for (let i = 1; i <= 19; i++)
            result = rc4(Buffer.from(encKey.map(b => b ^ i)), result);
        return result.slice(0, 16).equals(U.slice(0, 16));
    }
}

// Per-object key derivation
function getObjKey(encKey, objNum, gen) {
    const suffix = Buffer.alloc(5);
    suffix[0] = objNum & 0xff; suffix[1] = (objNum >> 8) & 0xff; suffix[2] = (objNum >> 16) & 0xff;
    suffix[3] = gen & 0xff;    suffix[4] = (gen >> 8) & 0xff;
    return crypto.createHash('md5')
        .update(Buffer.concat([encKey, suffix]))
        .digest()
        .slice(0, Math.min(encKey.length + 5, 16));
}

// ── ENCRYPT ──────────────────────────────────────────────────────────────────
async function encryptPDFBuffer(inputBuf, password, ownerPassword) {
    ownerPassword = ownerPassword || password;

    if (!inputBuf.slice(0, 5).toString().startsWith('%PDF'))
        throw new Error('Not a valid PDF file');

    // Normalize with pdf-lib
    const pdfDoc = await PDFDocument.load(inputBuf, { ignoreEncryption: true });
    const normalized = Buffer.from(await pdfDoc.save({ useObjectStreams: false }));
    const pdfStr = normalized.toString('latin1');

    // ONE pdfkit instance — same instance for encryptFn AND /Encrypt dict output
    const pkDoc = new PDFKitDoc({
        userPassword: password,
        ownerPassword: ownerPassword,
        compress: false,
        autoFirstPage: false
    });
    const security = pkDoc._security;

    // Encrypt all streams
    let result = '';
    let pos = 0;
    const objRegex = /(\d+) (\d+) obj\b/g;
    let m;
    while ((m = objRegex.exec(pdfStr)) !== null) {
        const objNum = parseInt(m[1]), gen = parseInt(m[2]);
        const objStart = m.index;
        const endObjIdx = pdfStr.indexOf('endobj', objStart + m[0].length);
        if (endObjIdx === -1) continue;
        const objBody = pdfStr.slice(objStart, endObjIdx + 6);
        const streamMarker = objBody.match(/\bstream\r?\n/);
        if (!streamMarker) continue;
        const streamStart  = objStart + streamMarker.index + streamMarker[0].length;
        const endStreamIdx = pdfStr.indexOf('\nendstream', streamStart);
        if (endStreamIdx === -1) continue;

        result += pdfStr.slice(pos, streamStart);
        const rawStream = Buffer.from(pdfStr.slice(streamStart, endStreamIdx), 'latin1');
        result += security.getEncryptFn(objNum, gen)(rawStream).toString('latin1');
        pos = endStreamIdx;
    }
    result += pdfStr.slice(pos, pdfStr.lastIndexOf('startxref')).trimEnd();

    // Collect pdfkit output to extract /Encrypt dict and /ID
    const pkChunks = [];
    await new Promise(resolve => { pkDoc.on('data', c => pkChunks.push(c)); pkDoc.on('end', resolve); pkDoc.end(); });
    const pkStr = Buffer.concat(pkChunks).toString('latin1');

    const encDictMatch = pkStr.match(/\d+ 0 obj\s*\n<<\s*\n\/Filter \/Standard[\s\S]+?endobj/);
    const idMatch      = pkStr.match(/\/ID \[(<[a-f0-9]+> <[a-f0-9]+>)\]/i);
    if (!encDictMatch || !idMatch) throw new Error('pdfkit did not produce /Encrypt dict');

    const encObjNum    = parseInt(pdfStr.match(/\/Size (\d+)/)[1]);
    const encDictStr   = encDictMatch[0].replace(/^\d+ 0 obj/, `${encObjNum} 0 obj`);
    const encObjOffset = Buffer.byteLength(result, 'latin1') + 1;
    result += '\n' + encDictStr + '\n';

    const xrefOffset = Buffer.byteLength(result, 'latin1');
    result += `xref\n${encObjNum} 1\n${String(encObjOffset).padStart(10, '0')} 00000 n \n`;

    const rootMatch = pdfStr.match(/\/Root (\d+ \d+ R)/);
    const infoMatch = pdfStr.match(/\/Info (\d+ \d+ R)/);
    const prevSxref = pdfStr.match(/startxref\s+(\d+)\s+%%EOF/);

    result += [
        `trailer`, `<<`,
        `/Size ${encObjNum + 1}`,
        prevSxref ? `/Prev ${prevSxref[1]}` : '',
        rootMatch  ? `/Root ${rootMatch[1]}` : '',
        infoMatch  ? `/Info ${infoMatch[1]}` : '',
        `/Encrypt ${encObjNum} 0 R`,
        `/ID [${idMatch[1]}]`,
        `>>`, `startxref`, `${xrefOffset}`, `%%EOF`, ``
    ].filter(Boolean).join('\n');

    return Buffer.from(result, 'latin1');
}

// ── DECRYPT ──────────────────────────────────────────────────────────────────
async function decryptPDFBuffer(encryptedBuf, password) {
    const pdfStr = encryptedBuf.toString('latin1');

    const encDictStart = pdfStr.indexOf('/Filter /Standard');
    if (encDictStart === -1) return encryptedBuf; // not encrypted

    const encSection = pdfStr.slice(encDictStart, encDictStart + 500);

    const oMatch  = encSection.match(/\/O <([A-F0-9]+)>/i);
    const uMatch  = encSection.match(/\/U <([A-F0-9]+)>/i);
    const pMatch  = encSection.match(/\/P (-?\d+)/);
    const idMatch = pdfStr.match(/\/ID\s*\[?\s*<([a-f0-9]+)>/i);
    const vVal    = parseInt((encSection.match(/\/V (\d+)/) || [])[1] || '1');
    const rVal    = parseInt((encSection.match(/\/R (\d+)/) || [])[1] || '2');
    const lenMatch = encSection.match(/\/Length (\d+)/);
    const keyLen  = lenMatch ? parseInt(lenMatch[1]) / 8 : (vVal === 1 ? 5 : 16);

    if (!oMatch || !uMatch || !pMatch || !idMatch)
        throw new Error('Could not parse encryption parameters from PDF');

    const O      = Buffer.from(oMatch[1], 'hex');
    const U      = Buffer.from(uMatch[1], 'hex');
    const perms  = parseInt(pMatch[1]);
    const fileId = Buffer.from(idMatch[1], 'hex');

    if (!verifyPassword(password, O, perms, fileId, U, keyLen, rVal))
        throw new Error('Incorrect password');

    const encKey = computeEncKey(password, O, perms, fileId, keyLen, rVal);
    console.log('[decrypt] ✅ Password verified');

    // Decrypt all streams (RC4 is symmetric)
    let result = '';
    let pos = 0;
    const objRegex = /(\d+) (\d+) obj\b/g;
    let m;
    while ((m = objRegex.exec(pdfStr)) !== null) {
        const objNum = parseInt(m[1]), gen = parseInt(m[2]);
        const objStart = m.index;
        const endObjIdx = pdfStr.indexOf('endobj', objStart + m[0].length);
        if (endObjIdx === -1) continue;
        const objBody = pdfStr.slice(objStart, endObjIdx + 6);
        const streamMarker = objBody.match(/\bstream\r?\n/);
        if (!streamMarker) continue;
        const streamStart  = objStart + streamMarker.index + streamMarker[0].length;
        const endStreamIdx = pdfStr.indexOf('\nendstream', streamStart);
        if (endStreamIdx === -1) continue;

        result += pdfStr.slice(pos, streamStart);
        const encStream = Buffer.from(pdfStr.slice(streamStart, endStreamIdx), 'latin1');
        result += rc4(getObjKey(encKey, objNum, gen), encStream).toString('latin1');
        pos = endStreamIdx;
    }

    // Append rest, strip /Encrypt reference
    let rest = pdfStr.slice(pos);
    rest = rest.replace(/\/Encrypt \d+ \d+ R\s*\n?/g, '');
    result += rest;

    return Buffer.from(result, 'latin1');
}

// ── CHECK ─────────────────────────────────────────────────────────────────────
function isPDFEncrypted(buf) {
    const s = buf.toString('latin1', 0, Math.min(buf.length, 50000));
    return s.includes('/Filter /Standard') || /\/Encrypt[\s\n\/\[<]/.test(s);
}

module.exports = { encryptPDFBuffer, decryptPDFBuffer, isPDFEncrypted };