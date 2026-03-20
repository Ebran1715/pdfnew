const crypto = require('crypto');
const { PDFDocument } = require('pdf-lib');
const PDFKitDoc = require('pdfkit');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ── RC4 ──────────────────────────────────────────────────────────────────────
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

function getObjKey(encKey, objNum, gen) {
    const suffix = Buffer.alloc(5);
    suffix[0] = objNum & 0xff; suffix[1] = (objNum >> 8) & 0xff;
    suffix[2] = (objNum >> 16) & 0xff;
    suffix[3] = gen & 0xff; suffix[4] = (gen >> 8) & 0xff;
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

    const pdfDoc = await PDFDocument.load(inputBuf, { ignoreEncryption: true });
    const normalized = Buffer.from(await pdfDoc.save({ useObjectStreams: false }));
    const pdfStr = normalized.toString('latin1');

    const pkDoc = new PDFKitDoc({
        userPassword: password,
        ownerPassword: ownerPassword,
        compress: false,
        autoFirstPage: false
    });
    const security = pkDoc._security;

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
        const streamStart = objStart + streamMarker.index + streamMarker[0].length;
        const endStreamIdx = pdfStr.indexOf('\nendstream', streamStart);
        if (endStreamIdx === -1) continue;

        result += pdfStr.slice(pos, streamStart);
        const rawStream = Buffer.from(pdfStr.slice(streamStart, endStreamIdx), 'latin1');
        result += security.getEncryptFn(objNum, gen)(rawStream).toString('latin1');
        pos = endStreamIdx;
    }
    result += pdfStr.slice(pos, pdfStr.lastIndexOf('startxref')).trimEnd();

    const pkChunks = [];
    await new Promise(resolve => {
        pkDoc.on('data', c => pkChunks.push(c));
        pkDoc.on('end', resolve);
        pkDoc.end();
    });
    const pkStr = Buffer.concat(pkChunks).toString('latin1');

    const encDictMatch = pkStr.match(/\d+ 0 obj\s*\n<<\s*\n\/Filter \/Standard[\s\S]+?endobj/);
    const idMatch = pkStr.match(/\/ID \[(<[a-f0-9]+> <[a-f0-9]+>)\]/i);
    if (!encDictMatch || !idMatch) throw new Error('pdfkit did not produce /Encrypt dict');

    const encObjNum = parseInt(pdfStr.match(/\/Size (\d+)/)[1]);
    const encDictStr = encDictMatch[0].replace(/^\d+ 0 obj/, `${encObjNum} 0 obj`);
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
        rootMatch ? `/Root ${rootMatch[1]}` : '',
        infoMatch ? `/Info ${infoMatch[1]}` : '',
        `/Encrypt ${encObjNum} 0 R`,
        `/ID [${idMatch[1]}]`,
        `>>`, `startxref`, `${xrefOffset}`, `%%EOF`, ``
    ].filter(Boolean).join('\n');

    return Buffer.from(result, 'latin1');
}

// ── DECRYPT ──────────────────────────────────────────────────────────────────
async function decryptPDFBuffer(encryptedBuf, password) {
    const pdfStr = encryptedBuf.toString('latin1');

    // Search for encrypt dictionary
    let encDictStart = pdfStr.indexOf('/Filter /Standard');

    if (encDictStart === -1) {
        const encryptRef = pdfStr.match(/\/Encrypt (\d+) (\d+) R/);
        if (encryptRef) {
            const encObjNum = encryptRef[1];
            const encObjPattern = new RegExp(`${encObjNum} \\d+ obj`);
            const encObjMatch = pdfStr.match(encObjPattern);
            if (encObjMatch) {
                encDictStart = pdfStr.indexOf('/Filter /Standard', encObjMatch.index);
            }
        }
    }

    if (encDictStart === -1) {
        console.log('[decrypt] Not encrypted');
        return encryptedBuf;
    }

    const encSection = pdfStr.slice(
        Math.max(0, encDictStart - 200),
        encDictStart + 1000
    );

    const oMatch   = encSection.match(/\/O <([A-F0-9]+)>/i);
    const uMatch   = encSection.match(/\/U <([A-F0-9]+)>/i);
    const pMatch   = encSection.match(/\/P (-?\d+)/);
    const idMatch  = pdfStr.match(/\/ID\s*\[?\s*<([a-f0-9]+)>/i);
    const vVal     = parseInt((encSection.match(/\/V (\d+)/) || [])[1] || '1');
    const rVal     = parseInt((encSection.match(/\/R (\d+)/) || [])[1] || '2');
    const lenMatch = encSection.match(/\/Length (\d+)/);
    const keyLen   = lenMatch ? parseInt(lenMatch[1]) / 8 : (vVal === 1 ? 5 : 16);

    console.log('[decrypt] V:', vVal, '| R:', rVal, '| KeyLen:', keyLen);

    if (!oMatch || !uMatch || !pMatch || !idMatch)
        throw new Error('Could not parse encryption parameters');

    const O      = Buffer.from(oMatch[1], 'hex');
    const U      = Buffer.from(uMatch[1], 'hex');
    const perms  = parseInt(pMatch[1]);
    const fileId = Buffer.from(idMatch[1], 'hex');

    if (!verifyPassword(password, O, perms, fileId, U, keyLen, rVal))
        throw new Error('Incorrect password');

    const encKey = computeEncKey(password, O, perms, fileId, keyLen, rVal);
    console.log('[decrypt] ✅ Password verified');

    // ── Decrypt using Buffer operations (not string) ──────────────────────────
    // Convert to buffer for proper binary handling
    const pdfBuf = encryptedBuf;
    const pdfLen = pdfBuf.length;

    // Find all objects using Buffer.indexOf
    const objPattern = /(\d+) (\d+) obj\b/g;
    const objects = [];
    let match;

    while ((match = objPattern.exec(pdfStr)) !== null) {
        objects.push({
            objNum: parseInt(match[1]),
            gen: parseInt(match[2]),
            start: match.index,
            headerEnd: match.index + match[0].length
        });
    }

    console.log('[decrypt] Total objects found:', objects.length);

    // Build decrypted buffer
    const chunks = [];
    let lastPos = 0;

    for (const obj of objects) {
        const objStart = obj.start;
        const endObjStr = 'endobj';
        const endObjIdx = pdfStr.indexOf(endObjStr, obj.headerEnd);
        if (endObjIdx === -1) continue;

        const objBodyStr = pdfStr.slice(objStart, endObjIdx + endObjStr.length);

        // Check for stream
        const streamMatch = objBodyStr.match(/\bstream\r?\n/);
        if (!streamMatch) continue;

        const streamStartInObj = streamMatch.index + streamMatch[0].length;
        const streamStart = objStart + streamStartInObj;
        const endStreamIdx = pdfStr.indexOf('\nendstream', streamStart);
        if (endStreamIdx === -1) continue;

        // Add content before stream
        chunks.push(Buffer.from(pdfStr.slice(lastPos, streamStart), 'latin1'));

        // Decrypt stream
        const encStreamBuf = Buffer.from(
            pdfStr.slice(streamStart, endStreamIdx),
            'latin1'
        );

        const objKey = getObjKey(encKey, obj.objNum, obj.gen);
        const decStreamBuf = rc4(objKey, encStreamBuf);

        chunks.push(decStreamBuf);
        lastPos = endStreamIdx;
    }

    // Add remaining content
    let remaining = pdfStr.slice(lastPos);

    // Remove /Encrypt reference from trailer
    remaining = remaining.replace(/\/Encrypt \d+ \d+ R\s*/g, '');

    chunks.push(Buffer.from(remaining, 'latin1'));

    // Combine all chunks
    let decryptedBuf = Buffer.concat(chunks);

    console.log('[decrypt] Raw decrypted size:', decryptedBuf.length);

    // Remove encrypt dictionary object
    let decryptedStr = decryptedBuf.toString('latin1');
  // Remove ONLY the encrypt dictionary object carefully
const encObjMatch = decryptedStr.match(/(\d+) 0 obj[^]*?\/Filter\s*\/Standard[^]*?endobj/);
if (encObjMatch) {
    console.log('[decrypt] Removing encrypt obj, length:', encObjMatch[0].length);
    decryptedStr = decryptedStr.replace(encObjMatch[0], '');
}

    decryptedBuf = Buffer.from(decryptedStr, 'latin1');
    console.log('[decrypt] Final decrypted size:', decryptedBuf.length);

    // Rebuild with pdf-lib to create clean PDF
    try {
        const pdfDoc = await PDFDocument.load(decryptedBuf, {
            ignoreEncryption: true,
            throwOnInvalidObject: false
        });

        const pageCount = pdfDoc.getPageCount();
        console.log('[decrypt] Pages:', pageCount);

        // Create new clean PDF with embedded pages
        const cleanDoc = await PDFDocument.create();
        const embeddedPages = await cleanDoc.embedPdf(
            decryptedBuf,
            Array.from({ length: pageCount }, (_, i) => i)
        );

        for (const ep of embeddedPages) {
            const page = cleanDoc.addPage([ep.width, ep.height]);
            page.drawPage(ep);
        }

        const cleanBytes = await cleanDoc.save();
        console.log('[decrypt] ✅ Clean PDF created, size:', cleanBytes.length);
        return Buffer.from(cleanBytes);

    } catch(err) {
        console.log('[decrypt] pdf-lib rebuild failed:', err.message);
        return decryptedBuf;
    }
}

// ── CHECK ─────────────────────────────────────────────────────────────────────
function isPDFEncrypted(buf) {
    const s = buf.toString('latin1');
    const hasStandard = s.includes('/Filter /Standard');
    const hasEncrypt = /\/Encrypt[\s\n\/\[<]/.test(s);
    const hasEncryptRef = /\/Encrypt \d+ \d+ R/.test(s);
    console.log('[isPDFEncrypted] hasStandard:', hasStandard, '| hasEncrypt:', hasEncrypt, '| hasEncryptRef:', hasEncryptRef);
    return hasStandard || hasEncrypt || hasEncryptRef;
}

module.exports = { encryptPDFBuffer, decryptPDFBuffer, isPDFEncrypted };