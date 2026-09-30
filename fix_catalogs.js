const fs = require('fs');
const path = require('path');

const BASE_DIR = path.resolve(__dirname);

function assertSafePath(targetPath, baseDir = BASE_DIR) {
    const normalized = path.normalize(targetPath);
    const resolved = path.resolve(baseDir, normalized);
    const resolvedBase = path.resolve(baseDir);
    const isWindows = process.platform === 'win32';
    const checkResolved = isWindows ? resolved.toLowerCase() : resolved;
    const checkBase = isWindows ? resolvedBase.toLowerCase() : resolvedBase;
    const prefix = checkBase.endsWith(path.sep) ? checkBase : checkBase + path.sep;

    if (!checkResolved.startsWith(prefix) && checkResolved !== checkBase) {
        throw new Error(`Path traversal detected: ${targetPath}`);
    }
    return resolved;
}

function fixZeroTrust() {
    const rawPath = path.join(__dirname, 'data/catalogs/zero-trust-network-catalog.ts');
    const normalizedPath = path.normalize(rawPath);
    if (!path.resolve(normalizedPath).startsWith(BASE_DIR)) {
        throw new Error('Path traversal detected');
    }
    let content = fs.readFileSync(normalizedPath, 'utf8');

    // we will find the index of the 11th item and just truncate the array.
    // The 11th item starts with id: 13111 or 'SDP-01' again but with [Spec-2].
    // Let's use a regex to find where the 11th item starts.
    const match11 = content.indexOf('  {\n    id: 13111,');
    if (match11 !== -1) {
        content = content.substring(0, match11) + '];\n';
    }

    // replace [Spec-1] in titles
    content = content.replace(/ \[Spec-1\]/g, '');

    // replace OWASP A01:2021 with OWASP A01:2025
    content = content.replace(/OWASP A(\d{2}):2021/g, 'OWASP A$1:2025');

    fs.writeFileSync(normalizedPath, content, 'utf8');
    console.log('Fixed zero-trust-network-catalog.ts');
}

function fixRust() {
    const rawPath = path.join(__dirname, 'data/catalogs/rust-systems-catalog.ts');
    const normalizedPath = path.normalize(rawPath);
    if (!path.resolve(normalizedPath).startsWith(BASE_DIR)) {
        throw new Error('Path traversal detected');
    }
    let content = fs.readFileSync(normalizedPath, 'utf8');

    // The 6th item starts with id: 9606
    const match6 = content.indexOf('  {\n    id: 9606,');
    if (match6 !== -1) {
        content = content.substring(0, match6) + '];\n';
    }

    content = content.replace(/OWASP A(\d{2}):2021/g, 'OWASP A$1:2025');

    fs.writeFileSync(normalizedPath, content, 'utf8');
    console.log('Fixed rust-systems-catalog.ts');
}

fixZeroTrust();
fixRust();
