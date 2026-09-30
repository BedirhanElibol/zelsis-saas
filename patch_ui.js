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

function replaceInFile(filePath, search, replacement) {
    const safePath = assertSafePath(filePath);
    if (fs.existsSync(safePath)) {
        let content = fs.readFileSync(safePath, 'utf8');
        content = content.replace(search, replacement);
        fs.writeFileSync(safePath, content);
    }
}

// 1. QuotaLimitModal.tsx
replaceInFile(
    'components/dashboard/QuotaLimitModal.tsx',
    /All 1,?450\+.*rules/i,
    'All verified production rules'
);

// 2. TierDetailsModal.tsx
replaceInFile(
    'components/pricing/TierDetailsModal.tsx',
    /All 1,?450\+ Production Rules/g,
    'All Verified Production Rules'
);

// 3. ComparisonTable.tsx
replaceInFile(
    'components/saas/ComparisonTable.tsx',
    /1,?450\+ Deep Production Rules/g,
    'All Verified Production Rules'
);
replaceInFile(
    'components/saas/ComparisonTable.tsx',
    /1,?450\+ Rules \+ Custom Org Rulesets/g,
    'Verified Rules + Custom Org Rulesets'
);
replaceInFile(
    'components/saas/ComparisonTable.tsx',
    /7,?500\+.*rules/ig,
    'Verified Production Rules'
);

// 4. lib/quota-manager.ts
replaceInFile(
    'lib/quota-manager.ts',
    /All 1,?450\+ Production Rules/g,
    'All Verified Production Rules'
);

console.log("Replaced fake rule counts in UI components.");
