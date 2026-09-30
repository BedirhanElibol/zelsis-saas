const fs = require('fs');

function replaceInFile(filePath, search, replacement) {
    if (fs.existsSync(filePath)) {
        let content = fs.readFileSync(filePath, 'utf8');
        content = content.replace(search, replacement);
        fs.writeFileSync(filePath, content);
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
