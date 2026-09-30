const fs = require('fs');
const path = require('path');

const catalogsDir = path.join(__dirname, 'data', 'catalogs');
const files = fs.readdirSync(catalogsDir).filter(f => f.endsWith('.ts') && f !== 'index.ts');

const keysToDedupe = new Set([
    'owasp2025Category',
    'cweId',
    'sourceUrl',
    'sourceType',
    'positiveExample',
    'negativeExample',
    'applicableLanguages',
    'detectionMethod',
    'falsePositiveRisk',
    'status'
]);

for (const file of files) {
    const filePath = path.join(catalogsDir, file);
    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(catalogsDir)) {
        throw new Error('Path traversal detected');
    }
    let content = fs.readFileSync(normalizedPath, 'utf-8');
    let lines = content.split('\n');
    let newLines = [];
    
    let currentObjectKeys = new Set();
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i];
        let trimmed = line.trim();
        
        if (trimmed.includes('{')) {
            currentObjectKeys.clear();
        }
        
        let skip = false;
        const match = trimmed.match(/^([a-zA-Z0-9_]+)\s*:/);
        if (match) {
            const key = match[1];
            if (keysToDedupe.has(key)) {
                if (currentObjectKeys.has(key)) {
                    skip = true;
                } else {
                    currentObjectKeys.add(key);
                }
            }
        }
        
        if (!skip) {
            newLines.push(line);
        }
    }
    
    fs.writeFileSync(normalizedPath, newLines.join('\n'));
}
console.log("Done");
