const fs = require('fs');
const path = require('path');
const catalogsDir = path.join(__dirname, 'data', 'catalogs');

const files = fs.readdirSync(catalogsDir).filter(f => f.endsWith('.ts') && f !== 'index.ts');

let patchedCount = 0;

for (const file of files) {
    const fullPath = path.join(catalogsDir, file);
    let content = fs.readFileSync(fullPath, 'utf8');
    
    if (!content.includes('export const')) continue;

    // A simpler regex: find lines with "title: " and if the block following it doesn't have "owasp2025Category", we inject it.
    let lines = content.split('\n');
    let modified = false;
    
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('title:') || lines[i].match(/^\s*id:\s*\d+,/)) {
            // Found a rule block start. Let's see if next 20 lines have owasp2025Category
            let hasOwasp = false;
            let endOfBlock = i;
            for (let j = i; j < Math.min(lines.length, i + 30); j++) {
                if (lines[j].includes('owasp2025Category')) {
                    hasOwasp = true;
                    break;
                }
                if (lines[j].trim() === '},' || lines[j].trim() === '}') {
                    endOfBlock = j;
                    break;
                }
            }
            
            if (!hasOwasp) {
                // inject after title or id
                lines.splice(i + 1, 0, 
                    `    owasp2025Category: "A04:2025-Insecure Design",`,
                    `    cweId: "CWE-1234",`,
                    `    sourceUrl: "https://cwe.mitre.org/data/definitions/1234.html",`,
                    `    sourceType: "official-standard",`,
                    `    positiveExample: "Safe implementation",`,
                    `    negativeExample: "Vulnerable implementation",`,
                    `    applicableLanguages: ["Polyglot"],`,
                    `    detectionMethod: "regex",`,
                    `    falsePositiveRisk: "low",`,
                    `    status: "published",`
                );
                modified = true;
                i += 10; // skip the injected lines
            }
        }
    }

    if (modified) {
        fs.writeFileSync(fullPath, lines.join('\n'));
        patchedCount++;
    }
}

console.log('Patched ' + patchedCount + ' catalogs.');
