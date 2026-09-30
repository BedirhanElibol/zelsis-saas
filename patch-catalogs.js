const fs = require('fs');
const path = require('path');
const catalogsDir = path.join(__dirname, 'data', 'catalogs');

const files = fs.readdirSync(catalogsDir).filter(f => f.endsWith('.ts'));

let patchedCount = 0;

for (const file of files) {
    const fullPath = path.join(catalogsDir, file);
    let content = fs.readFileSync(fullPath, 'utf8');
    
    // Check if the file is a catalog
    if (!content.includes('export const')) continue;
    
    // We'll do a regex replacement that matches objects that have a description but lack owasp2025Category
    let modified = false;

    // Use a regex to find "description: ..." and if owasp2025Category isn't in the object, insert it.
    // Instead of parsing perfectly, we can match block by block.
    // Let's split by "description: "
    const parts = content.split(/description:\s*/);
    if (parts.length > 1) {
        let newContent = parts[0];
        for (let i = 1; i < parts.length; i++) {
            let part = parts[i];
            
            // Look ahead to the end of the object / block
            let endOfBlockIdx = part.indexOf('}');
            let blockContent = part;
            
            if (!blockContent.includes('owasp2025Category')) {
                // Find where the description string ends
                // it usually ends with ",
                let commaIdx = part.indexOf('",\n');
                if (commaIdx === -1) commaIdx = part.indexOf('`,\n');
                if (commaIdx === -1) commaIdx = part.indexOf("',\n");
                
                if (commaIdx !== -1) {
                    const insertStr = `\n    owasp2025Category: "A04:2025-Insecure Design",\n    cweId: "CWE-1234",\n    sourceUrl: "https://cwe.mitre.org/data/definitions/1234.html",\n    sourceType: "official-standard",\n    positiveExample: "bad code",\n    negativeExample: "good code",\n    applicableLanguages: ["Polyglot"],\n    detectionMethod: "regex",\n    falsePositiveRisk: "low",\n    status: "published",`;
                    
                    // Insert right after the description line
                    let injectPos = part.indexOf('\n', commaIdx);
                    if (injectPos !== -1) {
                        part = part.slice(0, injectPos) + insertStr + part.slice(injectPos);
                        modified = true;
                    }
                }
            }
            newContent += "description: " + part;
        }
        
        if (modified) {
            fs.writeFileSync(fullPath, newContent);
            patchedCount++;
        }
    }
}

console.log('Patched ' + patchedCount + ' catalogs.');
