const fs = require('fs');
const path = require('path');

const catalogsDir = path.join(__dirname, 'data', 'catalogs');
const files = fs.readdirSync(catalogsDir).filter(f => f.endsWith('.ts'));

let descriptions = {};

for (const file of files) {
    const filePath = path.join(catalogsDir, file);
    const content = fs.readFileSync(filePath, 'utf-8');
    
    // match descriptions
    const descMatches = content.match(/description:\s*['"](.*?)['"]/g);
    if (descMatches) {
        for (const m of descMatches) {
            let desc = m.replace(/description:\s*['"](.*)['"]/, '$1');
            
            // Abstract the string
            // Replace specific words that might vary (e.g. SQL, NoSQL, JWT, CSRF) with a token
            // A simple heuristic for "same sentence structure, different words"
            let template = desc.replace(/[A-Z][a-zA-Z0-9_-]*/g, 'TOKEN').replace(/'.*?'/g, 'STR').replace(/`.*?`/g, 'STR');
            
            if (!descriptions[template]) {
                descriptions[template] = [];
            }
            descriptions[template].push({file, desc});
        }
    }
}

let hasDupes = false;
for (const [template, items] of Object.entries(descriptions)) {
    if (items.length > 1) {
        const uniqueDescs = new Set(items.map(i => i.desc));
        if (uniqueDescs.size > 1 && template.length > 30) {
            console.log('--- Duplicate structure found ---');
            for (let d of uniqueDescs) {
                console.log(d);
            }
            hasDupes = true;
        }
    }
}

if (hasDupes) {
    console.log("Checklist 4: FAIL");
} else {
    console.log("Checklist 4: PASS");
}
