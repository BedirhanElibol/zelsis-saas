const fs = require('fs');
const path = require('path');

const catalogsDir = path.join(__dirname, 'data', 'catalogs');
const files = fs.readdirSync(catalogsDir).filter(f => f.endsWith('.ts'));

let checklist = {
    c1: true,
    c2: true,
    c3: true,
    c4: true
};

const c1_keys = ['source_url', 'source_type', 'positive_example', 'negative_example'];
const rules_without_c1 = [];
const old_owasp_files = [];
const wrong_ast_rules = [];

for (const file of files) {
    const filePath = path.join(catalogsDir, file);
    const content = fs.readFileSync(filePath, 'utf-8');
    
    // Check 2: OWASP
    const owaspMatches = content.match(/OWASP(?! 2025)/g);
    if (owaspMatches) {
        checklist.c2 = false;
        old_owasp_files.push(file);
    }
    
    // Attempt to extract rules
    // A primitive way: match { id: '...', ... } blocks
    const ruleMatches = content.match(/{\s*id:\s*['"].*?['"][\s\S]*?(?=,\s*{\s*id:|}\s*])/g);
    if (ruleMatches) {
        for (const rule of ruleMatches) {
            // Check 1
            let hasAll = true;
            for (const key of c1_keys) {
                if (!rule.includes(key)) {
                    hasAll = false;
                }
            }
            if (!hasAll) {
                checklist.c1 = false;
                rules_without_c1.push({ file, ruleId: rule.match(/id:\s*['"](.*?)['"]/)?.[1] });
            }
            
            // Check 3: AST used but not AST rule
            if (rule.includes('AST') || rule.includes('ast')) {
                // If it's a rule using regex, it shouldn't say AST
                if (rule.includes('regex') || rule.includes('lexical')) {
                    if (rule.match(/\bAST\b/)) {
                        checklist.c3 = false;
                        wrong_ast_rules.push({ file, ruleId: rule.match(/id:\s*['"](.*?)['"]/)?.[1] });
                    }
                }
            }
        }
    }
}

console.log('Checklist 1 (Fields):', checklist.c1 ? 'Pass' : 'Fail', rules_without_c1.length > 0 ? `Failed in ${rules_without_c1.length} rules` : '');
console.log('Checklist 2 (OWASP):', checklist.c2 ? 'Pass' : 'Fail', old_owasp_files.length > 0 ? `Failed in ${old_owasp_files.length} files` : '');
console.log('Checklist 3 (AST):', checklist.c3 ? 'Pass' : 'Fail', wrong_ast_rules.length > 0 ? `Failed in ${wrong_ast_rules.length} rules` : '');

// For Check 4, check duplicate templates
const descriptions = [];
let hasDupeTemplate = false;
for (const file of files) {
    const filePath = path.join(catalogsDir, file);
    const content = fs.readFileSync(filePath, 'utf-8');
    const descMatches = content.match(/description:\s*['"](.*?)['"]/g);
    if (descMatches) {
        for (const desc of descMatches) {
            // strip description: ''
            let d = desc.replace(/description:\s*['"]/, '').replace(/['"]$/, '');
            // abstract the words
            let template = d.replace(/[A-Z][a-zA-Z0-9_]*/g, 'VAR').replace(/'.*?'/g, 'STR');
            if (descriptions.includes(template) && d.length > 20) {
                // simple heuristic
                // console.log("Duplicate template?", template, d);
            }
            descriptions.push(template);
        }
    }
}
// We will just do a manual inspection or rely on the primitive AST script.
