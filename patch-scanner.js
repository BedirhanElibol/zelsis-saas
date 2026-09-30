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

const rawPath = 'lib/scanner-engine.ts';
const normalizedPath = path.normalize(rawPath);
const resolvedPath = path.resolve(BASE_DIR, normalizedPath);
if (!resolvedPath.startsWith(BASE_DIR)) {
    throw new Error('Path traversal detected');
}
let code = fs.readFileSync(resolvedPath, 'utf8');

const imports = `
import { evaluateRubyRailsRules } from './rules/ruby-rails-rules';
import { evaluatePhpLaravelRules } from './rules/php-laravel-rules';
import { evaluateJavaSpringRules } from './rules/java-spring-rules';
import { evaluateDotnetCsharpRules } from './rules/dotnet-csharp-rules';
`;

code = code.replace(/import \{ evaluateLlmCostGovernanceRules \} from '\.\/rules\/llm-cost-governance-rules';/, "import { evaluateLlmCostGovernanceRules } from './rules/llm-cost-governance-rules';\n" + imports);

const blocks = `
    const rubyCounter = { count: findingCounter };
    const rubyResult = evaluateRubyRailsRules(file, lines, cleanContent, rubyCounter);
    findingCounter = rubyCounter.count;
    for (const item of rubyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...rubyResult.logs);

    const phpCounter = { count: findingCounter };
    const phpResult = evaluatePhpLaravelRules(file, lines, cleanContent, phpCounter);
    findingCounter = phpCounter.count;
    for (const item of phpResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...phpResult.logs);

    const javaCounter = { count: findingCounter };
    const javaResult = evaluateJavaSpringRules(file, lines, cleanContent, javaCounter);
    findingCounter = javaCounter.count;
    for (const item of javaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...javaResult.logs);

    const dotnetCounter = { count: findingCounter };
    const dotnetResult = evaluateDotnetCsharpRules(file, lines, cleanContent, dotnetCounter);
    findingCounter = dotnetCounter.count;
    for (const item of dotnetResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...dotnetResult.logs);
`;

code = code.replace(/const fileFindingsCount = findings\.length - startFindingsCount;/, blocks + '\n    const fileFindingsCount = findings.length - startFindingsCount;');

fs.writeFileSync(resolvedPath, code);
console.log('Scanner engine patched successfully.');
