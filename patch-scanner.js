const fs = require('fs');
const file = 'lib/scanner-engine.ts';
let code = fs.readFileSync(file, 'utf8');

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

fs.writeFileSync(file, code);
console.log('Scanner engine patched successfully.');
