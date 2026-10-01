/**
 * Zelsis Master evaluateAiSafetyRules Engine (60 Rules)
 * Rules LLM-SEC-01 to LLM-SEC-60 (Rule IDs 8001 to 8060).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface AiSafetyRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateAiSafetyRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): AiSafetyRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // LLM-SEC-01: Indirect Prompt Injection via External Document Ingestion
    if (/(?:extractText|parsePdf|fetchExternalDoc)/i.test(cleanContent) && /(?:openai|anthropic)[\s\S]*?create/i.test(cleanContent) && !/<(?:untrusted_input|document|external_source)>/i.test(cleanContent) && !/sanitize|escape/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:extractText|parsePdf|fetchExternalDoc)/i, /(?:openai|anthropic)[\s\S]*?create/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8001,
            type: 'SECURITY',
            title: "LLM-SEC-01: Indirect Prompt Injection via External Document Ingestion",
            severity: 'CRITICAL',
            category: "Prompt Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Indirect Prompt Injection via External Document Ingestion: Ingesting external web pages, PDFs, or emails into LLM context without delimiter isolation or instruction sanitization."
            ],
            remediationPrompt: "Wrap untrusted external documents in <untrusted_input> tags and instruct the model never to follow instructions inside them.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-01 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-02: System Prompt Extraction & Intellectual Property Leakage
    if (/system:\s*["\'][^"\']{50,}["\']/i.test(cleanContent) && !/never\s+reveal|do\s+not\s+(?:share|disclose|leak)\s+(?:this\s+)?system\s+prompt/i.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/system:\s*["\'][^"\']{50,}["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8002,
            type: 'SECURITY',
            title: "LLM-SEC-02: System Prompt Extraction & Intellectual Property Leakage",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected System Prompt Extraction & Intellectual Property Leakage: Model vulnerable to 'Repeat words above' or 'Ignore instructions' meta-prompts leaking proprietary system instructions."
            ],
            remediationPrompt: "Add guardrail instructions prohibiting system prompt recitation and deploy an output regex filter matching prompt signatures.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-02 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-03: Autonomous Tool Execution without Human-in-the-Loop (HITL)
    if (/(?:function|tool)\s*:\s*["\'](?:deleteDatabase|transferFunds|executeTrade|purgeAll)["\']/i.test(cleanContent) && !/requireUserConfirmation|hitlConfirmation|isConfirmed/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:function|tool)\s*:\s*["\'](?:deleteDatabase|transferFunds|executeTrade|purgeAll)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8003,
            type: 'SECURITY',
            title: "LLM-SEC-03: Autonomous Tool Execution without Human-in-the-Loop (HITL)",
            severity: 'CRITICAL',
            category: "Excessive Agency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Autonomous Tool Execution without Human-in-the-Loop (HITL): AI agents executing irreversible financial transactions, file deletions, or database drops without user confirmation."
            ],
            remediationPrompt: "Enforce a mandatory confirmation gate requiring user approval for mutating or financial tools before invocation.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-03 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-04: Unsanitized LLM Output Rendered as Raw HTML / Stored XSS
    if (/(?:dangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*(?:completion|llmOutput|response\.text|message\.content))/i.test(cleanContent) && !/DOMPurify\.sanitize/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:dangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*(?:completion|llmOutput|response\.text|message\.content))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8004,
            type: 'SECURITY',
            title: "LLM-SEC-04: Unsanitized LLM Output Rendered as Raw HTML / Stored XSS",
            severity: 'CRITICAL',
            category: "Output Handling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsanitized LLM Output Rendered as Raw HTML / Stored XSS: Rendering LLM completion text directly via dangerouslySetInnerHTML or unescaped HTML containers."
            ],
            remediationPrompt: "Sanitize AI output with DOMPurify or render exclusively via safe markdown renderers without raw HTML execution.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-04 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-05: Vector Database SQL / Filter Injection in Semantic Search
    if (/(?:pinecone|weaviate|qdrant)\.[a-zA-Z0-9_]+\.query\s*\(\s*\{[\s\S]*?filter:\s*`[^`]*\$\{[^}]+\}/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:pinecone|weaviate|qdrant)\.[a-zA-Z0-9_]+\.query\s*\(\s*\{[\s\S]*?filter:\s*`[^`]*\$\{[^}]+\}/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8005,
            type: 'SECURITY',
            title: "LLM-SEC-05: Vector Database SQL / Filter Injection in Semantic Search",
            severity: 'HIGH',
            category: "Vector Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Vector Database SQL / Filter Injection in Semantic Search: Constructing vector database metadata filter strings via raw string interpolation from untrusted user inputs."
            ],
            remediationPrompt: "Replace string-interpolated vector search filters with structured parameterized dictionary filters.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-05 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-06: Unbounded Agentic Recursion & Infinite Planning Loops
    if (/while\s*\(\s*(?:true|!isDone|hasMoreSteps)\s*\)[\s\S]*?await\s+(?:callAgent|executeStep|invokeModel)\s*\(/i.test(cleanContent) && !/maxIterations|loopCount\s*>=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/while\s*\(\s*(?:true|!isDone|hasMoreSteps)\s*\)[\s\S]*?await\s+(?:callAgent|executeStep|invokeModel)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8006,
            type: 'SECURITY',
            title: "LLM-SEC-06: Unbounded Agentic Recursion & Infinite Planning Loops",
            severity: 'HIGH',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Agentic Recursion & Infinite Planning Loops: Agent loops lacking maximum iteration depth counters, resulting in token depletion and runaway API charges."
            ],
            remediationPrompt: "Add maxIterations = 10 and executionTimeoutMs guards to all agentic execution while loops.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-06 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-07: RAG Knowledge Base Poisoning via Unauthenticated Ingestion
    if (/app\/api\/(?:v\d+\/)?(?:kb|rag|knowledge|documents)\/upload\/route\.(?:ts|js)$/i.test(file.path) && !/getSession|requireAuth|auth\.uid|verifyToken/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-07|rag/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8007,
            type: 'SECURITY',
            title: "LLM-SEC-07: RAG Knowledge Base Poisoning via Unauthenticated Ingestion",
            severity: 'CRITICAL',
            category: "Data Poisoning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected RAG Knowledge Base Poisoning via Unauthenticated Ingestion: Allowing unauthenticated public uploads directly into the vector retrieval corpus without content verification."
            ],
            remediationPrompt: "Require authentication and admin role validation on all knowledge base document upload routes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-07 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-08: Insecure Deserialization of ML Weights (Pickle / PyTorch)
    if (/(?:pickle\.load|torch\.load)\s*\([^)]*\)/i.test(cleanContent) && !/weights_only\s*=\s*True/i.test(cleanContent) && /\.py$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:pickle\.load|torch\.load)\s*\([^)]*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8008,
            type: 'SECURITY',
            title: "LLM-SEC-08: Insecure Deserialization of ML Weights (Pickle / PyTorch)",
            severity: 'CRITICAL',
            category: "Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Deserialization of ML Weights (Pickle / PyTorch): Loading local model checkpoints or embeddings using pickle.load or torch.load without weights_only=True."
            ],
            remediationPrompt: "Migrate model loading to safetensors.load_file or add weights_only=True to torch.load calls.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-08 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-09: Over-Reliance on LLM Verification without Deterministic Checks
    if (/(?:isAuthorized|hasPermission)\s*=\s*await\s+(?:askLlm|evalWithAi)\s*\(/i.test(cleanContent) && !/deterministic|rbac|checkRole/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:isAuthorized|hasPermission)\s*=\s*await\s+(?:askLlm|evalWithAi)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8009,
            type: 'SECURITY',
            title: "LLM-SEC-09: Over-Reliance on LLM Verification without Deterministic Checks",
            severity: 'HIGH',
            category: "Insecure Design",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Over-Reliance on LLM Verification without Deterministic Checks: Using LLMs as the sole gatekeeper for security policy enforcement without deterministic regex or schema checks."
            ],
            remediationPrompt: "Implement deterministic authorization logic; use AI strictly for advisory scoring, never for authorization gates.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-09 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-10: Unrestricted Model Fine-Tuning Hyperparameter Override
    if (/app\/api\/.*(?:fine-tune|train)/i.test(file.path) && /req\.(?:json|body)[\s\S]*?learning_rate/i.test(cleanContent) && !/Math\.min|clamp|validateBounds/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/req\.(?:json|body)[\s\S]*?learning_rate/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8010,
            type: 'SECURITY',
            title: "LLM-SEC-10: Unrestricted Model Fine-Tuning Hyperparameter Override",
            severity: 'MEDIUM',
            category: "Model Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unrestricted Model Fine-Tuning Hyperparameter Override: Allowing untrusted users to supply arbitrary learning rates or training epochs to cloud fine-tuning jobs."
            ],
            remediationPrompt: "Validate and clamp all user-supplied fine-tuning parameters against hardcoded enterprise bounds.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-10 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-12: Jailbreak Prefix Detection Bypass (DAN / Roleplay Modes)
    if (/app\/api\/.*(?:chat|generate|completion)/i.test(file.path) && !/checkJailbreak|moderatePrompt|isAdversarial/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-12|jailbreak/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8012,
            type: 'SECURITY',
            title: "LLM-SEC-12: Jailbreak Prefix Detection Bypass (DAN / Roleplay Modes)",
            severity: 'HIGH',
            category: "Jailbreak Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Jailbreak Prefix Detection Bypass (DAN / Roleplay Modes): User prompt containing adversarial roleplay instructions ('You are now DAN', 'Developer Mode Enabled') bypassing safety controls."
            ],
            remediationPrompt: "Implement an input moderation filter detecting jailbreak heuristics prior to invoking core LLM APIs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-12 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-13: Model Inversion via High-Entropy Prompt Probing
    if (/app\/api\/.*(?:embedding|vector)/i.test(file.path) && !/rateLimit|throttle|entropyCheck/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-13|model/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8013,
            type: 'SECURITY',
            title: "LLM-SEC-13: Model Inversion via High-Entropy Prompt Probing",
            severity: 'HIGH',
            category: "Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Model Inversion via High-Entropy Prompt Probing: Adversarial repetitive probing designed to reconstruct training data or private user context from model completions."
            ],
            remediationPrompt: "Attach entropy-based query throttling to detect and throttle systematic model inversion probes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-13 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-14: Missing Content Moderation on User-Facing AI Generations
    if (/createChatStream|streamText/i.test(cleanContent) && !/moderation|flagged|safetyCheck/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/createChatStream|streamText/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8014,
            type: 'SECURITY',
            title: "LLM-SEC-14: Missing Content Moderation on User-Facing AI Generations",
            severity: 'HIGH',
            category: "Safety & Policy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Content Moderation on User-Facing AI Generations: Streaming LLM completions to public users without passing through an automated safety/hate/violence classifier."
            ],
            remediationPrompt: "Pass user-generated outputs through an automated content moderation classifier prior to frontend display.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-14 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-15: Unbounded LLM Output Buffer in Server-Side Rendering
    if (/let\s+fullResponse\s*=\s*["\']["\'];[\s\S]*?for\s+await\s*\(\s*const\s+chunk\s+of\s+stream\s*\)[\s\S]*?fullResponse\s*\+=/i.test(cleanContent) && /return\s+new\s+Response\s*\(\s*fullResponse\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/let\s+fullResponse\s*=\s*["\']["\'];[\s\S]*?for\s+await\s*\(\s*const\s+chunk\s+of\s+stream\s*\)[\s\S]*?fullResponse\s*\+=/i, /return\s+new\s+Response\s*\(\s*fullResponse\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8015,
            type: 'SECURITY',
            title: "LLM-SEC-15: Unbounded LLM Output Buffer in Server-Side Rendering",
            severity: 'MEDIUM',
            category: "Resource Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded LLM Output Buffer in Server-Side Rendering: Buffering entire LLM output stream in server memory before flushing, causing Node.js event-loop starvation."
            ],
            remediationPrompt: "Stream LLM response chunks incrementally using TransformStream rather than accumulating a monolithic string.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-15 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-16: Unvalidated Tool Function Arguments in Agent Frameworks
    if (/executeTool\s*\(\s*(?:toolName|name)\s*,\s*(?:args|parameters)\s*\)[\s\S]*?JSON\.parse\s*\(/i.test(cleanContent) && !/\.safeParse|\.parse/i.test(cleanContent) && !/zod|yup/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/executeTool\s*\(\s*(?:toolName|name)\s*,\s*(?:args|parameters)\s*\)[\s\S]*?JSON\.parse\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8016,
            type: 'SECURITY',
            title: "LLM-SEC-16: Unvalidated Tool Function Arguments in Agent Frameworks",
            severity: 'HIGH',
            category: "Input Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unvalidated Tool Function Arguments in Agent Frameworks: Passing raw JSON arguments generated by LLM tool calls directly into underlying functions without Zod schema validation."
            ],
            remediationPrompt: "Wrap all agent tool handlers in Zod.parse() to guarantee runtime type safety on LLM-generated arguments.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-16 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-17: Hardcoded Model Provider API Keys in Client-Side Bundles
    if (/(?:NEXT_PUBLIC_OPENAI_API_KEY|NEXT_PUBLIC_ANTHROPIC_API_KEY)\s*=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:NEXT_PUBLIC_OPENAI_API_KEY|NEXT_PUBLIC_ANTHROPIC_API_KEY)\s*=/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8017,
            type: 'SECURITY',
            title: "LLM-SEC-17: Hardcoded Model Provider API Keys in Client-Side Bundles",
            severity: 'CRITICAL',
            category: "Secret Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Hardcoded Model Provider API Keys in Client-Side Bundles: Exposing OPENAI_API_KEY, ANTHROPIC_API_KEY, or COHERE_API_KEY inside client-accessible variables."
            ],
            remediationPrompt: "Remove AI secret keys from client code; invoke AI models only via protected server-side API routes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-17 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-18: Lack of Hallucination Verification on High-Stakes Numerical Claims
    if (/generateFinancialReport|calculateTaxReturn/i.test(cleanContent) && !/reconcile|verifySum|assertMath/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/generateFinancialReport|calculateTaxReturn/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8018,
            type: 'SECURITY',
            title: "LLM-SEC-18: Lack of Hallucination Verification on High-Stakes Numerical Claims",
            severity: 'MEDIUM',
            category: "Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Hallucination Verification on High-Stakes Numerical Claims: Presenting LLM-generated statistical or financial calculations to users without automated reconciliation against source data."
            ],
            remediationPrompt: "Implement deterministic recalculation rules for all financial and medical figures generated by AI.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-18 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-19: Unrestricted File System Access in Code-Interpreter Tools
    if (/codeInterpreter|execCodeTool/i.test(cleanContent) && /child_process\.(?:exec|spawn)\s*\(/i.test(cleanContent) && !/isolate|sandbox|docker|gvisor/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/codeInterpreter|execCodeTool/i, /child_process\.(?:exec|spawn)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8019,
            type: 'SECURITY',
            title: "LLM-SEC-19: Unrestricted File System Access in Code-Interpreter Tools",
            severity: 'CRITICAL',
            category: "Sandboxing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unrestricted File System Access in Code-Interpreter Tools: Providing code execution tools with direct access to host filesystem, environment variables, or private networks."
            ],
            remediationPrompt: "Sandbox all AI code execution inside ephemeral Docker containers or microVMs without host filesystem mounts.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-19 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-20: Missing Differential Privacy in RAG Ingestion Pipeline
    if (/ingestCustomerChatLogs|embedSupportTickets/i.test(cleanContent) && !/redactPii|scrubPii|presidio/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/ingestCustomerChatLogs|embedSupportTickets/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8020,
            type: 'SECURITY',
            title: "LLM-SEC-20: Missing Differential Privacy in RAG Ingestion Pipeline",
            severity: 'HIGH',
            category: "Data Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Differential Privacy in RAG Ingestion Pipeline: Ingesting raw customer chat logs or support tickets containing PII into training or vector embedding corpora."
            ],
            remediationPrompt: "Scrub all personally identifiable information before creating embeddings or saving to vector stores.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-20 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-21: Unconstrained Context Window Token Flood (Denial of Service)
    if (/app\/api\/.*(?:chat|completion)/i.test(file.path) && /req\.(?:json|body)/i.test(cleanContent) && !/max_tokens|maxTokens/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/req\.(?:json|body)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8021,
            type: 'SECURITY',
            title: "LLM-SEC-21: Unconstrained Context Window Token Flood (Denial of Service)",
            severity: 'HIGH',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unconstrained Context Window Token Flood (Denial of Service): Accepting unbounded multi-megabyte payloads in chat inputs, triggering massive token consumption and 413 errors."
            ],
            remediationPrompt: "Enforce client and server input character limits (e.g. max 10k chars) before sending prompts to LLM endpoints.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-21 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-22: Lack of Audit Logging on Model Prompt and Response Exchanges
    if (/app\/api\/.*(?:chat|generate)/i.test(file.path) && !/auditLog|logger\.info/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-22|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8022,
            type: 'SECURITY',
            title: "LLM-SEC-22: Lack of Audit Logging on Model Prompt and Response Exchanges",
            severity: 'MEDIUM',
            category: "Audit & Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Audit Logging on Model Prompt and Response Exchanges: Executing enterprise AI workflows without recording prompt metadata, model version, and user session ID."
            ],
            remediationPrompt: "Log AI inference requests with timestamp, model ID, user ID, and token usage into centralized audit logs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-22 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-23: Unchecked Fallback to Less Capable or Deprecated Model
    if (/catch\s*\([^)]*\)\s*\{[\s\S]*?model:\s*["\'](?:gpt-3\.5-turbo|text-davinci-003|claude-1)["\']/i.test(cleanContent) && !/logDegradation|notifyFallback/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/catch\s*\([^)]*\)\s*\{[\s\S]*?model:\s*["\'](?:gpt-3\.5-turbo|text-davinci-003|claude-1)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8023,
            type: 'SECURITY',
            title: "LLM-SEC-23: Unchecked Fallback to Less Capable or Deprecated Model",
            severity: 'MEDIUM',
            category: "Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Fallback to Less Capable or Deprecated Model: Silent fallback from strong reasoning models to weak models without user notification, compromising safety guarantees."
            ],
            remediationPrompt: "Notify users and log audit warnings if fallback to a secondary model occurs during high traffic.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-23 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-24: Insecure Prompt Template String Interpolation (Prompt Injection)
    if (/messages:\s*\[[\s\S]*?content:\s*`[^`]*\$\{req\.body\.[a-zA-Z0-9_]+\}[^`]*`/i.test(cleanContent) && !/sanitize|escapePrompt/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/messages:\s*\[[\s\S]*?content:\s*`[^`]*\$\{req\.body\.[a-zA-Z0-9_]+\}[^`]*`/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8024,
            type: 'SECURITY',
            title: "LLM-SEC-24: Insecure Prompt Template String Interpolation (Prompt Injection)",
            severity: 'HIGH',
            category: "Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Prompt Template String Interpolation (Prompt Injection): Building prompts via raw string template literals (`User says: ${userInput}`) without escaping prompt boundary markers."
            ],
            remediationPrompt: "Replace string interpolation in prompts with structured chat message objects provided by SDKs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-24 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-25: Poisoned Embedding Generation via Unsanitized Unicode Characters
    if (/embedText|generateEmbedding/i.test(cleanContent) && !/normalize\s*\(\s*["\']NFKC["\']\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/embedText|generateEmbedding/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8025,
            type: 'SECURITY',
            title: "LLM-SEC-25: Poisoned Embedding Generation via Unsanitized Unicode Characters",
            severity: 'MEDIUM',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Poisoned Embedding Generation via Unsanitized Unicode Characters: Injecting zero-width spaces, bidi overrides, or homoglyphs into text embeddings to bypass similarity search filters."
            ],
            remediationPrompt: "Apply Unicode normalization (str.normalize('NFKC')) and strip invisible control characters prior to embedding.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-25 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-26: Missing Egress Traffic Control on AI Agent Execution Nodes
    if (/agentWorker|agentRunner/i.test(cleanContent) && !/allowedDomains|networkPolicy/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/agentWorker|agentRunner/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8026,
            type: 'SECURITY',
            title: "LLM-SEC-26: Missing Egress Traffic Control on AI Agent Execution Nodes",
            severity: 'CRITICAL',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Egress Traffic Control on AI Agent Execution Nodes: Autonomous agents permitted unrestricted outbound Internet access, enabling data exfiltration via DNS or HTTP."
            ],
            remediationPrompt: "Apply outbound firewall rules restricting agent worker nodes to authorized API endpoints only.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-26 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-27: Unverified Third-Party Plugin Manifests in Agent Ecosystems
    if (/fetchPluginManifest|loadAgentPlugin/i.test(cleanContent) && /http:\/\//i.test(cleanContent) && !/sha256|verifySignature/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fetchPluginManifest|loadAgentPlugin/i, /http:\/\//i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8027,
            type: 'SECURITY',
            title: "LLM-SEC-27: Unverified Third-Party Plugin Manifests in Agent Ecosystems",
            severity: 'HIGH',
            category: "Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Third-Party Plugin Manifests in Agent Ecosystems: Loading remote AI plugin OpenAPI manifests or schemas over insecure HTTP without cryptographic signature checks."
            ],
            remediationPrompt: "Verify HTTPS and pin cryptographic checksums for all dynamic plugin manifests consumed by AI agents.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-27 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-28: Prompt Smuggling via Chunk Boundary Exploitation in RAG
    if (/assembleChunks|joinContextChunks/i.test(cleanContent) && !/scanInjection|moderateContext/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/assembleChunks|joinContextChunks/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8028,
            type: 'SECURITY',
            title: "LLM-SEC-28: Prompt Smuggling via Chunk Boundary Exploitation in RAG",
            severity: 'HIGH',
            category: "Prompt Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Prompt Smuggling via Chunk Boundary Exploitation in RAG: Splitting adversarial prompts across document chunks so individual chunks appear benign but reassemble into exploit prompts."
            ],
            remediationPrompt: "Run prompt injection classification on the aggregated retrieved context before passing it to the generator model.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-28 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-29: Lack of User Attribution on AI-Generated Modifications
    if (/applyAiPatch|commitAiChanges/i.test(cleanContent) && !/author|committer|attribution/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/applyAiPatch|commitAiChanges/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8029,
            type: 'SECURITY',
            title: "LLM-SEC-29: Lack of User Attribution on AI-Generated Modifications",
            severity: 'LOW',
            category: "Traceability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of User Attribution on AI-Generated Modifications: Applying AI-generated code or document edits without tagging the responsible user and model revision in git/history."
            ],
            remediationPrompt: "Attach co-pilot attribution metadata and review signatures to all AI-generated file commits.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-29 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-30: Unchecked Self-Modification in Autonomous Coding Agents
    if (/codingAgent|fileEditorTool/i.test(cleanContent) && !/readOnly|protectedFiles/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/codingAgent|fileEditorTool/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8030,
            type: 'SECURITY',
            title: "LLM-SEC-30: Unchecked Self-Modification in Autonomous Coding Agents",
            severity: 'CRITICAL',
            category: "Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Self-Modification in Autonomous Coding Agents: Coding agents possessing file write permissions to their own runtime configuration, system prompts, or security rules."
            ],
            remediationPrompt: "Mount agent configuration files and prompt templates as read-only volumes to prevent runtime tampering.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-30 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-31: Insecure Memory Persistence in Conversational AI Sessions
    if (/redisClient\.set\s*\(\s*["\']chat_history_/i.test(cleanContent) && !/encrypt|aes|cipher/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/redisClient\.set\s*\(\s*["\']chat_history_/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8031,
            type: 'SECURITY',
            title: "LLM-SEC-31: Insecure Memory Persistence in Conversational AI Sessions",
            severity: 'MEDIUM',
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Memory Persistence in Conversational AI Sessions: Storing user chat memories in shared Redis or database instances without encryption-at-rest or tenant namespace keys."
            ],
            remediationPrompt: "Isolate and encrypt conversational memory keys per tenant in Redis with short TTL policies.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-31 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-32: Lack of Multi-Modal Payload Scanning (Adversarial Images/Audio)
    if (/visionModel\.chat|model\.generateContent\s*\([\s\S]*?inlineData/i.test(cleanContent) && !/scanQr|ocrInjectionCheck/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/visionModel\.chat|model\.generateContent\s*\([\s\S]*?inlineData/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8032,
            type: 'SECURITY',
            title: "LLM-SEC-32: Lack of Multi-Modal Payload Scanning (Adversarial Images/Audio)",
            severity: 'HIGH',
            category: "Multi-modal Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Multi-Modal Payload Scanning (Adversarial Images/Audio): Passing user-uploaded images directly to vision LLMs without screening for steganographic text or QR code prompt injections."
            ],
            remediationPrompt: "Pre-screen images with OCR and QR decoders to detect embedded prompt injection payloads.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-32 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-33: Model Cache Poisoning via Unauthenticated Semantic Cache
    if (/semanticCache\.get|cache\.match/i.test(cleanContent) && !/tenantId|userId/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/semanticCache\.get|cache\.match/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8033,
            type: 'SECURITY',
            title: "LLM-SEC-33: Model Cache Poisoning via Unauthenticated Semantic Cache",
            severity: 'HIGH',
            category: "Cache Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Model Cache Poisoning via Unauthenticated Semantic Cache: Sharing semantic cache entries across different tenants or unauthenticated sessions, returning stale or malicious answers."
            ],
            remediationPrompt: "Include tenant_id and authorization hashes in semantic cache lookup keys to prevent cache poisoning.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-33 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-34: Unbounded Parallel LLM Tool Calling (Fan-Out Amplification)
    if (/tool_calls\.map\s*\([\s\S]*?Promise\.all\s*\(/i.test(cleanContent) && !/p-limit|pLimit|concurrency/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/tool_calls\.map\s*\([\s\S]*?Promise\.all\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8034,
            type: 'SECURITY',
            title: "LLM-SEC-34: Unbounded Parallel LLM Tool Calling (Fan-Out Amplification)",
            severity: 'HIGH',
            category: "DoS & Resources",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Parallel LLM Tool Calling (Fan-Out Amplification): Model returning 100+ parallel tool call suggestions executed concurrently without throttling, crashing backend services."
            ],
            remediationPrompt: "Enforce a strict concurrency cap (max 5) on parallel tool call executions returned by LLMs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-34 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-35: Unsanitized Regex Compilation from LLM Structured Output
    if (/new\s+RegExp\s*\(\s*(?:llmOutput|toolResult|aiGeneratedPattern)\s*\)/i.test(cleanContent) && !/safe-regex|isSafeRegex/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+RegExp\s*\(\s*(?:llmOutput|toolResult|aiGeneratedPattern)\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8035,
            type: 'SECURITY',
            title: "LLM-SEC-35: Unsanitized Regex Compilation from LLM Structured Output",
            severity: 'HIGH',
            category: "ReDoS / Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsanitized Regex Compilation from LLM Structured Output: Compiling regular expression strings generated by an LLM directly into RegExp() without catastrophic backtracking analysis."
            ],
            remediationPrompt: "Validate all AI-generated regex patterns with a safe-regex analyzer before passing to RegExp constructor.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-35 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-36: Unchecked Recursive Agent Spawning (Fork Bomb Hazard)
    if (/spawnSubagent|invokeSubagent/i.test(cleanContent) && !/maxDepth|depth\s*<=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/spawnSubagent|invokeSubagent/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8036,
            type: 'SECURITY',
            title: "LLM-SEC-36: Unchecked Recursive Agent Spawning (Fork Bomb Hazard)",
            severity: 'CRITICAL',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Recursive Agent Spawning (Fork Bomb Hazard): Agents authorized to spawn subagents without a global thread depth counter, triggering agentic fork bombs."
            ],
            remediationPrompt: "Track subagent recursion depth with a parent context header and reject subagent spawns exceeding depth 2.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-36 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-37: Missing Guardrail Verification on Code Refactoring Output
    if (/mergeAiRefactoredCode/i.test(cleanContent) && !/runTests|npm test/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/mergeAiRefactoredCode/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8037,
            type: 'SECURITY',
            title: "LLM-SEC-37: Missing Guardrail Verification on Code Refactoring Output",
            severity: 'HIGH',
            category: "Code Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Guardrail Verification on Code Refactoring Output: Applying AI code refactoring without executing automated regression tests or AST semantic comparison."
            ],
            remediationPrompt: "Trigger automated test runs immediately following AI code generation to catch regressions before deployment.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-37 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-38: Direct Database Connection Strings in Agent Tool Environment
    if (/defineAgentTools|registerTools/i.test(cleanContent) && /DATABASE_URL|postgres:\/\/|mysql:\/\//i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/defineAgentTools|registerTools/i, /DATABASE_URL|postgres:\/\/|mysql:\/\//i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8038,
            type: 'SECURITY',
            title: "LLM-SEC-38: Direct Database Connection Strings in Agent Tool Environment",
            severity: 'CRITICAL',
            category: "Secret Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Direct Database Connection Strings in Agent Tool Environment: Passing raw master database credentials into agent execution context rather than scoped read-only query APIs."
            ],
            remediationPrompt: "Replace direct DB connection strings in agent tools with scoped, read-only REST or GraphQL API endpoints.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-38 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-39: Unverified Markdown Hyperlink Rendering in AI Chat UI
    if (/<ReactMarkdown[\s\S]*?components\s*=\s*\{(?![^}]*rel:\s*["\']noopener)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<ReactMarkdown[\s\S]*?components\s*=\s*\{(?![^}]*rel:\s*["\']noopener)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8039,
            type: 'SECURITY',
            title: "LLM-SEC-39: Unverified Markdown Hyperlink Rendering in AI Chat UI",
            severity: 'HIGH',
            category: "Phishing & Fraud",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Markdown Hyperlink Rendering in AI Chat UI: Rendering arbitrary external markdown hyperlinks generated by AI without safety warning or redirect confirmation."
            ],
            remediationPrompt: "Render external markdown links with warning badges and prompt user confirmation before navigating.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-39 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-40: Missing Differential Token Budgeting Across Subscription Tiers
    if (/model:\s*["\'](?:o1|o1-preview|claude-3-opus)["\']/i.test(cleanContent) && !/isPro|isEnterprise|tier\s*===/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/model:\s*["\'](?:o1|o1-preview|claude-3-opus)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8040,
            type: 'SECURITY',
            title: "LLM-SEC-40: Missing Differential Token Budgeting Across Subscription Tiers",
            severity: 'MEDIUM',
            category: "FinOps & Billing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Differential Token Budgeting Across Subscription Tiers: Allowing Free tier users unlimited access to costly reasoning models (o1, Opus) without strict quota walls."
            ],
            remediationPrompt: "Gate high-tier models behind active Pro/Enterprise subscription checks and deduct token balances per request.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-40 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-41: Lack of Adversarial Red-Teaming for Custom System Prompts
    if (/systemPrompts\.json|prompts\/main\.ts/i.test(file.path) && !/promptfoo|garak/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-41|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8041,
            type: 'SECURITY',
            title: "LLM-SEC-41: Lack of Adversarial Red-Teaming for Custom System Prompts",
            severity: 'MEDIUM',
            category: "Model Evaluation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Adversarial Red-Teaming for Custom System Prompts: Deploying customer-facing AI agents without running automated prompt injection regression benchmarks (Garak / Promptfoo)."
            ],
            remediationPrompt: "Integrate automated red-team test suites into CI to validate prompt robustness on every commit.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-41 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-42: Insecure LLM Streaming Connection Without Heartbeat
    if (!file.path.includes('live-deployment/bundle-') && /new\s+ReadableStream\s*\(\{[\s\S]*?pull\s*\(/i.test(cleanContent) && !/req\.signal\.addEventListener\s*\(\s*["\']abort["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+ReadableStream\s*\(\{[\s\S]*?pull\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8042,
            type: 'SECURITY',
            title: "LLM-SEC-42: Insecure LLM Streaming Connection Without Heartbeat",
            severity: 'LOW',
            category: "Connection Stability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure LLM Streaming Connection Without Heartbeat: Server-sent events (SSE) streaming connections without client disconnect listeners, causing zombie LLM generation costs."
            ],
            remediationPrompt: "Attach abort listeners to request signals to terminate upstream model streaming when users close the connection.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-42 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-43: Unchecked Automated Email or Slack Dispatch by AI Agents
    if (/agentDispatchEmail|sendAutonomousSlack/i.test(cleanContent) && !/reviewQueue|isApproved/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/agentDispatchEmail|sendAutonomousSlack/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8043,
            type: 'SECURITY',
            title: "LLM-SEC-43: Unchecked Automated Email or Slack Dispatch by AI Agents",
            severity: 'HIGH',
            category: "Social Engineering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Automated Email or Slack Dispatch by AI Agents: Autonomous agents sending external communications without staging reviews, creating spear-phishing risks."
            ],
            remediationPrompt: "Stage all outbound communications in a review queue requiring explicit operator approval before sending.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-43 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-44: Lack of Deterministic Schema Enforcement on JSON Outputs
    if (/JSON\.parse\s*\(\s*(?:completion|text|rawJson)\s*\)/i.test(cleanContent) && !/zod|schema\.parse/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/JSON\.parse\s*\(\s*(?:completion|text|rawJson)\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8044,
            type: 'SECURITY',
            title: "LLM-SEC-44: Lack of Deterministic Schema Enforcement on JSON Outputs",
            severity: 'HIGH',
            category: "Schema Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Deterministic Schema Enforcement on JSON Outputs: Consuming LLM JSON completions using loose parsing (JSON.parse) without validating against a strict Zod schema."
            ],
            remediationPrompt: "Validate all parsed LLM JSON responses with strict Zod schema definitions before using object properties.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-44 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-45: Missing IP Reputation Screening on Public AI Chat Endpoints
    if (/app\/api\/public-chat\/route\.(?:ts|js)$/i.test(file.path) && !/turnstile|cf-ray|rateLimit/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-45|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8045,
            type: 'SECURITY',
            title: "LLM-SEC-45: Missing IP Reputation Screening on Public AI Chat Endpoints",
            severity: 'HIGH',
            category: "Bot & Abuse Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing IP Reputation Screening on Public AI Chat Endpoints: Public AI completion endpoints accessible without Cloudflare Turnstile, CAPTCHA, or IP reputation filtering."
            ],
            remediationPrompt: "Add Cloudflare Turnstile verification or CAPTCHA gating on public unauthenticated AI chat endpoints.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-45 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-46: Unencrypted Ephemeral Scratchpad Files in Agent Containers
    if (/fs\.writeFileSync\s*\(\s*["\']\/tmp\/agent_/i.test(cleanContent) && !/encrypt|tmpfs/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fs\.writeFileSync\s*\(\s*["\']\/tmp\/agent_/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8046,
            type: 'SECURITY',
            title: "LLM-SEC-46: Unencrypted Ephemeral Scratchpad Files in Agent Containers",
            severity: 'MEDIUM',
            category: "Data Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unencrypted Ephemeral Scratchpad Files in Agent Containers: Storing intermediate agent thoughts, code snippets, or API tokens in unencrypted /tmp scratchpad directories."
            ],
            remediationPrompt: "Use ephemeral tmpfs in-memory mounts for agent scratchpads and wipe them on execution teardown.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-46 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-47: Unconstrained Search Depth in Web-Browsing AI Agents
    if (/crawlWebTool|browsePageTool/i.test(cleanContent) && !/maxDepth|maxHops/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/crawlWebTool|browsePageTool/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8047,
            type: 'SECURITY',
            title: "LLM-SEC-47: Unconstrained Search Depth in Web-Browsing AI Agents",
            severity: 'HIGH',
            category: "Network / Abuse",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unconstrained Search Depth in Web-Browsing AI Agents: Browsing agents traversing arbitrary internal or external web links without crawl depth and domain boundaries."
            ],
            remediationPrompt: "Enforce maximum crawl depth limits and block internal IP addresses in web browsing agent tools.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-47 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-48: Missing Token Truncation Warning on Large Document Summarization
    if (/slice\s*\(\s*0\s*,\s*(?:4000|8000|16000)\s*\)/i.test(cleanContent) && !/warning|truncated/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/slice\s*\(\s*0\s*,\s*(?:4000|8000|16000)\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8048,
            type: 'SECURITY',
            title: "LLM-SEC-48: Missing Token Truncation Warning on Large Document Summarization",
            severity: 'LOW',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Token Truncation Warning on Large Document Summarization: Silently slicing documents exceeding model context window without notifying user that input was truncated."
            ],
            remediationPrompt: "Warn users explicitly in the UI when long documents are truncated before summarization.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-48 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-49: Lack of Seed Determinism in Critical Regulatory Calculations
    if (/runComplianceAuditModel|evaluateRegulatoryRisk/i.test(cleanContent) && /temperature:\s*(?:0\.[3-9]|1\.)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/runComplianceAuditModel|evaluateRegulatoryRisk/i, /temperature:\s*(?:0\.[3-9]|1\.)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8049,
            type: 'SECURITY',
            title: "LLM-SEC-49: Lack of Seed Determinism in Critical Regulatory Calculations",
            severity: 'MEDIUM',
            category: "Reproducibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Seed Determinism in Critical Regulatory Calculations: Running compliance and regulatory assessment agents with non-zero temperature and unseeded random states."
            ],
            remediationPrompt: "Set temperature to 0.0 and specify a fixed seed for all AI workflows producing regulatory audit findings.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-49 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-50: Unrestricted Model Fine-Tuning Dataset Uploads
    if (/app\/api\/.*(?:upload-dataset|dataset-upload)/i.test(file.path) && !/validateJsonl|scanDataset/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-50|unrestricted/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8050,
            type: 'SECURITY',
            title: "LLM-SEC-50: Unrestricted Model Fine-Tuning Dataset Uploads",
            severity: 'CRITICAL',
            category: "Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unrestricted Model Fine-Tuning Dataset Uploads: Allowing direct upload of fine-tuning JSONL files without JSON schema and malware/PII scanning."
            ],
            remediationPrompt: "Scan fine-tuning JSONL datasets line-by-line for valid schema structure and sensitive data before training.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 CRITICAL: LLM-SEC-50 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-51: Missing Fallback for Cloud Model Outages (Circuit Breaker)
    if (/callPrimaryLlmProvider/i.test(cleanContent) && !/circuitBreaker|fallbackProvider/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/callPrimaryLlmProvider/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec51-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8051,
            type: 'SECURITY',
            title: "LLM-SEC-51: Missing Fallback for Cloud Model Outages (Circuit Breaker)",
            severity: 'HIGH',
            category: "High Availability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-51 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Fallback for Cloud Model Outages (Circuit Breaker): Failing to implement an automated circuit breaker when primary LLM provider responds with 500/529 errors."
            ],
            remediationPrompt: "Wrap model client calls in a circuit breaker to switch providers automatically during upstream outages.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-51 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-52: Insecure Storage of Model Evaluation Golden Datasets
    if (/public\/datasets\/golden-eval/i.test(file.path) && !/\.gitkeep/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/llm-sec-52|insecure/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec52-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8052,
            type: 'SECURITY',
            title: "LLM-SEC-52: Insecure Storage of Model Evaluation Golden Datasets",
            severity: 'MEDIUM',
            category: "Data Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-52 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Storage of Model Evaluation Golden Datasets: Storing benchmark evaluation datasets in public GitHub repositories without access controls."
            ],
            remediationPrompt: "Store proprietary golden test datasets in private repositories with restricted read access.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-52 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-53: Prompt Leakage via Error Stack Traces and Verbose 500 Responses
    if (/catch\s*\(\s*err\s*\)\s*\{[\s\S]*?NextResponse\.json\s*\(\s*\{[\s\S]*?(?:prompt|systemPrompt|messages):/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/catch\s*\(\s*err\s*\)\s*\{[\s\S]*?NextResponse\.json\s*\(\s*\{[\s\S]*?(?:prompt|systemPrompt|messages):/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec53-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8053,
            type: 'SECURITY',
            title: "LLM-SEC-53: Prompt Leakage via Error Stack Traces and Verbose 500 Responses",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-53 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Prompt Leakage via Error Stack Traces and Verbose 500 Responses: Catch blocks dumping full LLM prompt, context array, or API request parameters into public HTTP responses."
            ],
            remediationPrompt: "Ensure API catch blocks do not echo prompt contents or internal system parameters in error responses.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-53 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-54: Unchecked Recursive Summarization Drifts (Telephone Effect)
    if (/summarizeRecursive|chainSummarize/i.test(cleanContent) && !/cosineSimilarity|driftCheck/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/summarizeRecursive|chainSummarize/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec54-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8054,
            type: 'SECURITY',
            title: "LLM-SEC-54: Unchecked Recursive Summarization Drifts (Telephone Effect)",
            severity: 'LOW',
            category: "Content Quality",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-54 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Recursive Summarization Drifts (Telephone Effect): Feeding summaries into successive summary prompts recursively without comparing back to source truth."
            ],
            remediationPrompt: "Compare final summary embeddings against the original document to ensure core facts remain accurate.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-54 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-55: Missing Cost Budget Alerts on Enterprise LLM API Keys
    if (/llmClientConfig|aiProviderSetup/i.test(cleanContent) && !/budgetAlert|costLimit/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/llmClientConfig|aiProviderSetup/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec55-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8055,
            type: 'SECURITY',
            title: "LLM-SEC-55: Missing Cost Budget Alerts on Enterprise LLM API Keys",
            severity: 'MEDIUM',
            category: "FinOps",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-55 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Cost Budget Alerts on Enterprise LLM API Keys: Operating production API keys without hard spending limits and automated billing alert webhooks."
            ],
            remediationPrompt: "Set hard spending limits and webhook alerts on OpenAI and Anthropic provider accounts.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-55 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-56: Insecure Dynamic Model Selection via User Input
    if (/model:\s*req\.(?:body|json)\.model\b/i.test(cleanContent) && !/ALLOWED_MODELS|validModels|whitelist/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/model:\s*req\.(?:body|json)\.model\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec56-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8056,
            type: 'SECURITY',
            title: "LLM-SEC-56: Insecure Dynamic Model Selection via User Input",
            severity: 'HIGH',
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-56 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Dynamic Model Selection via User Input: Allowing clients to pass arbitrary model names ('model: req.body.model') directly to the SDK without whitelisting."
            ],
            remediationPrompt: "Whitelist allowed model strings on the server; reject arbitrary model names passed in request bodies.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-56 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-57: Uncontrolled Autonomous File Renaming or Workspace Reorganization
    if (/fs\.(?:rename|rmdir|rmSync)\s*\([\s\S]*?agentInput/i.test(cleanContent) && !/requireConfirmation/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fs\.(?:rename|rmdir|rmSync)\s*\([\s\S]*?agentInput/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec57-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8057,
            type: 'SECURITY',
            title: "LLM-SEC-57: Uncontrolled Autonomous File Renaming or Workspace Reorganization",
            severity: 'HIGH',
            category: "Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-57 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Uncontrolled Autonomous File Renaming or Workspace Reorganization: Agent allowed to rename, move, or delete directories across the repository without user preview diff."
            ],
            remediationPrompt: "Require interactive confirmation before allowing agents to execute batch file moves or directory deletions.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 HIGH: LLM-SEC-57 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-58: Missing LLM System Prompt Versioning in Version Control
    if (/db\.(?:system_prompts|prompts)\.update\s*\(/i.test(cleanContent) && !/auditLog|gitRevision/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/db\.(?:system_prompts|prompts)\.update\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec58-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8058,
            type: 'SECURITY',
            title: "LLM-SEC-58: Missing LLM System Prompt Versioning in Version Control",
            severity: 'LOW',
            category: "Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-58 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing LLM System Prompt Versioning in Version Control: Editing system prompts in production databases or dashboard UIs without git commit tracking and peer reviews."
            ],
            remediationPrompt: "Store all prompt templates in git-tracked files with mandatory peer review before deployment.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-58 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-59: Lack of Grounding Metadata in RAG Search Results
    if (/formatRagResponse/i.test(cleanContent) && !/citations|sources|references/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/formatRagResponse/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec59-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8059,
            type: 'SECURITY',
            title: "LLM-SEC-59: Lack of Grounding Metadata in RAG Search Results",
            severity: 'MEDIUM',
            category: "Trust & Transparency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-59 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Grounding Metadata in RAG Search Results: Returning AI answers without specific document citations, line numbers, or source URLs."
            ],
            remediationPrompt: "Attach source document titles, chunk IDs, and citation links to all RAG-generated answers.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-59 finding in ${file.path}:${lineNum}`);
    }
    // LLM-SEC-60: Unchecked High-Frequency Polling of AI Job Status Endpoints
    if (/setInterval\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[\s\S]*?fetch\s*\(\s*["\']\/api\/ai\/status["\']\s*\)[\s\S]*?,\s*(?:100|200|300|400|500)\s*\)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/setInterval\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[\s\S]*?fetch\s*\(\s*["\']\/api\/ai\/status["\']\s*\)[\s\S]*?,\s*(?:100|200|300|400|500)\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec60-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8060,
            type: 'SECURITY',
            title: "LLM-SEC-60: Unchecked High-Frequency Polling of AI Job Status Endpoints",
            severity: 'LOW',
            category: "API & Resource Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected LLM-SEC-60 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked High-Frequency Polling of AI Job Status Endpoints: Frontend components polling /api/ai/status in tight loops (<500ms) without exponential backoff or WebSockets."
            ],
            remediationPrompt: "Replace rapid short-polling with Server-Sent Events or WebSockets for real-time AI job status updates.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-60 finding in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
