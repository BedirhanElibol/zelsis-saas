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
    // LLM-SEC-04: Unsanitized LLM Output Rendered as Raw HTML / Stored XSS
    // Model output (directly or via a markdown-to-HTML call) rendered as raw HTML in a file that talks to an LLM
    const llmHtmlSink = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?:(?:marked(?:\.parse)?|md\.render|markdownToHtml)\(\s*)?(?:completion|llmOutput|aiResponse|answer|response\.text|(?:m|msg|message)\.content)\b/;
    const llm04Line = /useChat|useCompletion|@ai-sdk|from\s+['"]ai(?:\/react)?['"]|openai|anthropic/i.test(cleanContent)
        ? cleanContent.split('\n').findIndex((l) => llmHtmlSink.test(l)) : -1;
    if (llm04Line !== -1) {
        const matchLineIdx = llm04Line;
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
    // LLM-SEC-08: Insecure Deserialization of ML Weights (Pickle / PyTorch)
    // Per call: pickle.load(s) always, torch.load unless that call passes weights_only=True
    const llm08Line = /\.py$/i.test(file.path)
        ? lines.findIndex((l) => !l.trim().startsWith('#') && (/\bpickle\.loads?\s*\(/.test(l) || (/\btorch\.load\s*\(/.test(l) && !/weights_only\s*=\s*True/.test(l))))
        : -1;
    if (llm08Line !== -1) {
        const matchLineIdx = llm08Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8008,
            type: 'SECURITY',
            title: "LLM-SEC-08: Insecure Deserialization of ML Weights (Pickle / PyTorch)",
            severity: 'MEDIUM',
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
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-08 finding in ${file.path}:${lineNum}`);
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
    // LLM-SEC-17: Hardcoded Model Provider API Keys in Client-Side Bundles
    // A provider key under a client-exposed env prefix is inlined into the browser bundle (definition or use)
    const publicLlmKey = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_(?:OPENAI|ANTHROPIC|GROQ|MISTRAL|GEMINI|GOOGLE_AI|COHERE|DEEPSEEK|OPENROUTER)_API_KEY\b/;
    const llm17Line = cleanContent.split('\n').findIndex((l) => !l.trim().startsWith('#') && publicLlmKey.test(l));
    if (llm17Line !== -1) {
        const matchLineIdx = llm17Line;
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
    // LLM-SEC-39: Unverified Markdown Hyperlink Rendering in AI Chat UI
    if (/<ReactMarkdown[\s\S]*?components\s*=\s*\{(?![^}]*rel:\s*["\']noopener)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<ReactMarkdown[\s\S]*?components\s*=\s*\{(?![^}]*rel:\s*["\']noopener)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `llmsec39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8039,
            type: 'SECURITY',
            title: "LLM-SEC-39: Unverified Markdown Hyperlink Rendering in AI Chat UI",
            severity: 'LOW',
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
        logs.push(`[${ts}] 🤖 LOW: LLM-SEC-39 finding in ${file.path}:${lineNum}`);
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
            severity: 'MEDIUM',
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
        logs.push(`[${ts}] 🤖 MEDIUM: LLM-SEC-56 finding in ${file.path}:${lineNum}`);
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
