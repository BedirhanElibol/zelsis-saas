/**
 * Zelsis Master evaluateAiSafetyRules Engine (60 Rules)
 * Rules LLM-SEC-01 to LLM-SEC-60 (Rule IDs 8001 to 8060).
 * Removed as unsound (ids never reused): 8010 8014 8015 8018 8022 8023 8025 8029 8031 8039 8040 8041
 * 8042 8044 8046 8048 8049 8052 8054 8055 8058 8059 8060 (made-up names, line-1, absence-of-X).
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
    return { findings, logs };
}
