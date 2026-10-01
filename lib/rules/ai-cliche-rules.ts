/**
 * AI Web Design Cliché Detection Rules (25 Rules)
 * Source: ai_web_design_cliches.pdf
 *
 * Detects common AI-generated UI/UX anti-patterns in frontend code
 * and provides professional remediation guidance.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
interface ClicheRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateAiClicheRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ClicheRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    // Only evaluate frontend component files
    const isFrontend = file.path.endsWith('.tsx') || file.path.endsWith('.jsx') || file.path.endsWith('.html') || file.path.endsWith('.css');
    if (!isFrontend)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // CLICHE-01: Decorative Hero Badge Pill & AI Landing Slop
    const isHeroOrLandingScope = /hero|landing/i.test(file.path);
    let pillBadgeLineIdx = -1;
    if (isHeroOrLandingScope) {
        for (let i = 0; i < lines.length; i++) {
            const l = lines[i];
            if (/inline-flex/i.test(l) && /rounded-(?:full|md)/i.test(l) && /border/i.test(l)) {
                const block = lines.slice(i, Math.min(lines.length, i + 7)).join(' ');
                if (/rounded-full.*bg-(?:emerald|green|blue|purple|amber|indigo)-/i.test(block) || /\|\s*<span/i.test(block) || (/\|/i.test(block) && /text-zinc/i.test(block)) || /(?:✨|🚀|Introducing|Powered by AI|Live Status|Early Access)\b/i.test(block) || /\/\/\s*[A-Z]{3,}/.test(block) || /[➔→]|->/.test(block)) {
                    pillBadgeLineIdx = i;
                    break;
                }
            }
        }
    }
    if (pillBadgeLineIdx !== -1) {
        const lineNum = pillBadgeLineIdx + 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 201,
            type: 'VIBEPOLISH',
            title: 'CLICHE-01: Decorative Floating Hero Pill Badge (AI Slop Anti-Pattern)',
            severity: 'MEDIUM',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[pillBadgeLineIdx]?.trim() || '<div className="inline-flex rounded-full border...">',
            reproductionSteps: [
                `Scanned hero section in ${file.path}:${lineNum}.`,
                'Detected decorative floating pill badge with status dots, pipe separators, pseudo-terminal syntax, or pulse animations placed above H1 headline — the #1 hallmark of AI-generated landing pages.'
            ],
            remediationPrompt: `Remove decorative floating hero pill badge in ${file.path}. Modern developer tools (e.g. Linear, Vercel, Stripe) establish clear typographical authority directly with the primary headline without floating status pills.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-01: Hero badge pill slop detected (${file.path}:${lineNum})`);
    }
    // CLICHE-02: Paired Dual CTA Buttons in Hero
    if (/hero|landing/i.test(file.path) && ((/Get Started|Start Free/i.test(cleanContent) && /Watch Demo|Learn More/i.test(cleanContent)) || (/btn-primary|variant.*primary/i.test(cleanContent) && /btn-secondary|btn-outline|variant.*outline|variant.*secondary/i.test(cleanContent)))) {
        const matchLineIdx = lines.findIndex(l => /Get Started|Start Free|Watch Demo/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 202,
            type: 'VIBEPOLISH',
            title: 'CLICHE-02: Paired Dual CTA Buttons in Hero',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Button>Get Started</Button> <Button variant="outline">Watch Demo</Button>',
            reproductionSteps: [
                `Scanned hero section in ${file.path}:${lineNum}.`,
                'Detected paired primary + outline CTA buttons — standard AI-generated dual button pattern.'
            ],
            remediationPrompt: `Simplify hero in ${file.path} to a single strong CTA. If a secondary action is needed, move it below the fold or into navigation.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-02: Dual CTA hero buttons detected (${file.path}:${lineNum})`);
    }
    // CLICHE-03: "No Credit Card Required" Micro-Copy Cliché
    if (/no credit card|no card required/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /no credit card|no card required/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 203,
            type: 'VIBEPOLISH',
            title: 'CLICHE-03: "No Credit Card Required" Micro-Copy Cliché',
            severity: 'LOW',
            category: 'AI Cliché & Copywriting',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'No credit card required',
            reproductionSteps: [
                `Scanned trust copy in ${file.path}:${lineNum}.`,
                'Detected generic "No credit card required" micro-copy — copy-paste AI filler.'
            ],
            remediationPrompt: `Replace generic trust statement in ${file.path} with specific differentiating value (e.g., "14-day free trial", "Cancel anytime").`,
            status: 'OPEN',
            owner: 'Copywriter',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-03: "No credit card" filler copy detected (${file.path}:${lineNum})`);
    }
    // CLICHE-04: Full-Screen 100vh Hero Lock
    if (/h-screen|min-h-screen|height:\s*100vh/i.test(cleanContent) && /hero|landing|home/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => /h-screen|min-h-screen|100vh/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 204,
            type: 'VIBEPOLISH',
            title: 'CLICHE-04: Full-Screen 100vh Hero Lock (Missing Scroll Peek)',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'className="min-h-screen"',
            reproductionSteps: [
                `Scanned hero layout in ${file.path}:${lineNum}.`,
                'Detected forced 100vh full-screen hero blocking scroll peek — user cannot sense content below.'
            ],
            remediationPrompt: `Allow below-fold content to peek by reducing hero height in ${file.path} to ~85vh or adding a scroll indicator.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-04: 100vh hero lock detected (${file.path}:${lineNum})`);
    }
    // CLICHE-05: Floating 3D Perspective Device Mockup
    if (/(?:mockup|device|screenshot)[\s\S]{0,300}?(?:perspective|rotate[XYZ]|rotate3d|skew[XY]?|transform.*3d)|(?:perspective|rotate[XYZ]|rotate3d|skew[XY]?|transform.*3d)[\s\S]{0,300}?(?:mockup|device|screenshot)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /perspective|rotate[XYZ]|rotate3d|skew|transform.*3d/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 205,
            type: 'VIBEPOLISH',
            title: 'CLICHE-05: Floating 3D Perspective Device Mockup',
            severity: 'LOW',
            category: 'AI Cliché & Visual',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'transform: perspective(1000px) rotateY(-15deg)',
            reproductionSteps: [
                `Scanned visual presentation in ${file.path}:${lineNum}.`,
                'Detected 3D tilted/perspective mockup — an AI-generated decorative anti-pattern.'
            ],
            remediationPrompt: `Replace 3D perspective mockup in ${file.path} with flat, readable real product screenshots that reflect actual user experience.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-05: 3D tilted mockup detected (${file.path}:${lineNum})`);
    }
    // CLICHE-06: Fake Browser Chrome Window Decoration
    if (/browser-?chrome|browser-?frame|red.*yellow.*green|dot.*dot.*dot.*mockup|fake.*browser/i.test(cleanContent) || (cleanContent.includes('bg-red-') && cleanContent.includes('bg-yellow-') && cleanContent.includes('bg-green-') && /rounded-full.*w-3|w-3.*rounded-full/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => /browser-?chrome|bg-red-.*bg-yellow-|rounded-full.*w-3/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 206,
            type: 'VIBEPOLISH',
            title: 'CLICHE-06: Fake Browser Chrome Window Decoration',
            severity: 'LOW',
            category: 'AI Cliché & Visual',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<div className="flex gap-1"><span className="w-3 h-3 rounded-full bg-red-500" />...',
            reproductionSteps: [
                `Scanned visual frame elements in ${file.path}:${lineNum}.`,
                'Detected fake browser chrome (red/yellow/green dots) decoration — adds visual noise without value.'
            ],
            remediationPrompt: `Remove fake browser frame in ${file.path}. Show clean product UI directly without decorative chrome.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-06: Fake browser chrome detected (${file.path}:${lineNum})`);
    }
    // CLICHE-07: Fabricated Brand Logos (Nexora, Vertexa, Lumina)
    if (/trusted by|as seen on/i.test(cleanContent) && /Nexora|Vertexa|Lumina|Quantiq|Acme|TechCorp|CloudSoft|DataPulse|SynergyAI|CyberVault/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /Nexora|Vertexa|Lumina|Quantiq|Acme|TechCorp/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 207,
            type: 'VIBEPOLISH',
            title: 'CLICHE-07: Fabricated Brand Logos (Fake Trust Proof)',
            severity: 'MEDIUM',
            category: 'AI Cliché & Trust',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '"Trusted by" Nexora, Vertexa, Lumina...',
            reproductionSteps: [
                `Scanned social proof section in ${file.path}:${lineNum}.`,
                'Detected fabricated brand names typically generated by AI — destroys user trust.'
            ],
            remediationPrompt: `Remove fake logos in ${file.path}. Only display real customer/partner logos or focus on product value instead.`,
            status: 'OPEN',
            owner: 'Marketing',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-07: Fake trust logos detected (${file.path}:${lineNum})`);
    }
    // CLICHE-08: Infinite Scrolling Logo Marquee
    if (/marquee|infinite.*scroll.*logo|logo.*marquee|scroll.*infinite|animate-scroll|animation.*scroll/i.test(cleanContent) && /logo|brand|partner|client/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /marquee|infinite.*scroll|animate-scroll/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 208,
            type: 'VIBEPOLISH',
            title: 'CLICHE-08: Infinite Scrolling Logo Marquee',
            severity: 'LOW',
            category: 'AI Cliché & Animation',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'className="animate-scroll infinite"',
            reproductionSteps: [
                `Scanned logo display section in ${file.path}:${lineNum}.`,
                'Detected infinite marquee logo animation — distracting and non-interactive.'
            ],
            remediationPrompt: `Replace infinite marquee in ${file.path} with a clean static grid of real partner logos.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-08: Infinite logo marquee detected (${file.path}:${lineNum})`);
    }
    // CLICHE-09: Overlapping Stock Avatar Social Proof
    if (/-space-x|avatar.*group|stacked.*avatar|overlapping.*avatar/i.test(cleanContent) && /\d+[\+,.]?\d*\s*(user|people|joined|customers)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /-space-x|avatar.*group|stacked.*avatar/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 209,
            type: 'VIBEPOLISH',
            title: 'CLICHE-09: Overlapping Stock Avatar Social Proof',
            severity: 'LOW',
            category: 'AI Cliché & Trust',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<AvatarGroup> "10,000+ users joined"',
            reproductionSteps: [
                `Scanned social proof in ${file.path}:${lineNum}.`,
                'Detected stacked avatar group with generic user count — stock photo social proof.'
            ],
            remediationPrompt: `Replace stacked stock avatars in ${file.path} with real user testimonials including name, company, and role.`,
            status: 'OPEN',
            owner: 'Marketing',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-09: Stacked avatar social proof detected (${file.path}:${lineNum})`);
    }
    // CLICHE-10: Fabricated Vanity Metrics (10,000+ Users, 99.9% Uptime, 24/7)
    if ((/10[,.]?000\+?\s*(user|customer)/i.test(cleanContent) && /99\.?9%\s*(uptime|availability)/i.test(cleanContent)) || (/10[,.]?000\+/i.test(cleanContent) && /24\/7/i.test(cleanContent) && /uptime|support/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => /10[,.]?000\+|99\.?9%|24\/7/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 210,
            type: 'VIBEPOLISH',
            title: 'CLICHE-10: Fabricated Vanity Metrics (10,000+ Users, 99.9% Uptime, 24/7)',
            severity: 'MEDIUM',
            category: 'AI Cliché & Trust',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '10,000+ Users | 99.9% Uptime | 24/7 Support',
            reproductionSteps: [
                `Scanned statistics section in ${file.path}:${lineNum}.`,
                'Detected the classic AI-generated vanity metric trio (users/uptime/support).'
            ],
            remediationPrompt: `Replace fabricated metrics in ${file.path} with real, verifiable product-specific KPIs and measurable outcomes.`,
            status: 'OPEN',
            owner: 'Marketing',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-10: Fabricated vanity metrics detected (${file.path}:${lineNum})`);
    }
    // CLICHE-11: Count-Up-From-Zero Number Animation
    if (/\b(?:countUp|count-up|useCountUp|CountUp)\b/i.test(cleanContent) || (/\b(?:start|from)\s*[:=]\s*\{?0\}?/i.test(cleanContent) && /\b(?:count|counter|number|stat)\b/i.test(cleanContent) && /\b(?:animate|motion|spring)\b/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => /\b(?:countUp|count-up|useCountUp|CountUp)\b/i.test(l) || (/\b(?:start|from)\s*[:=]\s*\{?0\}?/i.test(l) && /\b(?:count|counter)\b/i.test(l)));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `cliche-${Date.now()}-${findingCounter.count++}`,
                ruleId: 211,
                type: 'VIBEPOLISH',
                title: 'CLICHE-11: Count-Up-From-Zero Number Animation',
                severity: 'LOW',
                category: 'AI Cliché & Animation',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: lines[matchLineIdx] || '<CountUp start={0} end={10000} duration={2} />',
                reproductionSteps: [
                    `Scanned stat animations in ${file.path}:${lineNum}.`,
                    'Detected count-up-from-zero animation — gimmicky AI filler pattern.'
                ],
                remediationPrompt: `Remove count-up animation in ${file.path}. Display numbers directly and clearly without theatrical counting scripts.`,
                status: 'OPEN',
                owner: 'UI Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🎨 CLICHE-11: Count-up animation detected (${file.path}:${lineNum})`);
        }
    }
    // CLICHE-12: Forced 1-2-3 Step "How It Works" Pattern
    if (/how\s*it\s*works/i.test(cleanContent) && /(?:step\s*1|1\b[\s\S]{0,40}?(?:sign\s*up|create|register))[\s\S]{0,1000}?(?:step\s*2|2\b[\s\S]{0,40}?(?:connect|install|setup))[\s\S]{0,1000}?(?:step\s*3|3\b[\s\S]{0,40}?(?:start|launch|deploy|enjoy))/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /how\s*it\s*works/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 212,
            type: 'VIBEPOLISH',
            title: 'CLICHE-12: Forced 1-2-3 Step "How It Works" Pattern',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '"How It Works?" 1. Sign Up 2. Connect 3. Start',
            reproductionSteps: [
                `Scanned process steps in ${file.path}:${lineNum}.`,
                'Detected the forced 3-step "How It Works" layout — an AI template classic.'
            ],
            remediationPrompt: `Redesign process section in ${file.path}. Show the actual unique value-creation flow instead of generic 1-2-3 sign-up steps.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-12: 1-2-3 step pattern detected (${file.path}:${lineNum})`);
    }
    // CLICHE-13: Generic FAQ Accordion with Plus Icons
    if (/accordion|faq/i.test(cleanContent) && (/how does it work|is it secure|can i cancel/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => /accordion|faq/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 213,
            type: 'VIBEPOLISH',
            title: 'CLICHE-13: Generic FAQ Accordion with Plus Icons',
            severity: 'LOW',
            category: 'AI Cliché & Content',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Accordion> "How does it work?" "Is it secure?"',
            reproductionSteps: [
                `Scanned FAQ section in ${file.path}:${lineNum}.`,
                'Detected generic AI-generated FAQ questions that do not address real customer objections.'
            ],
            remediationPrompt: `Replace generic FAQ questions in ${file.path} with real customer purchase-blocking objections and specific technical answers.`,
            status: 'OPEN',
            owner: 'Copywriter',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-13: Generic FAQ accordion detected (${file.path}:${lineNum})`);
    }
    // CLICHE-14: Dark Closing CTA Banner ("Ready to get started?")
    if (/ready to (get started|start|begin)/i.test(cleanContent) && /bg-(black|gray-900|slate-900|zinc-900)|bg-\[#0/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /ready to/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 214,
            type: 'VIBEPOLISH',
            title: 'CLICHE-14: Dark Closing CTA Banner ("Ready to get started?")',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '"Ready to get started?" on dark background',
            reproductionSteps: [
                `Scanned closing CTA in ${file.path}:${lineNum}.`,
                'Detected generic dark-background "Ready to get started?" closing banner.'
            ],
            remediationPrompt: `Strengthen closing CTA in ${file.path} with a specific value proposition, risk reducer, or personalized offer instead of generic "Ready?" text.`,
            status: 'OPEN',
            owner: 'Copywriter',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-14: Dark closing CTA banner detected (${file.path}:${lineNum})`);
    }
    // CLICHE-15: Overloaded Fake Corporate Footer (5 Columns)
    let footerLinks = 0;
    if (/footer/i.test(file.path)) {
        footerLinks = (cleanContent.match(/<a[\s>]|<Link[\s>]/gi) || []).length;
    }
    else {
        const footerMatch = cleanContent.match(/<footer[\s\S]*?<\/footer>/i) || cleanContent.match(/<(?:div|section)[^>]*(?:id|class)=["'][^"']*footer[^"']*["'][\s\S]*?<\/(?:div|section)>/i);
        if (footerMatch) {
            footerLinks = (footerMatch[0].match(/<a[\s>]|<Link[\s>]/gi) || []).length;
        }
    }
    if (footerLinks > 15) {
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 215,
            type: 'VIBEPOLISH',
            title: 'CLICHE-15: Overloaded Fake Corporate Footer (5 Columns)',
            severity: 'LOW',
            category: 'AI Cliché & Navigation',
            filePath: file.path,
            lineRange: 'L1-L50',
            snippet: `Footer contains ${footerLinks} links — likely more than existing pages`,
            reproductionSteps: [
                `Scanned footer in ${file.path}.`,
                `Detected ${footerLinks} footer links — AI-generated sites often create links to pages that do not exist.`
            ],
            remediationPrompt: `Audit footer links in ${file.path}. Only link to pages that actually exist. Use a clean, functional 2-3 column footer.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-15: Overloaded footer (${footerLinks} links) detected (${file.path})`);
    }
    // CLICHE-16: Non-Functional Theme Toggle Button
    if (/dark.*mode.*toggle|theme.*toggle|mode.*switch|setTheme|toggleTheme/i.test(cleanContent) && !/data-theme|classList.*dark|document\.documentElement|ThemeProvider|useTheme/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /dark.*mode|theme.*toggle|toggleTheme/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 216,
            type: 'VIBEPOLISH',
            title: 'CLICHE-16: Non-Functional Theme Toggle Button',
            severity: 'MEDIUM',
            category: 'AI Cliché & Functionality',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<button onClick={toggleDarkMode}>🌙</button>',
            reproductionSteps: [
                `Scanned theme toggle in ${file.path}:${lineNum}.`,
                'Detected dark mode toggle without actual theme infrastructure (ThemeProvider / CSS variables).'
            ],
            remediationPrompt: `Either implement full CSS variable-based theme system or remove non-functional toggle in ${file.path}. Half-implemented toggles erode trust.`,
            status: 'OPEN',
            owner: 'Frontend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-16: Non-functional dark mode toggle detected (${file.path}:${lineNum})`);
    }
    // CLICHE-17: Excessive Center-Alignment (text-center Abuse)
    const centerCount = (cleanContent.match(/text-center|text-align:\s*center/gi) || []).length;
    if (centerCount > 8 && lines.length > 50) {
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 217,
            type: 'VIBEPOLISH',
            title: 'CLICHE-17: Excessive Center-Alignment (text-center Abuse)',
            severity: 'MEDIUM',
            category: 'AI Cliché & Typography',
            filePath: file.path,
            lineRange: 'L1-L50',
            snippet: `${centerCount} center-alignment instances detected in ${lines.length} lines`,
            reproductionSteps: [
                `Scanned text alignment in ${file.path}.`,
                `Detected ${centerCount} center-aligned blocks — AI defaults to center everything, hurting F-pattern readability.`
            ],
            remediationPrompt: `Left-align body text, descriptions, and feature lists in ${file.path} for natural F-pattern reading. Reserve center-align only for hero headlines.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-17: Excessive center-alignment (${centerCount}x) detected (${file.path})`);
    }
    // CLICHE-18: Repetitive 3-Column Card Grid Sections
    const gridSections = (cleanContent.match(/grid-cols-3|grid.*cols.*3/gi) || []).length;
    if (gridSections >= 3) {
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 218,
            type: 'VIBEPOLISH',
            title: 'CLICHE-18: Repetitive 3-Column Card Grid Sections',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: 'L1-L100',
            snippet: `${gridSections} identical 3-column grids repeating in layout`,
            reproductionSteps: [
                `Scanned layout structure in ${file.path}.`,
                `Detected ${gridSections} identical 3-column grid sections — break the visual monotony.`
            ],
            remediationPrompt: `Add visual rhythm to ${file.path}: alternate between 2-column splits, interactive demos, asymmetric grids, and full-width sections.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-18: Repetitive 3-column grid pattern (${gridSections}x) detected (${file.path})`);
    }
    // CLICHE-19: Default Indigo-600 Color Fallback (#4F46E5)
    if (/indigo-600|#4F46E5|#4f46e5|indigo-500/i.test(cleanContent) && !/brand|theme|custom/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /indigo-600|#4F46E5|indigo-500/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 219,
            type: 'VIBEPOLISH',
            title: 'CLICHE-19: Default Indigo-600 Color Fallback (#4F46E5)',
            severity: 'LOW',
            category: 'AI Cliché & Color',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'className="bg-indigo-600"',
            reproductionSteps: [
                `Scanned color usage in ${file.path}:${lineNum}.`,
                'Detected default AI fallback color Indigo-600 (#4F46E5) — a telltale sign of unbranded AI output.'
            ],
            remediationPrompt: `Define a custom brand color palette in ${file.path} instead of defaulting to Indigo-600/Blurple.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-19: Default Indigo-600 color detected (${file.path}:${lineNum})`);
    }
    // CLICHE-20: Monotone Slate-500 Gray Text Overuse (#64748B)
    const slateCount = (cleanContent.match(/slate-500|#64748B|#64748b|text-gray-500/gi) || []).length;
    if (slateCount > 6) {
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 220,
            type: 'VIBEPOLISH',
            title: 'CLICHE-20: Monotone Slate-500 Gray Text Overuse (#64748B)',
            severity: 'LOW',
            category: 'AI Cliché & Color',
            filePath: file.path,
            lineRange: 'L1-L50',
            snippet: `${slateCount} occurrences of Slate-500/#64748B mono-tone gray`,
            reproductionSteps: [
                `Scanned text color hierarchy in ${file.path}.`,
                `Detected ${slateCount} instances of the same gray (#64748B) — AI often uses a single shade for all text.`
            ],
            remediationPrompt: `Establish proper text hierarchy in ${file.path} using multiple font weights, sizes, and varied gray tones instead of flat Slate-500.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-20: Monotone Slate-500 text overuse (${slateCount}x) detected (${file.path})`);
    }
    // CLICHE-21: Forced Fixed-Height Card Containers
    const hasFixedCardContainer = /(?:class(?:Name)?=["'][^"']*\b(?:card|feature|pricing)[^"']*\bh-(?:\[\d+px\]|48|52|56|60|64|72|80)\b)|(?:class(?:Name)?=["'][^"']*\bh-(?:\[\d+px\]|48|52|56|60|64|72|80)\b[^"']*\b(?:card|feature|pricing)[^"']*)/i.test(cleanContent) ||
        /\b(?:card|feature|pricing)\b[\s\S]{0,100}?h-(?:\[\d+px\]|48|52|56|60|64|72|80)\b/i.test(cleanContent);
    if (hasFixedCardContainer) {
        const matchLineIdx = lines.findIndex(l => /(?:class(?:Name)?=["'][^"']*\bh-(?:\[\d+px\]|48|52|56|60|64|72|80)\b)/i.test(l) && /card|feature|pricing/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 221,
            type: 'VIBEPOLISH',
            title: 'CLICHE-21: Forced Fixed-Height Card Containers',
            severity: 'LOW',
            category: 'AI Cliché & Layout',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'className="h-[300px] card"',
            reproductionSteps: [
                `Scanned card layouts in ${file.path}:${lineNum}.`,
                'Detected force-fixed card heights — creates artificial whitespace when content varies.'
            ],
            remediationPrompt: `Allow natural content flow in ${file.path} cards or write balanced content. Use min-height instead of fixed height.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-21: Fixed card heights detected (${file.path}:${lineNum})`);
    }
    // CLICHE-22: Pastel Square Rounded Icon Containers
    if (/rounded-(?:lg|xl|2xl).*(?:bg-(?:blue|green|orange|pink|purple|teal|cyan)-(?:50|100)\b)/i.test(cleanContent) && /lucide|icon|Icon|Feature/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /rounded-.*bg-.*-(?:50|100)\b/i.test(l) && /icon|Icon/i.test(l));
        if (matchLineIdx !== -1) {
            const lineNum = matchLineIdx + 1;
            findings.push({
                id: `cliche-${Date.now()}-${findingCounter.count++}`,
                ruleId: 222,
                type: 'VIBEPOLISH',
                title: 'CLICHE-22: Pastel Square Rounded Icon Containers',
                severity: 'LOW',
                category: 'AI Cliché & Visual',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: lines[matchLineIdx] || '<div className="rounded-xl bg-blue-50 p-3"><Icon /></div>',
                reproductionSteps: [
                    `Scanned feature icon styling in ${file.path}:${lineNum}.`,
                    'Detected pastel-colored rounded square icon containers — standard AI visual pattern.'
                ],
                remediationPrompt: `Replace pastel icon boxes in ${file.path} with real UI screenshots, micro-illustrations, or inline contextual graphics.`,
                status: 'OPEN',
                owner: 'UI Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] 🎨 CLICHE-22: Pastel icon boxes detected (${file.path}:${lineNum})`);
        }
    }
    // CLICHE-23: Generic Faceless Flat Stock Vectors (unDraw)
    if (/undraw|unDraw|illustrations\/undraw|flat.*illustration/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /undraw|unDraw|flat.*illustration/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 223,
            type: 'VIBEPOLISH',
            title: 'CLICHE-23: Generic Faceless Flat Stock Vectors (unDraw)',
            severity: 'LOW',
            category: 'AI Cliché & Visual',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'src="/illustrations/undraw-team.svg"',
            reproductionSteps: [
                `Scanned visual assets in ${file.path}:${lineNum}.`,
                'Detected unDraw-style generic flat vector illustrations — faceless, personality-less stock art.'
            ],
            remediationPrompt: `Replace stock vector illustrations in ${file.path} with real product UI screenshots, actual data visualizations, or custom-designed brand assets.`,
            status: 'OPEN',
            owner: 'Design Team',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-23: Stock flat illustration detected (${file.path}:${lineNum})`);
    }
    // CLICHE-24: Decorative Floating Glassmorphism Blur Orbs
    if (/blur-(?:2xl|3xl)|backdrop-blur|glassmorphism/i.test(cleanContent) && /absolute.*rounded-full|rounded-full.*absolute/i.test(cleanContent) && /bg-(?:purple|blue|pink|cyan|teal)-(?:400|500|600)\/(?:20|30|40|50)|opacity-(?:20|30|40)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /blur-(?:2xl|3xl)|backdrop-blur/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 224,
            type: 'VIBEPOLISH',
            title: 'CLICHE-24: Decorative Floating Glassmorphism Blur Orbs',
            severity: 'LOW',
            category: 'AI Cliché & Visual',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<div className="absolute rounded-full blur-3xl bg-purple-500/30 w-64 h-64" />',
            reproductionSteps: [
                `Scanned decorative elements in ${file.path}:${lineNum}.`,
                'Detected floating glassmorphism blur orbs — AI-generated space-filler with no functional purpose.'
            ],
            remediationPrompt: `Remove floating blur decorations in ${file.path}. Use negative space (whitespace) intentionally as a design element instead.`,
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-24: Floating glassmorphism blur orbs detected (${file.path}:${lineNum})`);
    }
    // CLICHE-25: Stock Photo of Happy Team Looking at Laptop
    if (/stock.*photo|team.*photo|shutterstock|istock|unsplash.*team|pexels.*office|happy.*team/i.test(cleanContent) && /office|laptop|meeting|team/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /stock.*photo|shutterstock|istock|unsplash.*team|happy.*team/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 225,
            type: 'VIBEPOLISH',
            title: 'CLICHE-25: Stock Photo of Happy Team Looking at Laptop',
            severity: 'LOW',
            category: 'AI Cliché & Visual',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'src="/images/happy-team-office.jpg"',
            reproductionSteps: [
                `Scanned visual assets in ${file.path}:${lineNum}.`,
                'Detected generic stock team/office photography — reduces authenticity.'
            ],
            remediationPrompt: `Replace stock team photos in ${file.path} with real founder/team photos, workspace images, or direct product screenshots.`,
            status: 'OPEN',
            owner: 'Marketing',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-25: Stock team photo detected (${file.path}:${lineNum})`);
    }
    // CLICHE-26: Rainbow Animated Conic Gradient Card Borders
    if (/conic-gradient.*(?:red|blue|pink|yellow)|animate-border.*conic|rainbow-border/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/conic-gradient.*(?:red|blue|pink|yellow)|animate-border.*conic|rainbow-border/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 226,
            type: 'VIBEPOLISH',
            title: 'CLICHE-26: Rainbow Animated Conic Gradient Card Borders',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected rainbow-border animation: Continuous spinning conic rainbow border around every feature card"
            ],
            remediationPrompt: "Use subtle solid borders with stateful hover highlights instead of distracting spinning gradients.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-26: Rainbow Animated Conic Gradient Card Borders detected (${file.path}:${lineNum})`);
    }
    // CLICHE-27: Monotonous Matrix Grid Background Overlays
    if (/(?:bg-grid|bg-matrix|radial-gradient\(.*grid).*(?:opacity-10|opacity-20|opacity-5)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:bg-grid|bg-matrix|radial-gradient\(.*grid).*(?:opacity-10|opacity-20|opacity-5)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 227,
            type: 'VIBEPOLISH',
            title: 'CLICHE-27: Monotonous Matrix Grid Background Overlays',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Background",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected monotonous background grid overlay: Dark background blanketed with low-opacity square grid lines and radial spotlight mask"
            ],
            remediationPrompt: "Use purposeful background treatment or generous clean negative space.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-27: Monotonous Matrix Grid Background Overlays detected (${file.path}:${lineNum})`);
    }
    // CLICHE-28: Fabricated "Active Now" Pulsing Ping Dot
    if (/animate-ping.*(?:Users\s*Active|Online\s*Now|Live\s*Users)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/animate-ping.*(?:Users\s*Active|Online\s*Now|Live\s*Users)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 228,
            type: 'VIBEPOLISH',
            title: 'CLICHE-28: Fabricated "Active Now" Pulsing Ping Dot',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected fabricated live pulsing ping dot: Artificial animate-ping green badge indicating \"1,420 Users Active Now\""
            ],
            remediationPrompt: "Show genuine live presence only when backed by real WebSocket / Redis telemetry.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-28: Fabricated "Active Now" Pulsing Ping Dot detected (${file.path}:${lineNum})`);
    }
    // CLICHE-29: Generic Archetype Testimonial Persona Titles
    if (/(?:Tech\s*Enthusiast|Early\s*Adopter|Digital\s*Nomad|Product\s*Guy)\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Tech\s*Enthusiast|Early\s*Adopter|Digital\s*Nomad|Product\s*Guy)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 229,
            type: 'VIBEPOLISH',
            title: 'CLICHE-29: Generic Archetype Testimonial Persona Titles',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected generic testimonial persona title: Testimonials signed by \"Tech Enthusiast\", \"Early Adopter\", or \"Digital Nomad\""
            ],
            remediationPrompt: "Include real customer names, verified LinkedIn handles, and concrete company roles.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-29: Generic Archetype Testimonial Persona Titles detected (${file.path}:${lineNum})`);
    }
    // CLICHE-30: Asymmetric Bento Grid with Empty Filler Cards
    if (/(?:bento-grid|grid-cols-4.*bento).*(?:empty-card|spacer-card|decorative-box)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:bento-grid|grid-cols-4.*bento).*(?:empty-card|spacer-card|decorative-box)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 230,
            type: 'VIBEPOLISH',
            title: 'CLICHE-30: Asymmetric Bento Grid with Empty Filler Cards',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected asymmetric bento grid filler card: Bento grid layout where 2 cards have content and 3 cards have decorative shapes"
            ],
            remediationPrompt: "Select layouts that naturally fit your actual feature set rather than forcing arbitrary grids.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-30: Asymmetric Bento Grid with Empty Filler Cards detected (${file.path}:${lineNum})`);
    }
    // CLICHE-31: Floating Geometric Wireframe Polyhedra
    if (/(?:wireframe-(?:cube|sphere|polyhedron)|floating-(?:shapes|poly))/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:wireframe-(?:cube|sphere|polyhedron)|floating-(?:shapes|poly))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 231,
            type: 'VIBEPOLISH',
            title: 'CLICHE-31: Floating Geometric Wireframe Polyhedra',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected floating wireframe 3D polyhedra: 3D wireframe cubes, spheres, and donuts floating in landing page whitespace"
            ],
            remediationPrompt: "Replace abstract 3D shapes with product interface walkthroughs or data architecture diagrams.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-31: Floating Geometric Wireframe Polyhedra detected (${file.path}:${lineNum})`);
    }
    // CLICHE-32: Artificial Scarcity Countdown Banner
    if (/(?:Only\s*\d+\s*spots?\s*left|Tier\s*closing\s*in\s*\d+|Price\s*increases\s*in\s*\d+)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Only\s*\d+\s*spots?\s*left|Tier\s*closing\s*in\s*\d+|Price\s*increases\s*in\s*\d+)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 232,
            type: 'VIBEPOLISH',
            title: 'CLICHE-32: Artificial Scarcity Countdown Banner',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected artificial scarcity countdown banner: Permanent \"Only 3 spots remaining at this price!\" or recurring 15-minute countdown"
            ],
            remediationPrompt: "Provide honest, predictable pricing without manipulative countdown timers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-32: Artificial Scarcity Countdown Banner detected (${file.path}:${lineNum})`);
    }
    // CLICHE-33: Generic Robot / Brain / Neon Mascot Logo
    if (/header|navbar|logo/i.test(file.path) && /(?:lucide-bot|lucide-brain|robot-mascot|brain-sparkle)\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:lucide-bot|lucide-brain|robot-mascot|brain-sparkle)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 233,
            type: 'VIBEPOLISH',
            title: 'CLICHE-33: Generic Robot / Brain / Neon Mascot Logo',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Branding",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected generic robot/brain mascot logo: Landing page logo consisting of a generic Lucide Bot, Brain, or Sparkles icon in a square"
            ],
            remediationPrompt: "Design a distinctive, purpose-driven brandmark tailored to product identity.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-33: Generic Robot / Brain / Neon Mascot Logo detected (${file.path}:${lineNum})`);
    }
    // CLICHE-34: Arbitrary "Most Popular" Inverted Pricing Card
    if (/(?:scale-110.*popular|scale-105.*most-popular|pricing.*invert.*popular)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:scale-110.*popular|scale-105.*most-popular|pricing.*invert.*popular)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 234,
            type: 'VIBEPOLISH',
            title: 'CLICHE-34: Arbitrary "Most Popular" Inverted Pricing Card',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected arbitrary inverted pricing card: Inverting colors and scaling 1.1x on an enterprise tier with zero rationale"
            ],
            remediationPrompt: "Highlight tiers based on user personas and explain specifically why each tier fits the buyer.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-34: Arbitrary "Most Popular" Inverted Pricing Card detected (${file.path}:${lineNum})`);
    }
    // CLICHE-35: Endless Infinite One-Page Landing Monolith
    if ((cleanContent.match(/<section\b/gi) || []).length > 12) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/cliche-35|endless/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 235,
            type: 'VIBEPOLISH',
            title: 'CLICHE-35: Endless Infinite One-Page Landing Monolith',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected endless 12+ section landing page monolith: Stretching landing page to 14 sprawling sections with repetitive marketing claims"
            ],
            remediationPrompt: "Prioritize information density, clear sub-page routing, and focused user flows.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-35: Endless Infinite One-Page Landing Monolith detected (${file.path}:${lineNum})`);
    }
    // CLICHE-36: Unreadable Frosted Glass over High-Contrast Text
    if (/backdrop-blur-(?:sm|md)\s+bg-white\/5\s+text-white\/30/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/backdrop-blur-(?:sm|md)\s+bg-white\/5\s+text-white\/30/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 236,
            type: 'VIBEPOLISH',
            title: 'CLICHE-36: Unreadable Frosted Glass over High-Contrast Text',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Contrast",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected illegible frosted glass over low contrast: Backdrop-blur cards overlaid directly on busy animated canvas backgrounds"
            ],
            remediationPrompt: "Ensure minimum 4.5:1 WCAG contrast ratio with solid background opacity layers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-36: Unreadable Frosted Glass over High-Contrast Text detected (${file.path}:${lineNum})`);
    }
    // CLICHE-37: Fabricated FAANG Customer Logo Parade
    if (/(?:Trusted\s*by|Used\s*by).*(?:Google|Apple|Meta|Netflix|Microsoft)\s*logos/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Trusted\s*by|Used\s*by).*(?:Google|Apple|Meta|Netflix|Microsoft)\s*logos/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 237,
            type: 'VIBEPOLISH',
            title: 'CLICHE-37: Fabricated FAANG Customer Logo Parade',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected fabricated FAANG customer logo parade: Displaying Google, Meta, and Apple logos with ambiguous \"Works With\" claim"
            ],
            remediationPrompt: "Display verified customer case studies with attributed quotes and direct permission.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-37: Fabricated FAANG Customer Logo Parade detected (${file.path}:${lineNum})`);
    }
    // CLICHE-38: Uniform Rounded-3xl Corner Inflation
    if ((cleanContent.match(/rounded-(?:3xl|\[2rem\]|\[24px\])/gi) || []).length > 8) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/cliche-38|uniform/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 238,
            type: 'VIBEPOLISH',
            title: 'CLICHE-38: Uniform Rounded-3xl Corner Inflation',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected uniform rounded-3xl corner inflation: Applying rounded-3xl or rounded-[2rem] to every container, button, and input box"
            ],
            remediationPrompt: "Adopt a balanced radius hierarchy: smaller radius for micro-elements, structured radius for surfaces.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-38: Uniform Rounded-3xl Corner Inflation detected (${file.path}:${lineNum})`);
    }
    // CLICHE-39: Persistent Sticky Banner Blocking Mobile Viewport
    if (/(?:fixed\s+bottom-0.*fixed\s+top-0.*sticky|sticky\s+top-0.*fixed\s+bottom-0.*cookie)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:fixed\s+bottom-0.*fixed\s+top-0.*sticky|sticky\s+top-0.*fixed\s+bottom-0.*cookie)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 239,
            type: 'VIBEPOLISH',
            title: 'CLICHE-39: Persistent Sticky Banner Blocking Mobile Viewport',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Mobile",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected viewport blocking mobile banner collision: Combining sticky cookie bar, top promo ticker, and bottom CTA taking 45% of screen"
            ],
            remediationPrompt: "Collapse non-critical persistent banners on small viewports to maintain content readability.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-39: Persistent Sticky Banner Blocking Mobile Viewport detected (${file.path}:${lineNum})`);
    }
    // CLICHE-40: Blinding Radial Spotlight Halo Behind Hero Button
    if (/(?:blur-2xl|blur-3xl).*-inset-1.*bg-gradient/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:blur-2xl|blur-3xl).*-inset-1.*bg-gradient/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 240,
            type: 'VIBEPOLISH',
            title: 'CLICHE-40: Blinding Radial Spotlight Halo Behind Hero Button',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected blinding radial spotlight button halo: Gigantic 200px blurred gradient orb pulsing behind a single primary CTA"
            ],
            remediationPrompt: "Create visual hierarchy through high contrast, clean typography, and whitespace.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-40: Blinding Radial Spotlight Halo Behind Hero Button detected (${file.path}:${lineNum})`);
    }
    // CLICHE-41: Static Fake Product Hunt "#1 Product of the Day" Badge
    if (/(?:producthunt.*medal|product-of-the-day\.svg|ph-badge)/i.test(cleanContent) && !/https:\/\/www\.producthunt\.com/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:producthunt.*medal|product-of-the-day\.svg|ph-badge)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 241,
            type: 'VIBEPOLISH',
            title: 'CLICHE-41: Static Fake Product Hunt "#1 Product of the Day" Badge',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unlinked static Product Hunt badge: Embedding an unlinked, non-verifiable Product Hunt medal SVG"
            ],
            remediationPrompt: "Embed live, clickable official Product Hunt badges or omit if unverified.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-41: Static Fake Product Hunt "#1 Product of the Day" Badge detected (${file.path}:${lineNum})`);
    }
    // CLICHE-42: Buzzword Soup Hero Headline ("Supercharge Your Workflow")
    if (/(?:Supercharge|Revolutionize|Synergize|Unleash\s*the\s*Power).*(?:Workflow|Productivity|Potential)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Supercharge|Revolutionize|Synergize|Unleash\s*the\s*Power).*(?:Workflow|Productivity|Potential)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 242,
            type: 'VIBEPOLISH',
            title: 'CLICHE-42: Buzzword Soup Hero Headline ("Supercharge Your Workflow")',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected hyperbolic buzzword hero headline: Vague headlines claiming to \"Supercharge, Revolutionize, and Transform your Future\""
            ],
            remediationPrompt: "State clearly what the product does, who it is for, and the concrete outcome it delivers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-42: Buzzword Soup Hero Headline ("Supercharge Your Workflow") detected (${file.path}:${lineNum})`);
    }
    // CLICHE-43: Decorative Non-Functional Terminal with Fake Logs
    if (/(?:fake-terminal|mock-console|pseudo-terminal).*(?:Compiling\.\.\.|Bundling\.\.\.)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:fake-terminal|mock-console|pseudo-terminal).*(?:Compiling\.\.\.|Bundling\.\.\.)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 243,
            type: 'VIBEPOLISH',
            title: 'CLICHE-43: Decorative Non-Functional Terminal with Fake Logs',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected decorative non-functional terminal with fake logs: Mock terminal window printing fake compile logs with zero interactive capability"
            ],
            remediationPrompt: "Provide copyable CLI installation commands or an actual interactive interactive playground.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-43: Decorative Non-Functional Terminal with Fake Logs detected (${file.path}:${lineNum})`);
    }
    // CLICHE-44: Monospace Body Text Misuse
    if (/font-mono\s+text-(?:base|lg)\s+leading-relaxed/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/font-mono\s+text-(?:base|lg)\s+leading-relaxed/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 244,
            type: 'VIBEPOLISH',
            title: 'CLICHE-44: Monospace Body Text Misuse',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Typography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected monospace font misused for body paragraphs: Rendering entire multi-paragraph feature descriptions in JetBrains Mono or Courier"
            ],
            remediationPrompt: "Restrict monospace fonts strictly to code blocks, hashes, timestamps, and numeric tabular data.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-44: Monospace Body Text Misuse detected (${file.path}:${lineNum})`);
    }
    // CLICHE-45: Uncontrollable Auto-Playing Testimonial Carousel
    if (/(?:autoPlay|autoplay).*interval:\s*(?:1000|2000)\b/i.test(cleanContent) && !/pauseOnHover/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:autoPlay|autoplay).*interval:\s*(?:1000|2000)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 245,
            type: 'VIBEPOLISH',
            title: 'CLICHE-45: Uncontrollable Auto-Playing Testimonial Carousel',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected uncontrollable rapid auto-scrolling carousel: Testimonial cards spinning horizontally every 2 seconds without pause-on-hover"
            ],
            remediationPrompt: "Provide manual swipe/arrow controls and pause animation immediately on pointer hover or focus.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-45: Uncontrollable Auto-Playing Testimonial Carousel detected (${file.path}:${lineNum})`);
    }
    // CLICHE-46: Blown-Out Neon Box Shadow Glows
    if (/shadow-\[0_0_(?:40|50|60|80)px/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/shadow-\[0_0_(?:40|50|60|80)px/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 246,
            type: 'VIBEPOLISH',
            title: 'CLICHE-46: Blown-Out Neon Box Shadow Glows',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected blown-out saturated neon box shadow glow: Extreme box-shadow values with 100% saturation neon colors causing visual haze"
            ],
            remediationPrompt: "Use subtle, multi-layered neutral drop shadows with realistic ambient occlusion.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-46: Blown-Out Neon Box Shadow Glows detected (${file.path}:${lineNum})`);
    }
    // CLICHE-47: Formulaic Cliché Feature Comparison Matrix
    if (/(?:comparison-table|vs-competitors).*(?:Check.*X.*Check.*X|100%.*0%)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:comparison-table|vs-competitors).*(?:Check.*X.*Check.*X|100%.*0%)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 247,
            type: 'VIBEPOLISH',
            title: 'CLICHE-47: Formulaic Cliché Feature Comparison Matrix',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Content",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected biased formulaic comparison matrix: Comparison table where competitors have 10 red (X) icons and our app has 10 green checkmarks"
            ],
            remediationPrompt: "Build honest, nuanced comparison tables highlighting specific architectural differences.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-47: Formulaic Cliché Feature Comparison Matrix detected (${file.path}:${lineNum})`);
    }
    // CLICHE-48: Unlabeled Toggle Switch Interactive Ambiguity
    if (/<(?:Switch|Toggle)\b(?![^>]*(?:aria-label|aria-labelledby|<label))/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<(?:Switch|Toggle)\b(?![^>]*(?:aria-label|aria-labelledby|<label))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 248,
            type: 'VIBEPOLISH',
            title: 'CLICHE-48: Unlabeled Toggle Switch Interactive Ambiguity',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unlabeled toggle switch component: Toggle switch component rendering without associated label or active status indicator"
            ],
            remediationPrompt: "Pair every toggle with an explicit textual state label and aria-checked binding.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-48: Unlabeled Toggle Switch Interactive Ambiguity detected (${file.path}:${lineNum})`);
    }
    // CLICHE-49: Decorative Hand-Drawn SVG Scribble Arrows
    if (/(?:scribble-arrow|hand-drawn-arrow|doodle-arrow)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:scribble-arrow|hand-drawn-arrow|doodle-arrow)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 249,
            type: 'VIBEPOLISH',
            title: 'CLICHE-49: Decorative Hand-Drawn SVG Scribble Arrows',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected decorative hand-drawn scribble arrow SVG: Hand-drawn marker arrows pointing from sub-copy to primary button (\"Click here!\")"
            ],
            remediationPrompt: "Rely on intuitive layout hierarchy to guide user action without crude visual pointers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-49: Decorative Hand-Drawn SVG Scribble Arrows detected (${file.path}:${lineNum})`);
    }
    // CLICHE-50: Orphaned Dead Social Media Footer Anchors
    if (/href=["\']https?:\/\/(?:twitter|x|facebook|instagram)\.com\/?["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/href=["\']https?:\/\/(?:twitter|x|facebook|instagram)\.com\/?["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 250,
            type: 'VIBEPOLISH',
            title: 'CLICHE-50: Orphaned Dead Social Media Footer Anchors',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Navigation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected orphaned dead social media root link in footer: Twitter, Facebook, Instagram icons linking to root domains without company handle"
            ],
            remediationPrompt: "Link only to verified, active corporate channels or omit unused platforms completely.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-50: Orphaned Dead Social Media Footer Anchors detected (${file.path}:${lineNum})`);
    }
    // CLICHE-51: Hyper-Saturated Particle Canvas CPU Drain
    if (/(?:tsparticles|particle-canvas|particles-bg)/i.test(cleanContent) && !/prefers-reduced-motion/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:tsparticles|particle-canvas|particles-bg)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 251,
            type: 'VIBEPOLISH',
            title: 'CLICHE-51: Hyper-Saturated Particle Canvas CPU Drain',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected un-throttled continuous particle canvas: Background tsParticles or canvas drawing hundreds of bouncing nodes constantly at 60fps"
            ],
            remediationPrompt: "Limit canvas animations, throttle to requestAnimationFrame, and honor prefers-reduced-motion.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-51: Hyper-Saturated Particle Canvas CPU Drain detected (${file.path}:${lineNum})`);
    }
    // CLICHE-52: Generic Intercom Chat Bubble Impersonation
    if (/(?:chat-bubble|intercom-bubble|live-support-bubble).*(?:mailto:|href="#")/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:chat-bubble|intercom-bubble|live-support-bubble).*(?:mailto:|href="#")/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 252,
            type: 'VIBEPOLISH',
            title: 'CLICHE-52: Generic Intercom Chat Bubble Impersonation',
            severity: 'LOW',
            category: "AI Clich\u00e9 & UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected fake live chat trigger disguised as contact email: Floating bottom-right button with generic agent avatar that opens a mailto: link"
            ],
            remediationPrompt: "Label contact triggers accurately (\"Send us an email\") rather than mimicking live chat.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-52: Generic Intercom Chat Bubble Impersonation detected (${file.path}:${lineNum})`);
    }
    // CLICHE-53: 5-Star Rating Badge Without Review Count or Source
    if (/(?:Rated\s*5\.0|5\s*Stars?\s*Rating).*(?:top\s*companies|thousands\s*of\s*users)/i.test(cleanContent) && !/g2|capterra|trustpilot/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Rated\s*5\.0|5\s*Stars?\s*Rating).*(?:top\s*companies|thousands\s*of\s*users)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 253,
            type: 'VIBEPOLISH',
            title: 'CLICHE-53: 5-Star Rating Badge Without Review Count or Source',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unverified 5-star rating claim: Yellow 5-star SVGs accompanied by vague \"Rated 5.0 by top companies\""
            ],
            remediationPrompt: "Attribute star ratings to verified third-party aggregators with direct link.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-53: 5-Star Rating Badge Without Review Count or Source detected (${file.path}:${lineNum})`);
    }
    // CLICHE-54: Full-Bleed Unpadded Table Layout on Mobile
    if (/<table[\s>]/g.test(cleanContent) && !/overflow-x|overflow/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<table[\s>]/g], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 254,
            type: 'VIBEPOLISH',
            title: 'CLICHE-54: Full-Bleed Unpadded Table Layout on Mobile',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Mobile",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected full-bleed unpadded table on mobile viewports: Table layout overflowing viewport with zero padding and cut-off right border"
            ],
            remediationPrompt: "Wrap tables in responsive overflow containers with scroll affordance indicators.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-54: Full-Bleed Unpadded Table Layout on Mobile detected (${file.path}:${lineNum})`);
    }
    // CLICHE-55: Default Native Select Menu in Polished Dark Mode
    if (/<select\b(?![^>]*(?:bg-|className))/i.test(cleanContent) && /dark/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<select\b(?![^>]*(?:bg-|className))/i, /dark/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 255,
            type: 'VIBEPOLISH',
            title: 'CLICHE-55: Default Native Select Menu in Polished Dark Mode',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unstyled native select element in dark mode: Dark theme form using unstyled native HTML <select> opening blinding white dropdown OS menu"
            ],
            remediationPrompt: "Style select options using dark popovers or custom accessible dropdown components.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-55: Default Native Select Menu in Polished Dark Mode detected (${file.path}:${lineNum})`);
    }
    // CLICHE-56: Fixed Floating Call-to-Action Masking Footer Links
    if (/fixed\s+bottom-0\s+left-0\s+right-0/i.test(cleanContent) && !/pb-|padding-bottom/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fixed\s+bottom-0\s+left-0\s+right-0/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 256,
            type: 'VIBEPOLISH',
            title: 'CLICHE-56: Fixed Floating Call-to-Action Masking Footer Links',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected fixed floating CTA covering bottom layout elements: Floating sticky mobile action bar covering the legal and copyright footer"
            ],
            remediationPrompt: "Add safe-area-inset bottom padding to page container equal to floating bar height.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-56: Fixed Floating Call-to-Action Masking Footer Links detected (${file.path}:${lineNum})`);
    }
    // CLICHE-57: Nested Scroll Containers Causing Scrolljacking Traps
    if (/(?:overflow-y-scroll|overflow-y-auto)\s+h-(?:40|48|64)\b/i.test(cleanContent) && /card|feature/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:overflow-y-scroll|overflow-y-auto)\s+h-(?:40|48|64)\b/i, /card|feature/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 257,
            type: 'VIBEPOLISH',
            title: 'CLICHE-57: Nested Scroll Containers Causing Scrolljacking Traps',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected nested scroll container causing scrolljacking: Feature card containing internal scrollable text box that captures mousewheel scroll"
            ],
            remediationPrompt: "Avoid nested scrollable boxes on marketing pages; display full text or use disclosure modals.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-57: Nested Scroll Containers Causing Scrolljacking Traps detected (${file.path}:${lineNum})`);
    }
    // CLICHE-58: Misaligned Hero Headline Gradient Cutoff
    if (/bg-clip-text\s+text-transparent/i.test(cleanContent) && !/pb-|leading-(?:tight|normal|relaxed)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/bg-clip-text\s+text-transparent/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 258,
            type: 'VIBEPOLISH',
            title: 'CLICHE-58: Misaligned Hero Headline Gradient Cutoff',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Typography",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected headline gradient clipping typographic descenders: Applying bg-clip-text gradient with descenders (g, y, p, q) clipped at the baseline"
            ],
            remediationPrompt: "Add pb-1 or appropriate leading so typographic descenders remain fully rendered.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-58: Misaligned Hero Headline Gradient Cutoff detected (${file.path}:${lineNum})`);
    }
    // CLICHE-59: Fake "Built for Enterprise" Security Shield Badges
    if (/(?:Military\s*Grade\s*256-bit|SOC2\s*Type\s*II\s*Ready|Bank-Grade\s*Security)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Military\s*Grade\s*256-bit|SOC2\s*Type\s*II\s*Ready|Bank-Grade\s*Security)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 259,
            type: 'VIBEPOLISH',
            title: 'CLICHE-59: Fake "Built for Enterprise" Security Shield Badges',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected fabricated security shield marketing slogan: Generic lock SVG with \"Military Grade 256-bit Encryption\" and \"SOC2 Type II Ready\""
            ],
            remediationPrompt: "State concrete security controls (e.g. \"AES-256 at rest, TLS 1.3 in transit, automated pentests\").",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-59: Fake "Built for Enterprise" Security Shield Badges detected (${file.path}:${lineNum})`);
    }
    // CLICHE-60: Redundant Breadcrumb Navigation on 2-Level Site
    if (/(?:Home\s*>\s*Dashboard|Home\s*\/\s*App)\b/i.test(cleanContent) && !/breadcrumbs/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Home\s*>\s*Dashboard|Home\s*\/\s*App)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 260,
            type: 'VIBEPOLISH',
            title: 'CLICHE-60: Redundant Breadcrumb Navigation on 2-Level Site',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Navigation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected redundant shallow breadcrumb navigation on 2-page app: Displaying \"Home > Dashboard\" on a single-page web app with no deeper hierarchy"
            ],
            remediationPrompt: "Use breadcrumbs only when information architecture is 3+ levels deep.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-60: Redundant Breadcrumb Navigation on 2-Level Site detected (${file.path}:${lineNum})`);
    }
    // CLICHE-61: Missing Input Placeholder Contrast in Dark Theme
    if (/placeholder:(?:text-white\/10|text-gray-600|text-slate-700)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/placeholder:(?:text-white\/10|text-gray-600|text-slate-700)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 261,
            type: 'VIBEPOLISH',
            title: 'CLICHE-61: Missing Input Placeholder Contrast in Dark Theme',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected invisible low-contrast input placeholder in dark mode: Input placeholder text styled with opacity-20 making it completely invisible"
            ],
            remediationPrompt: "Use placeholder text with minimum 3:1 contrast against input background.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-61: Missing Input Placeholder Contrast in Dark Theme detected (${file.path}:${lineNum})`);
    }
    // CLICHE-62: Inflexible Fixed-Width Container Breakpoints
    if (/className=["\'][^"\']*\bw-\[1200px\]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/className=["\'][^"\']*\bw-\[1200px\]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 262,
            type: 'VIBEPOLISH',
            title: 'CLICHE-62: Inflexible Fixed-Width Container Breakpoints',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Responsive",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected inflexible fixed-width desktop container without responsive bounds: Using fixed w-[1200px] instead of max-w-7xl with responsive percentage margins"
            ],
            remediationPrompt: "Always use fluid percentage widths with max-width bounding constraints.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-62: Inflexible Fixed-Width Container Breakpoints detected (${file.path}:${lineNum})`);
    }
    // CLICHE-63: Fake "Press Mentions" Banner with Generic Icons
    if (/(?:As\s*seen\s*on|Featured\s*in).*(?:TechCrunch|Forbes|Bloomberg)/i.test(cleanContent) && !/href=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:As\s*seen\s*on|Featured\s*in).*(?:TechCrunch|Forbes|Bloomberg)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 263,
            type: 'VIBEPOLISH',
            title: 'CLICHE-63: Fake "Press Mentions" Banner with Generic Icons',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unlinked fake press mention logo bar: Displaying \"As seen in TechCrunch, Forbes, Bloomberg\" without any actual article links"
            ],
            remediationPrompt: "Link directly to verified third-party coverage or omit media mention bars entirely.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-63: Fake "Press Mentions" Banner with Generic Icons detected (${file.path}:${lineNum})`);
    }
    // CLICHE-64: Misplaced Skeuomorphic Glass Reflection Strokes
    if (/border-gradient.*glass-reflection|reflection-stroke/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/border-gradient.*glass-reflection|reflection-stroke/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 264,
            type: 'VIBEPOLISH',
            title: 'CLICHE-64: Misplaced Skeuomorphic Glass Reflection Strokes',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected skeuomorphic glass reflection border stroke on data table: Applying 1px gradient borders simulating glass reflections on flat data tables"
            ],
            remediationPrompt: "Maintain consistent surface styling across the entire design system.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-64: Misplaced Skeuomorphic Glass Reflection Strokes detected (${file.path}:${lineNum})`);
    }
    // CLICHE-65: Interactive Elements Disguised as Static Text
    if (/<a\b[^>]*className=["\'][^"\']*(?:text-inherit|text-current)(?![^"\']*underline)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<a\b[^>]*className=["\'][^"\']*(?:text-inherit|text-current)(?![^"\']*underline)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 265,
            type: 'VIBEPOLISH',
            title: 'CLICHE-65: Interactive Elements Disguised as Static Text',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Affordance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected interactive action link disguised as plain static text: Clickable action links rendered in plain body text color without underline or hover state"
            ],
            remediationPrompt: "Ensure interactive links have distinct color, underline on hover, or clear button styling.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-65: Interactive Elements Disguised as Static Text detected (${file.path}:${lineNum})`);
    }
    // CLICHE-66: Static Video Player Mockup with Fake Play Button
    if (/(?:video-mockup|video-preview).*(?:play-button|lucide-play)/i.test(cleanContent) && !/(?:<video|iframe|src=)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:video-mockup|video-preview).*(?:play-button|lucide-play)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 266,
            type: 'VIBEPOLISH',
            title: 'CLICHE-66: Static Video Player Mockup with Fake Play Button',
            severity: 'LOW',
            category: "AI Clich\u00e9 & UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected static video player mockup with fake non-functional play button: Big video preview image with centered play button that does nothing or opens modal with dead YouTube link"
            ],
            remediationPrompt: "Embed real, functioning video player or use animated GIF/WEBM interface preview.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-66: Static Video Player Mockup with Fake Play Button detected (${file.path}:${lineNum})`);
    }
    // CLICHE-67: Unstyled Skeleton Screen Flickering
    if (/skeleton\b.*bg-white(?:\s|\/)/i.test(cleanContent) && /dark/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/skeleton\b.*bg-white(?:\s|\/)/i, /dark/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 267,
            type: 'VIBEPOLISH',
            title: 'CLICHE-67: Unstyled Skeleton Screen Flickering',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected high-contrast white skeleton loader flashing in dark theme: Displaying high-contrast white skeleton boxes on dark background before data loads"
            ],
            remediationPrompt: "Style skeleton loaders with theme-matched subtle pulse animations.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-67: Unstyled Skeleton Screen Flickering detected (${file.path}:${lineNum})`);
    }
    // CLICHE-68: Missing Tab Indicator Transition on Navigation
    if (/<Tab\b[^>]*onClick/i.test(cleanContent) && !/layoutId|transition/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<Tab\b[^>]*onClick/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 268,
            type: 'VIBEPOLISH',
            title: 'CLICHE-68: Missing Tab Indicator Transition on Navigation',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Interaction",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected navigation tab bar lacking active indicator motion transition: Tab bars where the active indicator teleports abruptly with zero animation"
            ],
            remediationPrompt: "Use layoutId or smooth transition transitions on active tab indicator pill.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-68: Missing Tab Indicator Transition on Navigation detected (${file.path}:${lineNum})`);
    }
    // CLICHE-69: Arbitrary "Beta" Pill Attached Indefinitely
    if (/(?:badge|pill).*(?:BETA|Beta)\b/i.test(cleanContent) && /copyright.*(?:2021|2022|2023)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:badge|pill).*(?:BETA|Beta)\b/i, /copyright.*(?:2021|2022|2023)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 269,
            type: 'VIBEPOLISH',
            title: 'CLICHE-69: Arbitrary "Beta" Pill Attached Indefinitely',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Trust",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected indefinite beta pill attached to mature production app: Software operating for 3 years still showing glowing \"BETA\" pill next to brand name"
            ],
            remediationPrompt: "Remove beta labels once product is commercially released with paid subscriptions.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-69: Arbitrary "Beta" Pill Attached Indefinitely detected (${file.path}:${lineNum})`);
    }
    // CLICHE-70: Inconsistent Icon Stroke Widths across Sections
    if (/strokeWidth=["\'](?:1|1\.25)["\']/i.test(cleanContent) && /strokeWidth=["\'](?:2\.5|3)["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/strokeWidth=["\'](?:1|1\.25)["\']/i, /strokeWidth=["\'](?:2\.5|3)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 270,
            type: 'VIBEPOLISH',
            title: 'CLICHE-70: Inconsistent Icon Stroke Widths across Sections',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Visual",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected inconsistent mixed icon stroke weights across sections: Mixing 1px, 1.5px, and 2.5px icon line weights from different icon libraries"
            ],
            remediationPrompt: "Standardize on a single icon library with uniform stroke width across all views.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-70: Inconsistent Icon Stroke Widths across Sections detected (${file.path}:${lineNum})`);
    }
    // CLICHE-71: Ambiguous Back Button Navigation on Subpages
    if (/(?:router\.back\(\)|history\.back\(\))/i.test(cleanContent) && !/fallbackUrl|parentPath/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:router\.back\(\)|history\.back\(\))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 271,
            type: 'VIBEPOLISH',
            title: 'CLICHE-71: Ambiguous Back Button Navigation on Subpages',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected ambiguous browser history back navigation on subpages: Back button that executes router.back() into external referrer instead of parent page"
            ],
            remediationPrompt: "Direct back buttons explicitly to logical parent section or provide fallback.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-71: Ambiguous Back Button Navigation on Subpages detected (${file.path}:${lineNum})`);
    }
    // CLICHE-72: Inverted Hero Visual Dominating Primary Action
    if (/(?:hero-graphic|hero-animation).*(?:w-full|h-\[600px\])/i.test(cleanContent) && !/cta-container/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:hero-graphic|hero-animation).*(?:w-full|h-\[600px\])/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 272,
            type: 'VIBEPOLISH',
            title: 'CLICHE-72: Inverted Hero Visual Dominating Primary Action',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected oversized hero visual dominating primary conversion action: Massive glowing animation so prominent that user completely misses the sign-up CTA"
            ],
            remediationPrompt: "Ensure primary call-to-action has the highest visual weight in the hero section.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-72: Inverted Hero Visual Dominating Primary Action detected (${file.path}:${lineNum})`);
    }
    // CLICHE-73: Broken Mobile Hamburger Menu Scroll Lock
    if ((/mobileMenuOpen|isMobileNav/i.test(cleanContent) && !/overflow-hidden|useLockBodyScroll|style\.overflow\s*=/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/mobileMenuOpen|isMobileNav/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 273,
            type: 'VIBEPOLISH',
            title: 'CLICHE-73: Broken Mobile Hamburger Menu Scroll Lock',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Mobile",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected mobile navigation drawer lacking body scroll lock: Mobile navigation drawer open while background page continues scrolling underneath"
            ],
            remediationPrompt: "Apply overflow-hidden to document body when mobile navigation is active.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-73: Broken Mobile Hamburger Menu Scroll Lock detected (${file.path}:${lineNum})`);
    }
    // CLICHE-74: Unannounced External Link Navigation
    if (/<a\b[^>]*target=["\']_blank["\'](?![^>]*(?:rel=|noopener|ExternalLink))/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<a\b[^>]*target=["\']_blank["\'](?![^>]*(?:rel=|noopener|ExternalLink))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 274,
            type: 'VIBEPOLISH',
            title: 'CLICHE-74: Unannounced External Link Navigation',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected unannounced external link navigation missing security attributes: Links navigating to external third-party sites without target=\"_blank\" or external icon"
            ],
            remediationPrompt: "Indicate external links clearly with an ExternalLink icon and screen-reader notice.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-74: Unannounced External Link Navigation detected (${file.path}:${lineNum})`);
    }
    // CLICHE-75: Formulaic "Frequently Asked Questions" Subtitle Cliché
    if (/(?:Frequently\s*Asked\s*Questions|FAQ)[\s\S]{0,300}?Everything\s*you\s*need\s*to\s*know\s*about/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && /Everything\s*you\s*need\s*to\s*know\s*about/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 275,
            type: 'VIBEPOLISH',
            title: 'CLICHE-75: Formulaic "Frequently Asked Questions" Subtitle Cliché',
            severity: 'LOW',
            category: "AI Clich\u00e9 & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected cliche pattern>',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                "Detected boilerplate generic FAQ subtitle formula: \"Everything you need to know about our product and billing\" repeating on every site"
            ],
            remediationPrompt: "Write authentic section descriptions explaining how customer questions are handled.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🎨 CLICHE-75: Formulaic "Frequently Asked Questions" Subtitle Cliché detected (${file.path}:${lineNum})`);
    }
    // CLICHE-76: Decorative Eyebrow & Heading Icon Prepending
    // Note: Only flags true uppercase shouting text (case-sensitive) to avoid flagging standard mixed-case buttons
    if (/<(?:Terminal|Layers|Scale|HelpCircle|ShieldCheck|Sparkles|Activity|Code|Settings|Sliders|Zap)\b[^>]*\/>\s*<(?:span|div)[^>]*>\s*[A-Z0-9_\-&]{4,}(?:\s+[A-Z0-9_\-&]+)*\s*<\/(?:span|div)>/.test(cleanContent) || /<(?:Terminal|Layers|Scale|HelpCircle|ShieldCheck|Sparkles)\b[^>]*\/>\s*[A-Z0-9_\-&]{4,}/.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && /<(?:Terminal|Layers|Scale|HelpCircle|ShieldCheck|Sparkles|Activity|Code|Settings|Sliders|Zap)\b[^>]*\/>/i.test(l) && /[A-Z0-9_\-&]{4,}/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 276,
            type: 'VIBEPOLISH',
            title: 'CLICHE-76: Decorative Eyebrow & Heading Icon Prepending (AI Slop)',
            severity: 'MEDIUM',
            category: "AI Cliché & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<Terminal size={14} /> OPERATIONAL ARCHITECTURE',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                'Detected decorative Lucide icon prepended directly to uppercase section eyebrow text or category badges.'
            ],
            remediationPrompt: 'Remove decorative Lucide icons prepended to section eyebrows or uppercase headings. Rely on clear typographic hierarchy and letter spacing.',
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] [RULE] CLICHE-76: Eyebrow icon prepending detected (${file.path}:${lineNum})`);
    }
    // CLICHE-77: Pulsating Status Dot & Glowing Badge Cliché
    const isLiveRunnerComponent = /ScanRunnerView|TerminalLogWindow/i.test(file.path);
    if (!isLiveRunnerComponent && (/rounded-full\s+bg-emerald-[45]00[^"']*animate-pulse/i.test(cleanContent) || /animate-pulse[^"']*rounded-full\s+bg-emerald-[45]00/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && /animate-pulse/i.test(l) && /bg-emerald/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 277,
            type: 'VIBEPOLISH',
            title: 'CLICHE-77: Pulsating Status Dot & Glowing Badge Cliché (AI Slop)',
            severity: 'LOW',
            category: "AI Cliché & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                'Detected pulsating green indicator dot inside static component or card.'
            ],
            remediationPrompt: 'Remove distracting pulsating green animation dots in static badges. Use static monochromatic or subtle badges.',
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] [RULE] CLICHE-77: Pulsing status dot cliché detected (${file.path}:${lineNum})`);
    }
    // CLICHE-78: Repetitive Checkmark Icon Flooding
    if (/<(?:CheckCircle2|CheckCircle)\b[^>]*className="[^"]*text-emerald-400[^"]*shrink-0/i.test(cleanContent) && /\.map\s*\(/.test(cleanContent) && cleanContent.includes('<li')) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && /<(?:CheckCircle2|CheckCircle)\b/i.test(l) && /<li/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cliche-${Date.now()}-${findingCounter.count++}`,
            ruleId: 278,
            type: 'VIBEPOLISH',
            title: 'CLICHE-78: Repetitive Checkmark Icon Flooding (AI Slop)',
            severity: 'LOW',
            category: "AI Cliché & Copywriting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<CheckCircle2 size={16} className="text-emerald-400 shrink-0" />',
            reproductionSteps: [
                `Scanned UI layout and design tokens in ${file.path}:${lineNum}.`,
                'Detected repetitive CheckCircle icons prepended to every single list item.'
            ],
            remediationPrompt: 'Replace repetitive CheckCircle icons with clean typography dashes (e.g. "—"), numbered steps, or distinct micro-cards.',
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] [RULE] CLICHE-78: Repetitive checkmark flooding detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
