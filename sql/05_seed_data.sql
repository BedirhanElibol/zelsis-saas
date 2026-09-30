-- ==============================================================================
-- ZELSIS B2B SAAS - INITIAL SEED DATA (FULL OWASP RULES CATALOG)
-- File: sql/05_seed_data.sql
-- Description: Complete OWASP reference security catalog seed script.
-- ==============================================================================

-- 1. SECURITY RULES CATALOG TABLE
CREATE TABLE IF NOT EXISTS public.security_rules_catalog (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    owasp_tag TEXT NOT NULL,
    risk_level finding_severity NOT NULL,
    description TEXT NOT NULL,
    verification_control TEXT NOT NULL,
    remediation_prompt TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

ALTER TABLE public.security_rules_catalog ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public read-only for rules catalog" ON public.security_rules_catalog;
CREATE POLICY "Public read-only for rules catalog" ON public.security_rules_catalog
    FOR SELECT USING (auth.role() = 'anon' OR auth.role() = 'authenticated');


-- Seed OWASP Rules Catalog
INSERT INTO public.security_rules_catalog (id, code, title, category, owasp_tag, risk_level, description, verification_control, remediation_prompt)
VALUES
(1, 'SEC-01', 'Plaintext API Key / Hardcoded Secret Leak', 'Authentication Security', 'A02:2021-Cryptographic Failures', 'CRITICAL', 'Hardcoded API secrets or tokens in source code files.', 'Validate environment variable usage.', 'Extract hardcoded secret into process.env.'),
(2, 'SEC-02', 'SQL Injection Vulnerability', 'Injection Security', 'A03:2021-Injection', 'CRITICAL', 'Unsanitized raw SQL string concatenation.', 'Use parameterized SQL queries.', 'Replace raw query with parameterized inputs.'),
(3, 'SEC-03', 'Cross-Site Scripting (XSS) via dangerouslySetInnerHTML', 'Frontend Security', 'A03:2021-Injection', 'HIGH', 'Directly injecting unescaped HTML content into DOM.', 'Sanitize HTML inputs using DOMPurify.', 'Wrap innerHTML in DOMPurify.sanitize().'),
(4, 'SEC-04', 'Absence of CSRF Token Protection', 'API Security', 'A01:2021-Broken Access Control', 'HIGH', 'State-changing HTTP POST/PUT API route without CSRF validation.', 'Verify anti-CSRF headers.', 'Implement SameSite cookie or CSRF header verification.'),
(5, 'SEC-05', 'Insecure Direct Object Reference (IDOR)', 'Access Control', 'A01:2021-Broken Access Control', 'CRITICAL', 'API endpoints allowing access to resources without checking ownership.', 'Enforce Row Level Security and user ID ownership checks.', 'Add auth check: verify request user ID matches resource owner.'),
(6, 'SEC-06', 'Broken Authentication / Weak Password Policy', 'Authentication Security', 'A07:2021-Identification and Authentication Failures', 'HIGH', 'Missing rate limiting or weak hashing on login routes.', 'Enforce bcrypt/argon2 hashing and rate limiting.', 'Apply rate-limit middleware to authentication endpoints.'),
(7, 'SEC-07', 'Unrestricted File Upload Vulnerability', 'File Security', 'A04:2021-Insecure Design', 'CRITICAL', 'Uploading executable or arbitrary files without extension validation.', 'Validate MIME type, extension, and file size server-side.', 'Check allowed MIME types and store uploaded files in isolated bucket.'),
(8, 'SEC-08', 'Server-Side Request Forgery (SSRF)', 'Network Security', 'A10:2021-Server-Side Request Forgery', 'CRITICAL', 'Fetching URLs specified by untrusted user input.', 'Validate and restrict outgoing IP destinations.', 'Block internal private IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16).'),
(9, 'SEC-09', 'Insecure CORS Misconfiguration', 'API Security', 'A05:2021-Security Misconfiguration', 'MEDIUM', 'Wildcard Access-Control-Allow-Origin header with credentials.', 'Explicitly list allowed origin domain whitelist.', 'Set Access-Control-Allow-Origin to specific trusted domain origins.'),
(10, 'SEC-10', 'Sensitive Data Exposure in Logs', 'Logging Security', 'A09:2021-Security Logging and Monitoring Failures', 'HIGH', 'Logging plain passwords, tokens, or PII to console/log files.', 'Redact sensitive keys before logging.', 'Apply log redactor utility to strip secret properties.'),
(11, 'SEC-11', 'Missing Content Security Policy (CSP)', 'HTTP Headers', 'A05:2021-Security Misconfiguration', 'MEDIUM', 'Missing CSP header allowing arbitrary script execution.', 'Set Strict CSP HTTP response header.', 'Configure Content-Security-Policy header in Next.js headers.'),
(12, 'SEC-12', 'Outdated Vulnerable Dependency (CVE)', 'Supply Chain', 'A06:2021-Vulnerable and Outdated Components', 'HIGH', 'Using npm packages with known high/critical CVE vulnerabilities.', 'Run npm audit and update vulnerable packages.', 'Upgrade package to secure patched version.'),
(13, 'SEC-13', 'Directory Traversal / Arbitrary File Read', 'File System', 'A01:2021-Broken Access Control', 'CRITICAL', 'Unsanitized file paths allowing path traversal (../..)', 'Sanitize file paths using path.normalize().', 'Validate resolved path remains within target root folder.'),
(14, 'SEC-14', 'Insecure JWT Verification / Missing Signature Check', 'Authentication Security', 'A02:2021-Cryptographic Failures', 'CRITICAL', 'Accepting unsigned or weak secret JWT tokens (alg: none).', 'Verify JWT algorithm and signature key.', 'Enforce algorithm restriction and secret validation.'),
(15, 'SEC-15', 'Lack of Rate Limiting on Public APIs', 'API Security', 'A04:2021-Insecure Design', 'MEDIUM', 'Public API routes susceptible to brute-force and Denial of Service.', 'Implement sliding window rate limiting.', 'Attach rate limiter middleware to public route handlers.'),
(16, 'SEC-16', 'Improper Error Handling / Detailed Stack Leak', 'Information Disclosure', 'A05:2021-Security Misconfiguration', 'LOW', 'Exposing raw stack traces or internal errors to client responses.', 'Return generic error messages in production environment.', 'Wrap response in standardized error formatter.'),
(17, 'SEC-17', 'Unencrypted HTTP Communication / Missing HSTS', 'Transport Layer', 'A02:2021-Cryptographic Failures', 'HIGH', 'Transmitting data over HTTP without SSL/TLS enforcement.', 'Enforce HTTP Strict Transport Security (HSTS).', 'Set Strict-Transport-Security header max-age=31536000.'),
(18, 'SEC-18', 'XML External Entity (XXE) Injection', 'Parser Security', 'A03:2021-Injection', 'HIGH', 'Parsing XML with external entity resolution enabled.', 'Disable DTDs and external entity loading in XML parser.', 'Configure XML parser options to ignore DTDs.'),
(19, 'SEC-19', 'Weak Random Number Generation (Math.random)', 'Cryptography', 'A02:2021-Cryptographic Failures', 'MEDIUM', 'Using Math.random() for security-critical tokens or OTPs.', 'Use crypto.getRandomValues() or crypto.randomBytes().', 'Replace Math.random() with Web Crypto API.'),
(20, 'SEC-20', 'Open Redirect Vulnerability', 'Frontend Security', 'A01:2021-Broken Access Control', 'MEDIUM', 'Redirecting users based on untrusted query parameter URLs.', 'Validate redirect URLs against domain whitelist.', 'Restrict redirects to relative internal paths only.'),
(21, 'SEC-21', 'Prompt Injection Vulnerability in LLM Route', 'AI System Security', 'A03:2021-Injection', 'CRITICAL', 'Passing raw user prompt into LLM context without system boundary.', 'Sanitize user inputs and isolate system instructions.', 'Apply LLM input guardrails and prompt templates.'),
(22, 'SEC-22', 'Insecure Deserialization', 'API Security', 'A08:2021-Software and Data Integrity Failures', 'CRITICAL', 'Deserializing untrusted user objects using unsafe eval/eval-like parsers.', 'Use strict JSON.parse() schemas with Zod validation.', 'Parse payload with type-safe schema validator.'),
(23, 'SEC-23', 'Missing Anti-Automation / Bot Protection', 'Application Defenses', 'A04:2021-Insecure Design', 'MEDIUM', 'Critical form submissions lacking bot detection or reCAPTCHA.', 'Integrate Cloudflare Turnstile or CAPTCHA validation.', 'Verify anti-bot token prior to form processing.')
ON CONFLICT (id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    remediation_prompt = EXCLUDED.remediation_prompt;
