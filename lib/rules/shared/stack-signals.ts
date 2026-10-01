/**
 * Stack-agnostic signals shared by rule engines. Rules must not assume one vendor:
 * add a provider here once and every rule that relies on the signal recognises it.
 */

/** Server-side authentication checks across auth providers and frameworks. */
export const AUTH_GUARD = new RegExp([
  String.raw`\.auth\.(?:getUser|getClaims|getSession)\s*\(`, // Supabase
  String.raw`\bauth\(\s*\)|currentUser\s*\(|clerkClient|getAuth\s*\(`, // Clerk / Auth.js v5 / Firebase
  String.raw`getServerSession\s*\(|\bgetSession\s*\(|getToken\s*\(`, // NextAuth / Auth0 / generic
  String.raw`verifyIdToken\s*\(|validateRequest\s*\(|validateSession\s*\(|getKindeServerSession|auth\.api\.getSession`, // Firebase, Lucia, Kinde, Better Auth
  String.raw`requireAuth|withAuth|ensureAuthenticated|isAuthenticated|passport\.authenticate|\breq(?:uest)?\.user\b`, // Express / Passport
  String.raw`jwtVerify\s*\(|jwt\.verify\s*\(|verifyToken\s*\(|session\.user\b`,
  String.raw`login_required|Depends\(\s*get_current_user|IsAuthenticated|@UseGuards\(|authorize\s*\(` // Django, FastAPI, DRF, NestJS
].join('|'), 'i');

/** Rate limiting across libraries and platforms. */
export const RATE_LIMIT_GUARD = /rate[-_ ]?limit|ratelimit|limiter|throttl|slowDown|slidingWindow|tokenBucket|upstash|arcjet|\baj\.protect|unkey|\.limits?\.limit\s*\(|@limiter|RateLimiter/i;

/** Webhook signature verification across payment / event providers. */
export const WEBHOOK_VERIFY = new RegExp([
  String.raw`constructEvent(?:Async)?\s*\(|construct_event\s*\(`, // Stripe
  String.raw`validateEvent\s*\(|webhooks?\.(?:verify|unmarshal|unwrap|constructEvent)\s*\(`, // Polar, Paddle, Standard Webhooks
  String.raw`verify\w*(?:Signature|Webhook)\w*\s*\(|new\s+Webhook\s*\([^)]*\)\s*(?:;|\.verify)`, // PayPal, Svix, Clerk, custom
  String.raw`createHmac\s*\(|timingSafeEqual\s*\(|crypto\.subtle\.verify\s*\(|hmac\.compare_digest|hmac\.new\s*\(`
].join('|'), 'i');

/** Calls that run an LLM inference across SDKs. */
export const LLM_CALL = new RegExp([
  String.raw`chat\.completions\.create|\.completions\.create|responses\.create|messages\.create`, // OpenAI / Anthropic style
  String.raw`\b(?:generateText|streamText|generateObject|streamObject)\s*\(`, // Vercel AI SDK
  String.raw`generateContent(?:Stream)?\s*\(|getGenerativeModel\s*\(`, // Gemini
  String.raw`new\s+Chat(?:OpenAI|Anthropic|GoogleGenerativeAI|VertexAI|Mistral(?:AI)?|Groq|Bedrock(?:Converse)?|Ollama|Cohere)\s*\(`, // LangChain
  String.raw`ConverseCommand|InvokeModelCommand|mistral\.chat|cohere\.chat|ollama\.(?:chat|generate)`
].join('|'), 'i');

/** Output-token caps across SDKs. */
export const LLM_OUTPUT_LIMIT = /\b(?:max_tokens|max_completion_tokens|max_output_tokens|maxTokens|maxOutputTokens|max_tokens_to_sample|maxCompletionTokens|num_predict)\s*[:=]/i;

/** Payment / billing SDKs. */
export const PAYMENT_SDK = /stripe|paymentIntents|checkout\.sessions|lemonsqueezy|createCheckout|polar|paddle|paypal|braintree|adyen|mollie|razorpay|iyzi(?:pay|co)|squareup|square\.|mercadopago|paystack|flutterwave|xendit|chargebee|recurly/i;

/** Database writes across ORMs / query builders / document stores. */
export const DB_MUTATION = new RegExp([
  String.raw`supabase\.from\([^)]+\)\.(?:insert|update|delete|upsert)`,
  String.raw`\bdb\.(?:insert|update|delete)\s*\(|prisma\.\w+\.(?:create|createMany|update|updateMany|delete|deleteMany|upsert)\s*\(`, // Drizzle, Prisma
  String.raw`\.(?:findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany|insertOne|insertMany|bulkWrite)\s*\(`, // Mongoose / MongoDB
  String.raw`getRepository\([^)]*\)\.(?:save|delete|update|insert|remove)\s*\(|\.(?:insertInto|updateTable|deleteFrom)\s*\(`, // TypeORM, Kysely
  String.raw`knex\([^)]*\)\.(?:insert|update|del|delete)\s*\(|\.doc\([^)]*\)\.(?:set|update|delete)\s*\(|\.collection\([^)]*\)\.add\s*\(`, // Knex, Firestore
  String.raw`\.(?:destroy|bulkCreate)\s*\(` // Sequelize
].join('|'), 'i');

/** Server request handlers across frameworks (used to scope webhook / route rules beyond Next.js app/api). */
export const SERVER_HANDLER = /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|action|loader|handler)\b|export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=|export\s+default\s+(?:async\s+)?function|\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|all|route)\s*\(|@(?:app|router)\.(?:route|get|post)|def\s+\w+\s*\(\s*request\b/i;

/** Request body access across frameworks. */
export const REQUEST_BODY = /\breq(?:uest)?\.(?:body\b|json\s*\(|text\s*\(|formData\s*\()|request\.(?:json|data|POST|form)\b|ctx\.request\.body|event\.body/i;

/** Code that sends notifications to webhook URLs (Slack, Discord, Teams, generic) rather than receiving provider events. */
export const OUTBOUND_WEBHOOK = /hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook\.office\.com|\b(?:slack|discord|teams)Webhook(?:Url)?\b|dispatchWebhook\w*\s*\(|sendWebhook\w*\s*\(|IncomingWebhook\s*\(/i;

/** Signs that a handler processes events pushed by a provider (i.e. it is a webhook receiver). */
export const INBOUND_EVENT = /event\.type\b|event_type|eventType|['"]x-[\w-]*signature['"]|stripe-signature|webhook-signature|svix-|\.meta\.event_name/i;

export const isOutboundWebhookSender = (content: string): boolean => OUTBOUND_WEBHOOK.test(content) && !INBOUND_EVENT.test(content);
