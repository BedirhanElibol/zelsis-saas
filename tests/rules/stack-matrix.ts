/**
 * Cross-stack matrix: the same security concept written for different auth, ORM, payment,
 * framework and LLM providers. Zelsis serves every stack, so each rule must detect the
 * vulnerable form and stay quiet on the safe form regardless of vendor.
 * Add a row whenever a rule learns a new provider.
 */
export interface StackCase { id: string; expect: 'detect' | 'clean'; rules: number[]; path: string; content: string }
type C = StackCase;
const R = (path: string, body: string) => ({ path, content: body });
// Auth-guarded mutation routes across providers: must NOT be flagged as unauthenticated (rule 15) / server action (3006)
const authed: [string, string][] = [
  ['supabase', "const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response('401', { status: 401 });"],
  ['clerk', "const { userId } = await auth();\n  if (!userId) return new Response('401', { status: 401 });"],
  ['nextauth', "const session = await getServerSession(authOptions);\n  if (!session) return new Response('401', { status: 401 });"],
  ['authjs-v5', "const session = await auth();\n  if (!session?.user) return new Response('401', { status: 401 });"],
  ['auth0', "const session = await auth0.getSession();\n  if (!session) return new Response('401', { status: 401 });"],
  ['firebase', "const token = req.headers.get('authorization')?.slice(7) ?? '';\n  const decoded = await getAuth().verifyIdToken(token);\n  if (!decoded) return new Response('401', { status: 401 });"],
  ['lucia', "const { user } = await validateRequest();\n  if (!user) return new Response('401', { status: 401 });"],
  ['kinde', "const { isAuthenticated } = getKindeServerSession();\n  if (!(await isAuthenticated())) return new Response('401', { status: 401 });"],
  ['better-auth', "const session = await auth.api.getSession({ headers: req.headers });\n  if (!session) return new Response('401', { status: 401 });"],
];
export const STACK_MATRIX: C[] = [];
const cases = STACK_MATRIX;
for (const [name, guard] of authed) {
  cases.push({ id: `authed-route:${name}`, expect: 'clean', rules: [15], ...R('app/api/projects/route.ts', `export async function POST(req: Request) {\n  ${guard}\n  const body = await req.json();\n  await db.project.create({ data: { name: String(body.name) } });\n  return Response.json({ ok: true });\n}\n`) });
  cases.push({ id: `authed-action:${name}`, expect: 'clean', rules: [3006], ...R('app/actions/project.ts', `'use server';\nexport async function deleteProject(req: any, id: string) {\n  ${guard.replace(/return new Response\([^)]*\)\);?/g, "throw new Error('unauthorized');")}\n  await db.project.delete({ where: { id } });\n}\n`) });
}
// Unauthenticated mutations across ORMs: must be detected
for (const [orm, q] of [['prisma', 'await prisma.project.delete({ where: { id } });'], ['drizzle', 'await db.delete(projects).where(eq(projects.id, id));'], ['mongoose', 'await Project.findByIdAndDelete(id);'], ['supabase', "await supabase.from('projects').delete().eq('id', id);"]] as const) {
  cases.push({ id: `unauth-action:${orm}`, expect: 'detect', rules: [3006], ...R('app/actions/project.ts', `'use server';\nexport async function deleteProject(id: string) {\n  ${q}\n}\n`) });
}
// IDOR by request id without ownership, across ORMs (TENANT-06 / TENANT-01)
for (const [orm, q] of [['supabase-admin', "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n  const { data } = await admin.from('invoices').select('*').eq('id', params.id).single();"], ['prisma', 'const data = await prisma.invoice.findUnique({ where: { id: params.id } });'], ['drizzle', 'const data = await db.select().from(invoices).where(eq(invoices.id, params.id));'], ['mongoose', 'const data = await Invoice.findById(params.id);']] as const) {
  const guard = orm === 'supabase-admin' ? '' : "const session = await getServerSession(authOptions);\n  if (!session) return new Response('401', { status: 401 });\n  ";
  cases.push({ id: `idor:${orm}`, expect: 'detect', rules: [9106, 9101], ...R('app/api/invoices/[id]/route.ts', `export async function GET(req: Request, { params }: { params: { id: string } }) {\n  ${guard}${q}\n  return Response.json(data);\n}\n`) });
  cases.push({ id: `idor-scoped:${orm}`, expect: 'clean', rules: [9106], ...R('app/api/invoices/[id]/route.ts', `export async function GET(req: Request, { params }: { params: { id: string } }) {\n  ${guard}${q}\n  if (data?.userId !== session?.user?.id) return new Response('404', { status: 404 });\n  return Response.json(data);\n}\n`) });
  cases.push({ id: `public-read:${orm}`, expect: 'clean', rules: [9106], ...R('app/api/posts/[id]/route.ts', `export async function GET(req: Request, { params }: { params: { id: string } }) {\n  ${q.replace(/invoice/gi, 'post').replace("const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n  ", '').replace('admin.from', 'supabase.from')}\n  return Response.json(data);\n}\n`) });
}
// Webhooks without signature verification across frameworks/providers (8143 / 9704)
for (const [name, path, code] of [
  ['next-app', 'app/api/webhooks/billing/route.ts', "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'subscription.created') await grantPro(event.data.customer);\n  return new Response('ok');\n}\n"],
  ['next-pages', 'pages/api/webhooks/paddle.ts', "export default async function handler(req, res) {\n  const event = req.body;\n  if (event.event_type === 'subscription.created') await grantPro(event.data.customer_id);\n  res.status(200).end();\n}\n"],
  ['express', 'server/routes/webhooks.ts', "router.post('/webhooks/lemonsqueezy', express.json(), async (req, res) => {\n  const event = req.body;\n  if (event.meta.event_name === 'order_created') await grantPro(event.data.attributes.user_email);\n  res.sendStatus(200);\n});\n"],
  ['remix', 'app/routes/api.webhooks.iyzico.ts', "export async function action({ request }) {\n  const event = await request.json();\n  if (event.status === 'SUCCESS') await grantPro(event.paymentId);\n  return new Response('ok');\n}\n"],
] as const) cases.push({ id: `webhook-nosig:${name}`, expect: 'detect', rules: [8143, 9704], ...R(path, code) });
// Client-controlled price across payment providers (SAAS-04)
for (const [name, call] of [
  ['stripe', 'stripe.checkout.sessions.create({ line_items: [{ price: priceId, quantity: 1 }] })'],
  ['paddle', 'paddle.transactions.create({ items: [{ priceId: priceId, quantity: 1 }] })'],
  ['lemonsqueezy', 'createCheckout(storeId, variantId, {})'],
  ['paypal', "paypal.orders.create({ purchase_units: [{ amount: { currency_code: 'USD', value: amount } }] })"],
  ['iyzico', "iyzipay.checkoutFormInitialize.create({ price: amount, paidPrice: amount, currency: 'TRY' }, cb)"],
  ['razorpay', "razorpay.orders.create({ amount: amount, currency: 'INR' })"],
] as const) cases.push({ id: `client-price:${name}`, expect: 'detect', rules: [23004], ...R('app/api/checkout/route.ts', `export async function POST(req: Request) {\n  const { priceId, variantId, amount, storeId } = await req.json();\n  const r = await ${call};\n  return Response.json(r);\n}\n`) });
// LLM max tokens missing across providers (8071 / 4001 / 141)
for (const [name, code] of [
  ['openai', "await openai.chat.completions.create({ model: 'gpt-4o', messages })"],
  ['anthropic', "await anthropic.messages.create({ model: 'claude', messages })"],
  ['ai-sdk', "await generateText({ model: openai('gpt-4o'), prompt })"],
  ['gemini', "await genAI.getGenerativeModel({ model: 'gemini-2.0-flash' }).generateContent(prompt)"],
  ['langchain', "await new ChatOpenAI({ model: 'gpt-4o' }).invoke(prompt)"],
  ['bedrock', "await bedrock.send(new ConverseCommand({ modelId, messages }))"],
] as const) cases.push({ id: `llm-no-limit:${name}`, expect: 'detect', rules: [8071, 4001, 141], ...R('app/api/ai/route.ts', `export async function POST(req: Request) {\n  const { prompt, messages } = await req.json();\n  const r = ${code};\n  return Response.json(r);\n}\n`) });
// Prompt injection across providers (SAAS-07)
for (const [name, code] of [
  ['gemini-systemInstruction', "genAI.getGenerativeModel({ model: 'gemini-2.0-flash', systemInstruction: `Act as ${persona}` })"],
  ['langchain-SystemMessage', 'model.invoke([new SystemMessage(`You are ${persona}`), new HumanMessage(q)])'],
  ['cohere-preamble', 'cohere.chat({ message: q, preamble: `You are ${persona}` })'],
] as const) cases.push({ id: `prompt-inj:${name}`, expect: 'detect', rules: [23007], ...R('app/api/ai/route.ts', `export async function POST(req: Request) {\n  const { persona, q } = await req.json();\n  return Response.json(await ${code});\n}\n`) });
// Cron without secret across platforms (SAAS-06)
for (const [name, path] of [['next-app', 'app/api/cron/sync/route.ts'], ['pages-router', 'pages/api/cron/daily.ts'], ['express', 'server/routes/index.ts']] as const) {
  const body = name === 'express' ? "router.get('/cron/daily', async (req, res) => {\n  await syncAll();\n  res.json({ ok: true });\n});\n" : 'export async function GET() {\n  await syncAll();\n  return Response.json({ ok: true });\n}\n';
  cases.push({ id: `cron:${name}`, expect: 'detect', rules: [23006], ...R(path, body) });
}
// Rate limiting recognised across libraries: AI route WITH limiter must be clean (10402)
for (const [name, guard] of [['upstash', 'const { success } = await ratelimit.limit(ip);'], ['arcjet', 'const decision = await aj.protect(req);'], ['unkey', 'const { success } = await unkey.limits.limit(ip);'], ['express-rate-limit', 'await limiter(req);']] as const)
  cases.push({ id: `ai-ratelimited:${name}`, expect: 'clean', rules: [10402], ...R('app/api/ai/route.ts', `import OpenAI from 'openai';\nexport async function POST(req: Request) {\n  ${guard}\n  const { prompt } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 200, messages: [{ role: 'user', content: prompt }] }));\n}\n`) });
// Timing-unsafe compare in Python (SAAS-05)
cases.push({ id: 'webhook-verified:paddle', expect: 'clean', rules: [8143, 9704], ...R('app/api/webhooks/paddle/route.ts', "export async function POST(req: Request) {\n  const signature = req.headers.get('paddle-signature') ?? '';\n  const event = await paddle.webhooks.unmarshal(await req.text(), process.env.PADDLE_WEBHOOK_SECRET!, signature);\n  return new Response('ok');\n}\n") });
cases.push({ id: 'webhook-verified:express-hmac', expect: 'clean', rules: [8143, 9704], ...R('server/routes/webhooks.ts', "router.post('/webhooks/lemonsqueezy', express.raw({ type: 'application/json' }), (req, res) => {\n  const digest = crypto.createHmac('sha256', process.env.LS_WEBHOOK_SECRET!).update(req.body).digest('hex');\n  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(req.get('X-Signature') ?? ''))) return res.sendStatus(401);\n  res.sendStatus(200);\n});\n") });
cases.push({ id: 'timing:python', expect: 'detect', rules: [23005], ...R('app/views.py', "def hook(request):\n    if request.headers.get('X-Secret') != os.environ['WEBHOOK_SECRET']:\n        return HttpResponse(status=401)\n") });

// Regression: an id taken from the verified session is not a request-supplied id
cases.push({ id: 'session-id-lookup:supabase-admin', expect: 'clean', rules: [9106], ...R('app/api/me/route.ts', "export async function GET() {\n  const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n  const { data: { user } } = await supabase.auth.getUser();\n  const { data } = await admin.from('profiles').select('*').eq('id', user!.id).single();\n  return Response.json(data);\n}\n") });
// Outbound notification senders are not webhook receivers, but still need caller auth
cases.push({ id: 'outbound-webhook-sender:not-a-receiver', expect: 'clean', rules: [8143], ...R('app/api/test-webhook/route.ts', "export async function POST(req: Request) {\n  const { slackWebhookUrl } = await req.json();\n  await fetch(slackWebhookUrl, { method: 'POST', body: JSON.stringify({ text: 'test' }) });\n  return Response.json({ ok: true });\n}\n") });
cases.push({ id: 'outbound-webhook-sender:unauthenticated', expect: 'detect', rules: [15], ...R('app/api/test-webhook/route.ts', "export async function POST(req: Request) {\n  const { slackWebhookUrl } = await req.json();\n  await fetch(slackWebhookUrl, { method: 'POST', body: JSON.stringify({ text: 'test' }) });\n  return Response.json({ ok: true });\n}\n") });
// RLS only matters when clients can reach the database directly (Supabase / PostgREST)
cases.push({ id: 'rls:prisma-server-only', expect: 'clean', rules: [3001, 6010], ...R('prisma/migrations/20240101_init/migration.sql', 'CREATE TABLE "Article" ("id" SERIAL PRIMARY KEY, "title" TEXT NOT NULL);\n') });
// Python: ORM .exec() / .execute() are not the eval/exec builtins
cases.push({ id: 'python-exec:sqlmodel-session', expect: 'clean', rules: [8811], ...R('backend/app/api/routes/items.py', 'def read_items(session: SessionDep):\n    count_statement = select(func.count()).select_from(Item)\n    count = session.exec(count_statement).one()\n    return count\n') });
cases.push({ id: 'python-exec:builtin', expect: 'detect', rules: [8811], ...R('app/tools.py', 'def run(code):\n    exec(code)\n') });
// SSRF: SDKs fetching their own configured endpoints are not SSRF
cases.push({ id: 'ssrf:sdk-own-endpoint', expect: 'clean', rules: [34], ...R('src/FunctionsClient.ts', "export class FunctionsClient {\n  constructor(private url: string) {}\n  async invoke(name: string) {\n    const url = `${this.url}/${name}`;\n    return fetch(url, { method: 'POST' });\n  }\n}\n") });

// A variable merely named after SSRF is not a guard
cases.push({ id: 'ssrf:guard-word-in-variable-name', expect: 'detect', rules: [34], ...R('routes/profileImageUrlUpload.ts', "export const upload = () => async (req, res) => {\n  const url = req.body.imageUrl;\n  if (url.match(/server-side/)) req.app.locals.abused_ssrf_bug = true;\n  const response = await fetch(url);\n  res.send(await response.text());\n};\n") });
// Command injection needs dynamic or request-derived input, not a constant named `command`
cases.push({ id: 'cmd-injection:constant-command', expect: 'clean', rules: [33], ...R('scripts/format.js', "const { execSync } = require('child_process')\nconst command = process.env.CI ? 'npx prettier --check .' : 'npx prettier --write .'\nexecSync(command, { stdio: 'inherit' })\n") });
cases.push({ id: 'cmd-injection:request-var', expect: 'detect', rules: [33], ...R('app/api/ping/route.ts', "import { exec } from 'child_process';\nexport async function POST(req: Request) {\n  const { host } = await req.json();\n  exec('ping -c 1 ' + host);\n  return new Response('ok');\n}\n") });
// PyJWT decode with key + algorithms verifies; disabling verification does not
cases.push({ id: 'jwt-decode:pyjwt-verified', expect: 'clean', rules: [39], ...R('app/api/deps.py', 'def get_current_user(token: str):\n    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[security.ALGORITHM])\n    return payload\n') });
cases.push({ id: 'jwt-decode:pyjwt-unverified', expect: 'detect', rules: [39], ...R('app/api/deps.py', 'def get_current_user(token: str):\n    return jwt.decode(token, options={"verify_signature": False})\n') });
// A React settings page about webhooks is not a webhook receiver
cases.push({ id: 'webhook:ui-settings-page', expect: 'clean', rules: [8143], ...R('apps/remix/app/routes/settings.webhooks.$id._index.tsx', "export default function WebhookPage() {\n  const { data } = useWebhook();\n  return <WebhookForm webhook={data} />;\n}\n") });
// Developer scripts: interpolated git/tooling commands are not request-driven injection
cases.push({ id: 'cmd-injection:dev-script-template', expect: 'clean', rules: [33], ...R('scripts/release-canary.ts', "import { execSync } from 'child_process'\nconst tag = execSync('git describe --tags --abbrev=0').toString().trim()\nconst log = execSync(`git log ${tag}..HEAD --oneline`).toString()\nconsole.log(log)\n") });
cases.push({ id: 'cmd-injection:server-template', expect: 'detect', rules: [33], ...R('server/convert.ts', "import { exec } from 'child_process'\nexport function convert(file: string) {\n  exec(`convert ${file} out.png`)\n}\n") });
// Vendored / minified third-party libraries are not the customer's code
cases.push({ id: 'vendored:static-js-lib', expect: 'clean', rules: [32], ...R('djangoproject/static/js/lib/require.js', 'define=function(b){return eval(b)};\n') });
cases.push({ id: 'minified:bundle-without-min-suffix', expect: 'clean', rules: [32], ...R('public/app.js', 'var a=' + JSON.stringify('x'.repeat(6000)) + ';eval(a);') });
cases.push({ id: 'eval:app-code', expect: 'detect', rules: [32], ...R('routes/contributions.js', 'exports.handle = (req, res) => {\n  const preTax = eval(req.body.preTax);\n  res.json({ preTax });\n};\n') });
// CORE-01..08 across languages: vulnerable form detected, safe form clean
const core: [string, number, 'detect' | 'clean', string, string][] = [
  ['sqli:java-concat', 24101, 'detect', 'src/main/java/app/UserRepo.java', 'class UserRepo {\n  List<User> find(String name) throws Exception {\n    String query = "SELECT * FROM users WHERE name = \'" + name + "\'";\n    return jdbc.createStatement().executeQuery(query);\n  }\n}\n'],
  ['sqli:java-prepared', 24101, 'clean', 'src/main/java/app/UserRepo.java', 'class UserRepo {\n  List<User> find(String name) throws Exception {\n    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");\n    ps.setString(1, name);\n    return ps.executeQuery();\n  }\n}\n'],
  ['sqli:ruby-where-interp', 24101, 'detect', 'app/controllers/users_controller.rb', 'class UsersController < ApplicationController\n  def show\n    @user = User.where("id = \'#{params[:id]}\'").first\n  end\nend\n'],
  ['sqli:ruby-where-hash', 24101, 'clean', 'app/controllers/users_controller.rb', 'class UsersController < ApplicationController\n  def show\n    @user = User.where(id: params[:id]).first\n  end\nend\n'],
  ['sqli:ruby-quoted-table-name', 24101, 'clean', 'app/models/download.rb', 'class Download < ApplicationRecord\n  def bump\n    connection.execute("UPDATE #{quoted_table_name} SET count = count + 1")\n  end\nend\n'],
  ['sqli:php-interp', 24101, 'detect', 'src/user.php', '<?php\n$id = $_GET["id"];\n$result = mysqli_query($db, "SELECT * FROM users WHERE id = \'$id\'");\n'],
  ['sqli:php-prepared', 24101, 'clean', 'src/user.php', '<?php\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$_GET["id"]]);\n'],
  ['sqli:python-fstring', 24101, 'detect', 'app/db.py', 'def find(cur, name):\n    cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'],
  ['sqli:python-params', 24101, 'clean', 'app/db.py', 'def find(cur, name):\n    cur.execute("SELECT * FROM users WHERE name = %s", (name,))\n'],
  ['sqli:csharp-interp', 24101, 'detect', 'Data/UserRepo.cs', 'public class UserRepo {\n  public User Find(string name) {\n    var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = \'{name}\'", conn);\n    return Map(cmd.ExecuteReader());\n  }\n}\n'],
  ['sqli:go-sprintf', 24101, 'detect', 'store/users.go', 'func Find(db *sql.DB, name string) {\n\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE name = \'%s\'", name))\n}\n'],
  ['cmd:ruby-system-interp', 24102, 'detect', 'app/models/backup.rb', 'class Backup\n  def run(file)\n    system("cp #{file} /backups/")\n  end\nend\n'],
  ['cmd:ruby-system-args', 24102, 'clean', 'app/models/backup.rb', 'class Backup\n  def run(file)\n    system("cp", file, "/backups/")\n  end\nend\n'],
  ['cmd:php-shell-exec', 24102, 'detect', 'ping.php', "<?php\n$target = $_POST['ip'];\n$out = shell_exec('ping -c 4 ' . $target);\n"],
  ['cmd:python-shell-true', 24102, 'detect', 'app/tools.py', 'import subprocess\ndef convert(name):\n    subprocess.run("convert " + name, shell=True)\n'],
  ['cmd:python-arg-list', 24102, 'clean', 'app/tools.py', 'import subprocess\ndef convert(name):\n    subprocess.run(["convert", name], check=True)\n'],
  ['cmd:django-management-command', 24102, 'clean', 'docs/management/commands/update_docs.py', 'import subprocess\ndef handle(path):\n    subprocess.check_call("cd %s && make html" % path, shell=True)\n'],
  ['deser:ruby-marshal', 24103, 'detect', 'app/controllers/sessions_controller.rb', 'class SessionsController < ApplicationController\n  def restore\n    user = Marshal.load(Base64.decode64(params[:user]))\n  end\nend\n'],
  ['deser:python-pickle', 24103, 'detect', 'app/views.py', 'import pickle\ndef load(request):\n    return pickle.loads(request.body)\n'],
  ['deser:python-yaml-safe', 24103, 'clean', 'app/config.py', 'import yaml\ndef load(text):\n    return yaml.load(text, Loader=yaml.SafeLoader)\n'],
  ['deser:java-objectinputstream', 24103, 'detect', 'src/main/java/app/Importer.java', 'class Importer {\n  Object read(InputStream in) throws Exception {\n    ObjectInputStream ois = new ObjectInputStream(in);\n    return ois.readObject();\n  }\n}\n'],
  ['xxe:java-default-factory', 24104, 'detect', 'src/main/java/app/XmlParser.java', 'class XmlParser {\n  Document parse(InputStream in) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    return f.newDocumentBuilder().parse(in);\n  }\n}\n'],
  ['xxe:java-hardened-factory', 24104, 'clean', 'src/main/java/app/XmlParser.java', 'class XmlParser {\n  Document parse(InputStream in) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n    return f.newDocumentBuilder().parse(in);\n  }\n}\n'],
  ['xss:erb-html-safe-params', 24105, 'detect', 'app/views/users/show.html.erb', '<h1><%= params[:name].html_safe %></h1>\n'],
  ['xss:erb-html-safe-trusted', 24105, 'clean', 'app/views/layouts/application.html.erb', '<%= render_icon_svg.html_safe %>\n'],
  ['xss:ruby-interp-params', 24105, 'detect', 'app/controllers/password_resets_controller.rb', 'class PasswordResetsController < ApplicationController\n  def create\n    flash[:error] = "Could not send email to #{params[:email]}".html_safe\n  end\nend\n'],
  ['xss:php-echo-get', 24105, 'detect', 'hello.php', "<?php\necho 'Hello ' . $_GET['name'];\n"],
  ['xss:php-escaped', 24105, 'clean', 'hello.php', "<?php\necho 'Hello ' . htmlspecialchars($name, ENT_QUOTES);\n"],
  ['xss:django-safe-on-admin-content', 24105, 'clean', 'templates/blog/entry.html', '<h1>{{ entry.headline|safe }}</h1>\n'],
  ['xss:email-autoescape-off', 24105, 'clean', 'templates/registration/password_reset_email.html', '{% autoescape off %}Reset: {{ url }}{% endautoescape %}\n'],
  ['xss:jinja-autoescape-false', 24105, 'detect', 'app/app.py', "setup_jinja(app, loader=PackageLoader('app', 'templates'), autoescape=False)\n"],
  ['include:php-request-path', 24106, 'detect', 'index.php', "<?php\n$file = $_GET['page'];\ninclude($file);\n"],
  ['include:php-constant-path', 24106, 'clean', 'index.php', "<?php\n$file = __DIR__ . '/views/home.php';\ninclude($file);\n"],
  ['upload:php-unchecked', 24107, 'detect', 'upload.php', "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);\n"],
  ['upload:php-checked-extension', 24107, 'clean', 'upload.php', "<?php\n$ext = pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);\nif (!in_array($ext, ['jpg', 'png'])) exit;\nmove_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . bin2hex(random_bytes(8)) . '.' . $ext);\n"],
  ['weakhash:python-password-md5', 24108, 'detect', 'app/auth.py', 'from hashlib import md5\ndef store(password):\n    return md5(password.encode()).hexdigest()\n'],
  ['weakhash:checksum-md5', 24108, 'clean', 'scripts/s3_utils.py', 'import hashlib\ndef checksum(body):\n    return hashlib.md5(body).hexdigest()\n'],
  ['weakhash:java-md5-password', 24108, 'detect', 'src/main/java/app/Hasher.java', 'class Hasher {\n  byte[] hashPassword(String password) throws Exception {\n    return MessageDigest.getInstance("MD5").digest(password.getBytes());\n  }\n}\n']
];
for (const [id, rule, expect, path, content] of core) cases.push({ id: `core-${id}`, expect, rules: [rule], ...R(path, content) });
