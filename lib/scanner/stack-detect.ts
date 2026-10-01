import type { CodeFile } from './types';

/** Label used until the first scan detects the real stack. */
export const UNDETECTED_FRAMEWORK = 'Auto-detect';

const base = (path: string) => path.replace(/\\/g, '/').split('/').pop()!.toLowerCase();

/** JS framework from package.json dependencies, most specific first. */
const JS_FRAMEWORKS: [string, string][] = [
  ['next', 'Next.js'], ['@remix-run/react', 'Remix'], ['@react-router/dev', 'React Router'], ['@sveltejs/kit', 'SvelteKit'],
  ['nuxt', 'Nuxt'], ['astro', 'Astro'], ['@angular/core', 'Angular'], ['@nestjs/core', 'NestJS'], ['expo', 'Expo (React Native)'],
  ['react-native', 'React Native'], ['hono', 'Hono'], ['fastify', 'Fastify'], ['koa', 'Koa'], ['express', 'Express'],
  ['solid-js', 'SolidJS'], ['svelte', 'Svelte'], ['vue', 'Vue'], ['react', 'React']
];

/** Non-JS frameworks: [manifest file, dependency pattern, label]. */
const OTHER_FRAMEWORKS: [RegExp, RegExp, string][] = [
  [/^(?:requirements.*\.txt|pyproject\.toml|pipfile)$/, /\bdjango\b/i, 'Django'],
  [/^(?:requirements.*\.txt|pyproject\.toml|pipfile)$/, /\bfastapi\b/i, 'FastAPI'],
  [/^(?:requirements.*\.txt|pyproject\.toml|pipfile)$/, /\bflask\b/i, 'Flask'],
  [/^gemfile$/, /['"]rails['"]/, 'Ruby on Rails'],
  [/^composer\.json$/, /laravel\/framework/, 'Laravel'],
  [/^composer\.json$/, /symfony\/framework-bundle/, 'Symfony'],
  [/^go\.mod$/, /gin-gonic\/gin/, 'Go (Gin)'],
  [/^go\.mod$/, /labstack\/echo/, 'Go (Echo)'],
  [/^go\.mod$/, /gofiber\/fiber/, 'Go (Fiber)'],
  [/^go\.mod$/, /^module\s/m, 'Go'],
  [/^(?:pom\.xml|build\.gradle(?:\.kts)?)$/, /spring-boot/, 'Spring Boot'],
  [/^cargo\.toml$/, /\b(?:axum|actix-web|rocket)\b/, 'Rust (web)'],
  [/^pubspec\.yaml$/, /\bflutter\b/, 'Flutter'],
  [/\.csproj$/, /Microsoft\.AspNetCore|Sdk="Microsoft\.NET\.Sdk\.Web"/, 'ASP.NET Core']
];

/** Hosting / CI providers from their config files. */
const PROVIDER_FILES: [RegExp, string][] = [
  [/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/, 'GitHub Actions'],
  [/(?:^|\/)\.gitlab-ci\.yml$/, 'GitLab CI'],
  [/(?:^|\/)\.circleci\/config\.yml$/, 'CircleCI'],
  [/(?:^|\/)bitbucket-pipelines\.yml$/, 'Bitbucket Pipelines'],
  [/(?:^|\/)vercel\.json$/, 'Vercel'],
  [/(?:^|\/)netlify\.toml$/, 'Netlify'],
  [/(?:^|\/)wrangler\.(?:toml|jsonc?)$/, 'Cloudflare'],
  [/(?:^|\/)fly\.toml$/, 'Fly.io'],
  [/(?:^|\/)render\.yaml$/, 'Render'],
  [/(?:^|\/)railway\.(?:json|toml)$/, 'Railway'],
  [/(?:^|\/)firebase\.json$/, 'Firebase'],
  [/(?:^|\/)(?:serverless\.ya?ml|template\.ya?ml|cdk\.json|samconfig\.toml)$/, 'AWS'],
  [/(?:^|\/)app\.yaml$/, 'Google App Engine'],
  [/(?:^|\/)(?:Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)$/i, 'Docker'],
  [/(?:^|\/)(?:Chart\.yaml|kustomization\.ya?ml)$/, 'Kubernetes'],
  [/\.tf$/, 'Terraform']
];

export interface DetectedAppStack {
  framework: string | null;
  providers: string[];
}

/** Detects the application framework and hosting/CI providers from manifest and config files. */
export function detectAppStack(files: CodeFile[]): DetectedAppStack {
  let framework: string | null = null;

  const rootPkg = files
    .filter((f) => base(f.path) === 'package.json' && !f.path.includes('node_modules/'))
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length);
  for (const pkgFile of rootPkg) {
    try {
      const pkg = JSON.parse(pkgFile.content || '{}');
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const hit = JS_FRAMEWORKS.find(([dep]) => dep in deps);
      if (hit) { framework = hit[1]; break; }
    } catch {
      // Ignore malformed package.json
    }
  }

  if (!framework) {
    for (const [manifest, dep, label] of OTHER_FRAMEWORKS) {
      if (files.some((f) => manifest.test(base(f.path)) && dep.test(f.content || ''))) { framework = label; break; }
    }
  }

  const providers = PROVIDER_FILES.filter(([pattern]) => files.some((f) => pattern.test(f.path))).map(([, label]) => label);
  return { framework, providers };
}

/** Framework choices offered in the UI: everything the detector knows, plus auto-detect first. */
export const FRAMEWORK_CHOICES: string[] = [
  UNDETECTED_FRAMEWORK,
  ...Array.from(new Set([...JS_FRAMEWORKS.map(([, label]) => label), ...OTHER_FRAMEWORKS.map(([, , label]) => label)])),
  'Other'
];
