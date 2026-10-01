import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectAppStack } from '../../lib/scanner/stack-detect';

const pkg = (deps: Record<string, string>) => ({ path: 'package.json', content: JSON.stringify({ dependencies: deps }) });

describe('detectAppStack', () => {
  const cases: [string, { path: string; content: string }[], string | null][] = [
    ['Next.js', [pkg({ next: '15.2.3', react: '19.0.0' })], 'Next.js'],
    ['Remix', [pkg({ '@remix-run/react': '2.0.0', react: '18.0.0' })], 'Remix'],
    ['SvelteKit', [pkg({ '@sveltejs/kit': '2.0.0', svelte: '5.0.0' })], 'SvelteKit'],
    ['Express', [pkg({ express: '4.21.0' })], 'Express'],
    ['NestJS', [pkg({ '@nestjs/core': '10.0.0', express: '4.0.0' })], 'NestJS'],
    ['Django', [{ path: 'requirements.txt', content: 'Django==5.0\npsycopg==3.1\n' }], 'Django'],
    ['FastAPI', [{ path: 'pyproject.toml', content: '[project]\ndependencies = ["fastapi>=0.110"]\n' }], 'FastAPI'],
    ['Rails', [{ path: 'Gemfile', content: "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n" }], 'Ruby on Rails'],
    ['Laravel', [{ path: 'composer.json', content: '{"require":{"laravel/framework":"^11.0"}}' }], 'Laravel'],
    ['Go Gin', [{ path: 'go.mod', content: 'module example.com/app\nrequire github.com/gin-gonic/gin v1.10.0\n' }], 'Go (Gin)'],
    ['Spring Boot', [{ path: 'pom.xml', content: '<artifactId>spring-boot-starter-web</artifactId>' }], 'Spring Boot'],
    ['nothing known', [{ path: 'main.c', content: 'int main() {}' }], null]
  ];
  for (const [name, files, expected] of cases) {
    it(`detects ${name}`, () => assert.equal(detectAppStack(files).framework, expected));
  }

  it('prefers the root package.json in a monorepo', () => {
    const files = [{ path: 'apps/api/package.json', content: JSON.stringify({ dependencies: { express: '4' } }) }, pkg({ next: '15.2.3' })];
    assert.equal(detectAppStack(files).framework, 'Next.js');
  });

  it('detects hosting and CI from config files, not assumptions', () => {
    const { providers } = detectAppStack([
      { path: '.gitlab-ci.yml', content: '' },
      { path: 'netlify.toml', content: '' },
      { path: 'Dockerfile', content: 'FROM node:22' }
    ]);
    assert.deepEqual(providers.sort(), ['Docker', 'GitLab CI', 'Netlify']);
    assert.deepEqual(detectAppStack([{ path: 'src/index.ts', content: '' }]).providers, []);
  });
});
