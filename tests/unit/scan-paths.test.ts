import { describe, it, test } from 'node:test';
import assert from 'node:assert/strict';
import { PUBLIC_ARTIFACT, isScannableTreePath, withPublicArtifactPaths } from '../../lib/scanner/scan-paths';
import { isVendoredPath } from '../../lib/scanner/text';

describe('isVendoredPath', () => {
  it('detects versioned, slim, bundle and minified library assets anywhere in the tree', () => {
    for (const p of [
      'lib/flipper/ui/public/js/jquery-3.6.0.slim.js',
      'public/assets/foo-1.2.3.min.js',
      'app/static/bootstrap.bundle.min.js',
      'vendor/d3.js',
    ]) {
      assert.equal(isVendoredPath(p), true, p);
    }
    for (const p of ['src/components/CodeBlock.tsx', 'app/page.tsx', 'lib/rules/security-rules.ts']) {
      assert.equal(isVendoredPath(p), false, p);
    }
  });
});

describe('isScannableTreePath', () => {
  it('keeps CI workflows (.github is not .git)', () => {
    assert.equal(isScannableTreePath('.github/workflows/ci.yml'), true);
    assert.equal(isScannableTreePath('.github/dependabot.yml'), true);
  });

  it('keeps infrastructure and server config files', () => {
    for (const p of ['infra/main.tf', 'infra/prod.tfvars', 'deploy/nomad.hcl', 'nginx/nginx.conf', 'src/main/resources/application.properties',
      '.npmrc', '.yarnrc', '.gitmodules', '.dockerignore', 'Dockerfile', 'docker/Dockerfile.prod', 'requirements.txt', 'app/page.tsx']) {
      assert.equal(isScannableTreePath(p), true, p);
    }
  });

  it('skips git internals, dependencies and build output', () => {
    for (const p of ['.git/config', 'node_modules/a/index.js', 'dist/app.js', 'web/build/main.js', '.next/server/page.js', 'vendor/lib.php',
      '.venv/lib/python3.12/site-packages/x.py', 'src/__pycache__/a.py', 'logo.png']) {
      assert.equal(isScannableTreePath(p), false, p);
    }
  });
});

test('PUBLIC_ARTIFACT matches secrets and dumps in served folders only', () => {
  for (const p of ['public/.env', 'public/.env.local', 'public/dump.sql', 'static/terraform.tfstate', 'apps/web/public/db/site.sql.gz', 'public/private-key.pem', 'public/id_rsa', 'public/app.log'])
    assert.ok(PUBLIC_ARTIFACT.test(p), p);
  for (const p of ['public/.env.example', 'public/cert.pem', 'public/logo.svg', 'supabase/seed.sql', '.env', 'public/catalog.json'])
    assert.equal(PUBLIC_ARTIFACT.test(p), false, p);
});

test('withPublicArtifactPaths adds skipped public artifacts as path-only files, once', () => {
  const tree = [
    { type: 'blob', path: 'public/huge-dump.sql' },
    { type: 'blob', path: 'public/state.tfstate' },
    { type: 'blob', path: 'public/logo.svg' },
    { type: 'blob', path: 'node_modules/x/public/a.sql' },
    { type: 'tree', path: 'public' },
  ];
  const files = [{ path: 'public/state.tfstate', content: '{}' }];
  const out = withPublicArtifactPaths(tree, files);
  assert.deepEqual(out.map((f) => f.path), ['public/state.tfstate', 'public/huge-dump.sql']);
  assert.equal(out[1].content, '');
  assert.equal(withPublicArtifactPaths([], files), files);
});
