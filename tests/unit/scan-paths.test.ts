import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isScannableTreePath } from '../../lib/scanner/scan-paths';

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
