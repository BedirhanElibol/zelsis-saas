import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractDependencies, isDependencyLockfile } from '@/lib/scanner/dependencies';

const deps = (path: string, content: string) =>
  extractDependencies([{ path, content }]).map((d) => `${d.ecosystem}:${d.name}@${d.version}${d.dev ? ':dev' : ''}#${d.line}`);

test('package-lock v3 lists every installed package with dev flag', () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/lodash': { version: '4.17.15' },
      'node_modules/@babel/core': { version: '7.20.0', dev: true },
      'node_modules/a/node_modules/minimist': { version: '0.0.8' },
      'node_modules/local': { link: true }
    }
  }, null, 2);
  const out = deps('package-lock.json', lock);
  assert.deepEqual(out.map((s) => s.split('#')[0]).sort(), ['npm:@babel/core@7.20.0:dev', 'npm:lodash@4.17.15', 'npm:minimist@0.0.8']);
  assert.ok(out.find((s) => s.startsWith('npm:lodash'))!.endsWith('#8'));
});

test('package-lock v1 nested dependencies', () => {
  const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { express: { version: '4.16.0', dependencies: { qs: { version: '6.5.1' } } } } });
  assert.deepEqual(deps('package-lock.json', lock).map((s) => s.split('#')[0]), ['npm:express@4.16.0', 'npm:qs@6.5.1']);
});

test('yarn v1 and berry lockfiles', () => {
  const v1 = '# yarn lockfile v1\n\n"@types/node@^18.0.0", "@types/node@^18.1.0":\n  version "18.11.9"\n\nlodash@^4.17.0:\n  version "4.17.20"\n';
  assert.deepEqual(deps('yarn.lock', v1), ['npm:@types/node@18.11.9#3', 'npm:lodash@4.17.20#6']);
  const berry = '__metadata:\n  version: 6\n\n"axios@npm:^0.21.0":\n  version: 0.21.1\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n';
  assert.deepEqual(deps('yarn.lock', berry).map((s) => s.split('#')[0]), ['npm:axios@0.21.1']);
});

test('pnpm lockfile v6 and v9 package keys', () => {
  const v6 = "lockfileVersion: '6.0'\n\ndependencies:\n  next:\n    version: 13.0.0\n\npackages:\n\n  /next@13.0.0(react@18.2.0):\n    resolution: {}\n  /@scope/pkg@1.2.3:\n    resolution: {}\n";
  assert.deepEqual(deps('pnpm-lock.yaml', v6).map((s) => s.split('#')[0]), ['npm:next@13.0.0', 'npm:@scope/pkg@1.2.3']);
  const v9 = "lockfileVersion: '9.0'\n\npackages:\n\n  'semver@7.5.1':\n    resolution: {}\n\nsnapshots:\n\n  semver@7.5.1: {}\n";
  assert.deepEqual(deps('pnpm-lock.yaml', v9).map((s) => s.split('#')[0]), ['npm:semver@7.5.1']);
});

test('python: requirements pins only, Pipfile.lock, poetry.lock', () => {
  assert.deepEqual(
    deps('requirements.txt', 'django==3.2.0  # web\nrequests>=2.0\nurllib3[socks]==1.26.4 ; python_version > "3"\n-e .\n').map((s) => s.split('#')[0]),
    ['PyPI:django@3.2.0', 'PyPI:urllib3@1.26.4']
  );
  const pipfile = JSON.stringify({ default: { flask: { version: '==1.0' } }, develop: { pytest: { version: '==7.0.0' } } });
  assert.deepEqual(deps('Pipfile.lock', pipfile).map((s) => s.split('#')[0]), ['PyPI:flask@1.0', 'PyPI:pytest@7.0.0:dev']);
  const poetry = '[[package]]\nname = "jinja2"\nversion = "2.10"\ncategory = "main"\n\n[[package]]\nname = "black"\nversion = "22.1.0"\ncategory = "dev"\n\n[metadata]\nlock-version = "1.1"\n';
  assert.deepEqual(deps('poetry.lock', poetry), ['PyPI:jinja2@2.10#1', 'PyPI:black@22.1.0:dev#6']);
});

test('ruby, php, rust, go and maven', () => {
  const gem = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.3-x86_64-linux)\n      racc (~> 1.4)\n    rails (6.1.0)\n\nPLATFORMS\n  ruby\n';
  assert.deepEqual(deps('Gemfile.lock', gem).map((s) => s.split('#')[0]), ['RubyGems:nokogiri@1.13.3', 'RubyGems:rails@6.1.0']);
  const composer = JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.4.0' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }, { name: 'x/y', version: 'dev-main' }] });
  assert.deepEqual(deps('composer.lock', composer).map((s) => s.split('#')[0]), ['Packagist:guzzlehttp/guzzle@7.4.0', 'Packagist:phpunit/phpunit@9.5.0:dev']);
  assert.deepEqual(deps('Cargo.lock', '[[package]]\nname = "hyper"\nversion = "0.14.0"\nsource = "registry"\n').map((s) => s.split('#')[0]), ['crates.io:hyper@0.14.0']);
  const gomod = 'module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n\nrequire (\n\tgolang.org/x/net v0.7.0 // indirect\n\tgithub.com/x/y v2.0.0+incompatible\n)\n';
  assert.deepEqual(deps('go.mod', gomod).map((s) => s.split('#')[0]), ['Go:github.com/gin-gonic/gin@1.6.0', 'Go:golang.org/x/net@0.7.0', 'Go:github.com/x/y@2.0.0']);
  const pom = '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency><dependency><groupId>a</groupId><artifactId>b</artifactId><version>${b.version}</version></dependency></dependencies></project>';
  assert.deepEqual(deps('pom.xml', pom).map((s) => s.split('#')[0]), ['Maven:org.apache.logging.log4j:log4j-core@2.14.1']);
});

test('go.sum is used only without a sibling go.mod; duplicates collapse', () => {
  const sum = 'github.com/a/b v1.0.0 h1:abc=\ngithub.com/a/b v1.0.0/go.mod h1:def=\n';
  assert.equal(extractDependencies([{ path: 'go.sum', content: sum }]).length, 1);
  assert.equal(extractDependencies([{ path: 'go.sum', content: sum }, { path: 'go.mod', content: 'module x\n' }]).length, 0);
});

test('lockfiles are recognised; package.json ranges are not versions', () => {
  assert.ok(isDependencyLockfile('apps/web/pnpm-lock.yaml'));
  assert.ok(isDependencyLockfile('Gemfile.lock'));
  assert.ok(!isDependencyLockfile('package.json'));
  assert.equal(extractDependencies([{ path: 'package.json', content: '{"dependencies":{"lodash":"^4.17.15"}}' }]).length, 0);
});
