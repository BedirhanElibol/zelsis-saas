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

test('pnpm marks build-only packages as dev (v6 flag, v9 graph from importers)', () => {
  const v6 = "lockfileVersion: '6.0'\n\ndependencies:\n  next:\n    version: 14.0.0\n\ndevDependencies:\n  esbuild:\n    version: 0.18.20\n\npackages:\n\n  /next@14.0.0:\n    resolution: {}\n    dev: false\n\n  /esbuild@0.18.20:\n    resolution: {}\n    dev: true\n";
  assert.deepEqual(deps('pnpm-lock.yaml', v6).map((s) => s.split('#')[0]), ['npm:next@14.0.0', 'npm:esbuild@0.18.20:dev']);

  const v9 = [
    "lockfileVersion: '9.0'", '', 'importers:', '', '  .:', '    dependencies:', '      next:', '        specifier: ^15.0.0',
    '        version: 15.0.0(react@19.0.0)', '    devDependencies:', '      drizzle-kit:', '        specifier: ^0.31.0', '        version: 0.31.1', '',
    'packages:', '', '  next@15.0.0:', '    resolution: {}', '', '  postcss@8.4.31:', '    resolution: {}', '', '  drizzle-kit@0.31.1:', '    resolution: {}', '',
    '  esbuild@0.18.20:', '    resolution: {}', '', 'snapshots:', '', '  next@15.0.0(react@19.0.0):', '    dependencies:', '      postcss: 8.4.31', '',
    '  postcss@8.4.31: {}', '', '  drizzle-kit@0.31.1:', '    dependencies:', '      esbuild: 0.18.20', '', '  esbuild@0.18.20: {}', ''
  ].join('\n');
  // postcss is reached through next (shipped); esbuild only through drizzle-kit (build tooling)
  assert.deepEqual(deps('pnpm-lock.yaml', v9).map((s) => s.split('#')[0]), [
    'npm:next@15.0.0', 'npm:postcss@8.4.31', 'npm:drizzle-kit@0.31.1:dev', 'npm:esbuild@0.18.20:dev'
  ]);
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

test('bun.lock text format keeps exact versions, skips workspace refs', () => {
  const lock = '{\n  "lockfileVersion": 1,\n  "packages": {\n    "react": ["react@18.3.1", "", {}, "sha512-x"],\n    "@types/node": ["@types/node@20.11.5", "", {}, "sha512-y"],\n    "app": ["app@workspace:packages/app"],\n  }\n}';
  assert.deepEqual(deps('bun.lock', lock), ['npm:react@18.3.1#4', 'npm:@types/node@20.11.5#5']);
});

test('pubspec.lock lists hosted packages and marks direct dev ones', () => {
  const lock = 'packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n    source: hosted\n    version: "0.13.5"\n  flutter_lints:\n    dependency: "direct dev"\n    source: hosted\n    version: "2.0.1"\n  flutter:\n    dependency: "direct main"\n    source: sdk\n    version: "0.0.0"\nsdks:\n  dart: ">=3.0.0"\n';
  assert.deepEqual(deps('app/pubspec.lock', lock), ['Pub:http@0.13.5#2', 'Pub:flutter_lints@2.0.1:dev#8']);
});

test('NuGet packages.lock.json, csproj and packages.config', () => {
  const lock = '{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1"},"MyLib":{"type":"Project"}}}}';
  assert.deepEqual(deps('src/packages.lock.json', lock), ['NuGet:Newtonsoft.Json@13.0.1#1']);
  const csproj = '<Project>\n  <ItemGroup>\n    <PackageReference Include="Serilog" Version="3.1.1" />\n    <PackageReference Include="Floating" Version="3.*" />\n    <PackageReference Include="Dapper">\n      <Version>2.1.24</Version>\n    </PackageReference>\n  </ItemGroup>\n</Project>';
  assert.deepEqual(deps('src/Api/Api.csproj', csproj), ['NuGet:Serilog@3.1.1#3', 'NuGet:Dapper@2.1.24#5']);
  assert.deepEqual(deps('packages.config', '<packages>\n  <package id="jQuery" version="3.4.1" targetFramework="net48" />\n</packages>'), ['NuGet:jQuery@3.4.1#2']);
  assert.deepEqual(deps('Directory.Packages.props', '<Project>\n  <ItemGroup>\n    <PackageVersion Include="Ardalis.ApiEndpoints" Version="4.1.0" />\n  </ItemGroup>\n</Project>'), ['NuGet:Ardalis.ApiEndpoints@4.1.0#3']);
});

test('gradle.lockfile and version catalog', () => {
  const lock = '# comment\ncom.squareup.okhttp3:okhttp:4.9.0=debugRuntimeClasspath,releaseRuntimeClasspath\njunit:junit:4.13.2=testRuntimeClasspath\nempty=annotationProcessor\n';
  assert.deepEqual(deps('app/gradle.lockfile', lock), ['Maven:com.squareup.okhttp3:okhttp@4.9.0#2', 'Maven:junit:junit@4.13.2:dev#3']);
  const toml = '[versions]\nretrofit = "2.9.0"\n\n[libraries]\nretrofit = { module = "com.squareup.retrofit2:retrofit", version.ref = "retrofit" }\ngson = { group = "com.google.code.gson", name = "gson", version = "2.10.1" }\ncoil = "io.coil-kt:coil:2.5.0"\ndynamic = { module = "a.b:c", version.ref = "missing" }\n';
  assert.deepEqual(deps('gradle/libs.versions.toml', toml), ['Maven:com.squareup.retrofit2:retrofit@2.9.0#5', 'Maven:com.google.code.gson:gson@2.10.1#6', 'Maven:io.coil-kt:coil@2.5.0#7']);
});

test('SwiftPM Package.resolved v2 and v1 use the repository URL as the name', () => {
  const v2 = '{\n  "pins" : [\n    {\n      "identity" : "swift-nio",\n      "kind" : "remoteSourceControl",\n      "location" : "https://github.com/apple/swift-nio.git",\n      "state" : { "revision" : "abc", "version" : "2.58.0" }\n    },\n    {\n      "identity" : "branchy",\n      "location" : "https://github.com/a/branchy.git",\n      "state" : { "branch" : "main", "revision" : "def" }\n    }\n  ],\n  "version" : 2\n}';
  assert.deepEqual(deps('App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved', v2), ['SwiftURL:github.com/apple/swift-nio@2.58.0#6']);
  const v1 = '{"object":{"pins":[{"package":"Alamofire","repositoryURL":"https://github.com/Alamofire/Alamofire.git","state":{"version":"5.6.4"}}]},"version":1}';
  assert.deepEqual(deps('Package.resolved', v1), ['SwiftURL:github.com/Alamofire/Alamofire@5.6.4#1']);
});
