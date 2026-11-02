import crypto from 'node:crypto';
import type { Dependency, OsvEcosystem } from './dependencies';

export type SbomFormat = 'cyclonedx' | 'spdx';

const PURL_TYPE: Record<OsvEcosystem, string> = {
  npm: 'npm',
  PyPI: 'pypi',
  Go: 'golang',
  RubyGems: 'gem',
  Packagist: 'composer',
  'crates.io': 'cargo',
  Maven: 'maven',
};

/** Package URL for a dependency. Name segments are encoded, the slashes between them are not. */
export function purlFor(dep: Pick<Dependency, 'ecosystem' | 'name' | 'version'>): string {
  const raw = dep.ecosystem === 'Maven' ? dep.name.replace(':', '/') : dep.ecosystem === 'PyPI' ? dep.name.toLowerCase().replace(/[-_.]+/g, '-') : dep.name;
  const name = raw.split('/').map(encodeURIComponent).join('/');
  return `pkg:${PURL_TYPE[dep.ecosystem]}/${name}@${encodeURIComponent(dep.version)}`;
}

/** One entry per package and version: a package listed in two lockfiles is one component. */
function uniqueSorted(deps: Dependency[]): (Dependency & { purl: string })[] {
  const byPurl = new Map<string, Dependency & { purl: string }>();
  for (const dep of deps) {
    const purl = purlFor(dep);
    const seen = byPurl.get(purl);
    // Shipped anywhere counts as shipped.
    if (!seen) byPurl.set(purl, { ...dep, purl });
    else if (!dep.dev) seen.dev = false;
  }
  return [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

/** License fields stay out or NOASSERTION: lockfiles do not record licenses and Zelsis does not guess them. */
export function buildSbom(deps: Dependency[], { format, projectName, now = new Date() }: { format: SbomFormat; projectName?: string; now?: Date }) {
  const name = projectName || 'project';
  const components = uniqueSorted(deps);
  const created = now.toISOString().replace(/\.\d{3}Z$/, 'Z');

  if (format === 'cyclonedx') {
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: created,
        tools: { components: [{ type: 'application', name: 'Zelsis' }] },
        component: { type: 'application', name },
      },
      components: components.map((c) => ({
        type: 'library',
        'bom-ref': c.purl,
        name: c.name,
        version: c.version,
        purl: c.purl,
        scope: c.dev ? 'excluded' : 'required',
      })),
    };
  }

  const root = 'SPDXRef-Project';
  const packages = components.map((c, i) => ({
    SPDXID: `SPDXRef-Package-${i + 1}`,
    name: c.name,
    versionInfo: c.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl }],
  }));
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name,
    documentNamespace: `https://zelsis.com/spdx/${encodeURIComponent(name)}-${crypto.randomUUID()}`,
    creationInfo: { created, creators: ['Tool: Zelsis'] },
    packages: [
      { SPDXID: root, name, downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION' },
      ...packages,
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: root },
      ...packages.map((p) => ({ spdxElementId: root, relationshipType: 'DEPENDS_ON', relatedSpdxElement: p.SPDXID })),
    ],
  };
}
