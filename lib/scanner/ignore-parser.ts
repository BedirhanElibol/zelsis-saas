/**
 * .zelsisignore parser. Each line is a rule code (e.g. `DB-PERF-12`), a bare rule id, or a path.
 */

/** Named aliases checked before any prefix pattern. */
const ALIAS_RULE_IDS: Record<string, number[]> = {
  'UI-A11Y-01': [26, 1026], 'UI-A11Y': [26, 1026], 'UI-26': [26, 1026],
  'UI-PERF-01': [27, 1027], 'UI-PERF': [27, 1027], 'UI-27': [27, 1027],
  'UI-SEO-01': [28, 1028], 'UI-SEO': [28, 1028], 'UI-28': [28, 1028],
  'SEC-SCA-01': [20], 'SEC-SCA': [20], 'SEC-20': [20],
  'SEC-LOG-01': [21], 'SEC-LOG': [21], 'SEC-21': [21],
  'SEC-LLM-01': [22], 'SEC-LLM': [22], 'SEC-22': [22]
};

/**
 * Rule-code prefixes mapped to rule id offsets: `<PREFIX>-<n>` suppresses `offset + n` for each offset.
 * Order matters: the first matching pattern wins.
 */
const PREFIX_OFFSETS: ReadonlyArray<readonly [RegExp, readonly number[]]> = [
  [/^SEC-?(\d+)$/i, [0]],
  [/^SAAS-?(\d+)$/i, [23000]],
  [/^JS-SEC-?(\d+)$/i, [24000]],
  [/^CORE-?(\d+)$/i, [24100]],
  [/^LLM-?(\d+)$/i, [4000, 0]],
  [/^CLICHE-?(\d+)$/i, [200]],
  [/^UI-INTERACT-?(\d+)$/i, [1200]],
  [/^SEC-SECRET-?(\d+)$/i, [5000]],
  [/^DB-PERF-?(\d+)$/i, [6000]],
  [/^CLOUD-?(\d+)$/i, [7000]],
  [/^(?:WEB-PERF|PERF)-?(\d+)$/i, [7100]],
  [/^API-?(\d+)$/i, [7200]],
  [/^(?:SUPPLY|SBOM)-?(\d+)$/i, [7300]],
  [/^LLM-SEC-?(\d+)$/i, [8000]],
  [/^ZERO-AUTH-?(\d+)$/i, [8100]],
  [/^PRIVACY-?(\d+)$/i, [8200]],
  [/^IAC-?(\d+)$/i, [8300]],
  [/^CHAOS-?(\d+)$/i, [8400]],
  [/^GQL-?(\d+)$/i, [8500]],
  [/^(?:NEXT15|NEXT)-?(\d+)$/i, [8600]],
  [/^WEB3-?(\d+)$/i, [8700]],
  [/^(?:PY-SEC|PY)-?(\d+)$/i, [8800]],
  [/^K8S-?(\d+)$/i, [8900]],
  [/^GO-?(\d+)$/i, [9000]],
  [/^TENANT-?(\d+)$/i, [9100]],
  [/^CLOUD-SEC-?(\d+)$/i, [9200]],
  [/^MOB-SEC-?(\d+)$/i, [9300]],
  [/^EVENT-?(\d+)$/i, [9400]],
  [/^CICD-SEC-?(\d+)$/i, [9500]],
  [/^RUST-?(\d+)$/i, [9600]],
  [/^FINTECH-?(\d+)$/i, [9700]],
  [/^HIPAA-?(\d+)$/i, [9800]],
  [/^OTEL-?(\d+)$/i, [9900]],
  [/^(?:CPP-SEC|CPP)-?(\d+)$/i, [10000]],
  [/^ECOMM-?(\d+)$/i, [10100]],
  [/^GRPC-?(\d+)$/i, [10200]],
  [/^PG-?(\d+)$/i, [10300]],
  [/^WAF-?(\d+)$/i, [10400]],
  [/^WS-?(\d+)$/i, [10500]],
  [/^SOC2-?(\d+)$/i, [10600]],
  [/^CACHE-?(\d+)$/i, [10700]],
  [/^ISO-?(\d+)$/i, [10800]],
  [/^OAUTH-?(\d+)$/i, [10900]],
  [/^TF-?(\d+)$/i, [11000]],
  [/^CDN-?(\d+)$/i, [11100]],
  [/^MESH-?(\d+)$/i, [11200]],
  [/^SLS-?(\d+)$/i, [11300]],
  [/^GW-?(\d+)$/i, [11400]],
  [/^DATA-?(\d+)$/i, [11500]],
  [/^AIACT-?(\d+)$/i, [11600]],
  [/^CRON-?(\d+)$/i, [11700]],
  [/^DNS-?(\d+)$/i, [11800]],
  [/^NIST-?(\d+)$/i, [11900]],
  [/^GRPH-?(\d+)$/i, [12000]],
  [/^AUDIT-?(\d+)$/i, [12100]],
  [/^CONTAINER-?(\d+)$/i, [12200]],
  [/^TLS-?(\d+)$/i, [12300]],
  [/^DORA-?(\d+)$/i, [12400]],
  [/^MQ-?(\d+)$/i, [12500]],
  [/^SBOM-?(\d+)$/i, [12600]],
  [/^WASM-?(\d+)$/i, [12700]],
  [/^SSO-?(\d+)$/i, [12800]],
  [/^PCI4-?(\d+)$/i, [12900]],
  [/^SEARCH-?(\d+)$/i, [13000]],
  [/^SDP-?(\d+)$/i, [13100]],
  [/^OPA-?(\d+)$/i, [13200]],
  [/^CRYPTO-?(\d+)$/i, [13300]],
  [/^SOX-?(\d+)$/i, [13400]],
  [/^VECTOR-?(\d+)$/i, [13500]],
  [/^THREAT-?(\d+)$/i, [13600]],
  [/^FED-?(\d+)$/i, [13700]],
  [/^ASVS-?(\d+)$/i, [13800]],
  [/^FEDRAMP-?(\d+)$/i, [13900]],
  [/^TSDB-?(\d+)$/i, [14000]],
  [/^SLSA-?(\d+)$/i, [14100]],
  [/^EBPF-?(\d+)$/i, [14200]],
  [/^APIDEF-?(\d+)$/i, [14300]],
  [/^HIPAASEC-?(\d+)$/i, [14400]],
  [/^MQOPT-?(\d+)$/i, [14500]],
  [/^RASP-?(\d+)$/i, [14600]],
  [/^GRPCSEC-?(\d+)$/i, [14700]],
  [/^CSPM-?(\d+)$/i, [14800]],
  [/^GLBA-?(\d+)$/i, [14900]],
  [/^GEODIST-?(\d+)$/i, [15000]],
  [/^DECEPTION-?(\d+)$/i, [15100]],
  [/^WASM-EDGE-?(\d+)$/i, [15200]],
  [/^PQC-?(\d+)$/i, [15300]],
  [/^NIS2-?(\d+)$/i, [15400]],
  [/^SHARD-?(\d+)$/i, [15500]],
  [/^CTI-?(\d+)$/i, [15600]],
  [/^KERN-SEC-?(\d+)$/i, [15700]],
  [/^ISO20022-?(\d+)$/i, [15800]],
  [/^TSDB-OPT-?(\d+)$/i, [15900]],
  [/^AI-RED-?(\d+)$/i, [16000]],
  [/^FABRIC-?(\d+)$/i, [16100]],
  [/^QUANT-RISK-?(\d+)$/i, [16200]],
  [/^LLM-ORCH-?(\d+)$/i, [16300]],
  [/^CONF-COMPUTE-?(\d+)$/i, [16400]],
  [/^FED-LEARN-?(\d+)$/i, [16500]],
  [/^VEC-OPT-?(\d+)$/i, [16600]],
  [/^QKD-?(\d+)$/i, [16700]],
  [/^SPACE-MESH-?(\d+)$/i, [16800]],
  [/^AI-ETHICS-?(\d+)$/i, [16900]],
  [/^FHE-SEC-?(\d+)$/i, [17000]],
  [/^NEURO-COMP-?(\d+)$/i, [17100]],
  [/^AV-SAFETY-?(\d+)$/i, [17200]],
  [/^EDGE-AI-OPT-?(\d+)$/i, [17300]],
  [/^QRNG-?(\d+)$/i, [17400]],
  [/^MED-DEV-?(\d+)$/i, [17500]],
  [/^VEC-CACHE-?(\d+)$/i, [17600]],
  [/^DNA-STORE-?(\d+)$/i, [17700]],
  [/^SUBSEA-OPT-?(\d+)$/i, [17800]],
  [/^ZK-ROLLUP-?(\d+)$/i, [17900]],
  [/^DO178C-?(\d+)$/i, [18000]],
  [/^OPT-SWITCH-?(\d+)$/i, [18100]],
  [/^BCI-SEC-?(\d+)$/i, [18200]],
  [/^SCADA-SEC-?(\d+)$/i, [18300]],
  [/^SPACE-GNC-?(\d+)$/i, [18400]],
  [/^EUV-LITHO-?(\d+)$/i, [18500]],
  [/^IAEA-SAFE-?(\d+)$/i, [18600]],
  [/^HYPERS-FLT-?(\d+)$/i, [18700]],
  [/^MARITIME-COL-?(\d+)$/i, [18800]],
  [/^HFT-SEC-?(\d+)$/i, [18900]],
  [/^PATHOGEN-BIO-?(\d+)$/i, [19000]],
  [/^GEOTHERM-ENG-?(\d+)$/i, [19100]],
  [/^LAUNCH-FAA-?(\d+)$/i, [19200]],
  [/^CPO-OPTICS-?(\d+)$/i, [19300]],
  [/^MEV-DEFENSE-?(\d+)$/i, [19400]],
  [/^BIOREACT-ENG-?(\d+)$/i, [19500]],
  [/^HAPS-STRAT-?(\d+)$/i, [19600]],
  [/^DAC-CARBON-?(\d+)$/i, [19700]],
  [/^RAIL-PTC-?(\d+)$/i, [19800]],
  [/^SYNCHRO-PMU-?(\d+)$/i, [19900]],
  [/^ALE-PLASMA-?(\d+)$/i, [20000]],
  [/^DID-CRED-?(\d+)$/i, [20100]],
  [/^SUB-REACTOR-?(\d+)$/i, [20200]],
  [/^LIDAR-SPACE-?(\d+)$/i, [20300]],
  [/^FLOW-TOXIC-?(\d+)$/i, [20400]],
  [/^SSB-ANODE-?(\d+)$/i, [20500]],
  [/^SUBSEA-ACOU-?(\d+)$/i, [20600]],
  [/^NEUTRON-NDT-?(\d+)$/i, [20700]],
  [/^HYPER-SPECT-?(\d+)$/i, [20800]],
  [/^HVDC-GRID-?(\d+)$/i, [20900]],
  [/^CRYO-HYDRO-?(\d+)$/i, [21000]],
  [/^ZKML-PROOF-?(\d+)$/i, [21100]],
  [/^TOKAMAK-PLASMA-?(\d+)$/i, [21200]],
  [/^SAT-SWARM-?(\d+)$/i, [21300]],
  [/^PHOTON-QC-?(\d+)$/i, [21400]],
  [/^DEEPSEA-ROV-?(\d+)$/i, [21500]],
  [/^SYNBIO-GENE-?(\d+)$/i, [21600]],
  [/^BCI-NEURAL-?(\d+)$/i, [21700]],
  [/^AERO-TRAJECT-?(\d+)$/i, [21800]],
  [/^DIVERTOR-EROSION-?(\d+)$/i, [21900]],
  [/^ORGAN-CHIP-?(\d+)$/i, [22000]],
  [/^QUANTUM-BELL-?(\d+)$/i, [22100]],
  [/^UI-?(\d+)$/i, [0, 1000]],
];

/** Legacy compliance (2001-2020) and infra (3001-3020) ids also exist as short 1-20 aliases. */
function addPillarAlias(ids: Set<number>, num: number, base: number): void {
  if (num >= 1 && num <= 20) {
    ids.add(base + num);
    ids.add(num);
  } else if (num >= base + 1 && num <= base + 20) {
    ids.add(num);
    ids.add(num - base);
  } else {
    ids.add(num);
  }
}

function addRawRuleId(ids: Set<number>, num: number, includeUiMirror: boolean): void {
  ids.add(num);
  if (num >= 2001 && num <= 2020) ids.add(num - 2000);
  else if (num >= 3001 && num <= 3020) ids.add(num - 3000);
  else if (num >= 4001 && num <= 4020) ids.add(num - 4000);
  else if (includeUiMirror && num < 1000) ids.add(num + 1000);
}

/**
 * Parses .zelsisignore (or legacy .shipguardignore) file lines to filter out suppressed rule IDs or file paths.
 */
export function parseZelsisIgnore(ignoreContent: string): { ignoredRuleIds: Set<number>; ignoredPaths: string[] } {
  const ignoredRuleIds = new Set<number>();
  const ignoredPaths: string[] = [];

  if (!ignoreContent) return { ignoredRuleIds, ignoredPaths };

  for (const line of ignoreContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const alias = ALIAS_RULE_IDS[trimmed.toUpperCase()];
    if (alias) {
      alias.forEach((id) => ignoredRuleIds.add(id));
      continue;
    }

    const prefixed = PREFIX_OFFSETS.find(([pattern]) => pattern.test(trimmed));
    if (prefixed) {
      const num = parseInt(trimmed.match(prefixed[0])![1], 10);
      prefixed[1].forEach((offset) => ignoredRuleIds.add(offset + num));
      continue;
    }

    const compl = trimmed.match(/^COMPL-?(\d+)$/i);
    const infra = trimmed.match(/^INFRA-?(\d+)$/i);
    const rule = trimmed.match(/^RULE-?(\d+)$/i);
    const bare = trimmed.match(/^(\d+)$/);
    if (compl) addPillarAlias(ignoredRuleIds, parseInt(compl[1], 10), 2000);
    else if (infra) addPillarAlias(ignoredRuleIds, parseInt(infra[1], 10), 3000);
    else if (rule) addRawRuleId(ignoredRuleIds, parseInt(rule[1], 10), false);
    else if (bare) addRawRuleId(ignoredRuleIds, parseInt(bare[1], 10), true);
    else ignoredPaths.push(trimmed.toLowerCase());
  }

  return { ignoredRuleIds, ignoredPaths };
}

export const parseShipguardIgnore = parseZelsisIgnore;
