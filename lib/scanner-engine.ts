import { evaluateAiCommentRules } from './rules/ai-comment-rules';
import { Finding, SecurityRule, UiRule } from '@/data/schema';
import { SECURITY_RULES_CATALOG, UI_RULES_CATALOG } from '@/data/mockData';
import { evaluateAiClicheRules } from './rules/ai-cliche-rules';
import { evaluateSecurityRules } from './rules/security-rules';
import { evaluateFrontendRules } from './rules/frontend-rules';
import { evaluateComplianceRules } from './rules/compliance-rules';
import { evaluateInfraRules } from './rules/infra-rules';
import { evaluateInteractionRules } from './rules/interaction-rules';
import { evaluateSecretRules } from './rules/secrets-rules';
import { evaluateDatabaseRules } from './rules/database-rules';
import { evaluateCloudNativeRules } from './rules/cloud-native-rules';
import { evaluateWebVitalsRules } from './rules/web-vitals-rules';
import { evaluateApiRules } from './rules/api-rules';
import { evaluateSupplyChainRules } from './rules/supply-chain-rules';
import { evaluateAiSafetyRules } from './rules/ai-safety-rules';
import { evaluateZeroTrustRules } from './rules/zero-trust-rules';
import { evaluatePrivacyComplianceRules } from './rules/privacy-compliance-rules';
import { evaluateIacRules } from './rules/iac-rules';
import { evaluateChaosResilienceRules } from './rules/chaos-resilience-rules';
import { evaluateGraphqlSecurityRules } from './rules/graphql-security-rules';
import { evaluateModernFullstackRules } from './rules/modern-fullstack-rules';
import { evaluateWeb3SecurityRules } from './rules/web3-security-rules';
import { evaluatePythonEnterpriseRules } from './rules/python-enterprise-rules';
import { evaluatePolyglotBackendRules } from './rules/polyglot-backend-rules';
import { evaluateMultiDatabaseRules, detectProjectDatabases } from './rules/multi-database-rules';
import { evaluateK8sHardeningRules } from './rules/k8s-hardening-rules';
import { evaluateGoMicroservicesRules } from './rules/go-microservices-rules';
import { evaluateTenantIsolationRules } from './rules/tenant-isolation-rules';
import { evaluateCloudSecurityRules } from './rules/cloud-security-rules';
import { evaluateMobileSecurityRules } from './rules/mobile-security-rules';
import { evaluateEventStreamingRules } from './rules/event-streaming-rules';
import { evaluateCicdSupplyChainRules } from './rules/cicd-supplychain-rules';
import { evaluateRustSystemsRules } from './rules/rust-systems-rules';
import { evaluateFintechComplianceRules } from './rules/fintech-compliance-rules';
import { evaluateHipaaComplianceRules } from './rules/hipaa-compliance-rules';
import { evaluateOtelObservabilityRules } from './rules/otel-observability-rules';
import { evaluateCppMemoryRules } from './rules/cpp-memory-rules';
import { evaluateEcommInventoryRules } from './rules/ecomm-inventory-rules';
import { evaluateGrpcProtobufRules } from './rules/grpc-protobuf-rules';
import { evaluatePgvectorPostgresRules } from './rules/pgvector-postgres-rules';
import { evaluateWafEdgeRules } from './rules/waf-edge-rules';
import { evaluateWebsocketRealtimeRules } from './rules/websocket-realtime-rules';
import { evaluateSoc2AuditRules } from './rules/soc2-audit-rules';
import { evaluateCacheRedisRules } from './rules/cache-redis-rules';
import { evaluateIso27001ComplianceRules } from './rules/iso27001-compliance-rules';
import { evaluateOauthOidcRules } from './rules/oauth-oidc-rules';
import { evaluateTerraformIacRules } from './rules/terraform-iac-rules';
import { evaluateEdgeCdnRules } from './rules/edge-cdn-rules';
import { evaluateServiceMeshRules } from './rules/service-mesh-rules';
import { evaluateServerlessLambdaRules } from './rules/serverless-lambda-rules';
import { evaluateApiGatewayRules } from './rules/api-gateway-rules';
import { evaluateDataPipelineRules } from './rules/data-pipeline-rules';
import { evaluateEuAiActRules } from './rules/eu-ai-act-rules';
import { evaluateCronSchedulerRules } from './rules/cron-scheduler-rules';
import { evaluateDnsSecurityRules } from './rules/dns-security-rules';
import { evaluateNistSp80053Rules } from './rules/nist-sp800-53-rules';
import { evaluateGraphDatabaseRules } from './rules/graph-database-rules';
import { evaluateSiemAuditLoggingRules } from './rules/siem-audit-logging-rules';
import { evaluateContainerSecurityRules } from './rules/container-security-rules';
import { evaluateTlsCryptographyRules } from './rules/tls-cryptography-rules';
import { evaluateDoraComplianceRules } from './rules/dora-compliance-rules';
import { evaluateMessageBrokerRules } from './rules/message-broker-rules';
import { evaluateSbomAttestationRules } from './rules/sbom-attestation-rules';
import { evaluateWasmRuntimeRules } from './rules/wasm-runtime-rules';
import { evaluateEnterpriseSsoRules } from './rules/enterprise-sso-rules';
import { evaluatePciDssV4Rules } from './rules/pci-dss-v4-rules';
import { evaluateSearchEngineRules } from './rules/search-engine-rules';
import { evaluateZeroTrustNetworkRules } from './rules/zero-trust-network-rules';
import { evaluateOpaPolicyRules } from './rules/opa-policy-rules';
import { evaluateCryptoKmsRules } from './rules/crypto-kms-rules';
import { evaluateSoxComplianceRules } from './rules/sox-compliance-rules';
import { evaluateVectorDbRules } from './rules/vector-db-rules';
import { evaluateThreatDetectionRules } from './rules/threat-detection-rules';
import { evaluateGraphqlFederationRules } from './rules/graphql-federation-rules';
import { evaluateOwaspAsvsRules } from './rules/owasp-asvs-rules';
import { evaluateFedrampComplianceRules } from './rules/fedramp-compliance-rules';
import { evaluateTimeSeriesDbRules } from './rules/time-series-db-rules';
import { evaluateSlsaProvenanceRules } from './rules/slsa-provenance-rules';
import { evaluateEbpfObservabilityRules } from './rules/ebpf-observability-rules';
import { evaluateOwaspApiSecurityRules } from './rules/owasp-api-security-rules';
import { evaluateHipaaSecurityRules } from './rules/hipaa-security-rules';
import { evaluateMessageQueueOptRules } from './rules/message-queue-opt-rules';
import { evaluateRaspAntiTamperRules } from './rules/rasp-anti-tamper-rules';
import { evaluateGrpcWebSecurityRules } from './rules/grpc-web-security-rules';
import { evaluateCspmCloudPostureRules } from './rules/cspm-cloud-posture-rules';
import { evaluateGlbaComplianceRules } from './rules/glba-compliance-rules';
import { evaluateGeoDistributedDbRules } from './rules/geo-distributed-db-rules';
import { evaluateCyberDeceptionRules } from './rules/cyber-deception-rules';
import { evaluateWasmEdgeRuntimeRules } from './rules/wasm-edge-runtime-rules';
import { evaluateEuNis2ComplianceRules } from './rules/eu-nis2-compliance-rules';
import { evaluateDatabaseShardingRules } from './rules/database-sharding-rules';
import { evaluateThreatIntelligenceRules } from './rules/threat-intelligence-rules';
import { evaluateLinuxKernelSecurityRules } from './rules/linux-kernel-security-rules';
import { evaluateIso20022FintechRules } from './rules/iso20022-fintech-rules';
import { evaluateTimeSeriesDbOptRules } from './rules/time-series-db-opt-rules';
import { evaluateAiRedTeamSecurityRules } from './rules/ai-red-team-security-rules';
import { evaluateServiceFabricResilienceRules } from './rules/service-fabric-resilience-rules';
import { evaluateQuantitativeRiskRules } from './rules/quantitative-risk-rules';
import { evaluateMultiAgentOrchestrationRules } from './rules/multi-agent-orchestration-rules';
import { evaluateConfidentialComputingRules } from './rules/confidential-computing-rules';
import { evaluateFederatedLearningRules } from './rules/federated-learning-rules';
import { evaluateVectorIndexOptimizationRules } from './rules/vector-index-optimization-rules';
import { evaluateAiAgentEthicsGovernanceRules } from './rules/ai-agent-ethics-governance-rules';
import { evaluateEdgeAiModelQuantizationRules } from './rules/edge-ai-model-quantization-rules';
import { evaluateServerlessVectorCacheRules } from './rules/serverless-vector-cache-rules';
import { evaluateScaDependencyRules } from './rules/sca-dependency-rules';
import { evaluateStrixPentestRules } from './rules/strix-pentest-rules';
import { evaluateNoAiSlopRules } from './rules/no-ai-slop-rules';
import { evaluateLlmCostGovernanceRules } from './rules/llm-cost-governance-rules';

import { evaluateRubyRailsRules } from './rules/ruby-rails-rules';
import { evaluatePhpLaravelRules } from './rules/php-laravel-rules';
import { evaluateJavaSpringRules } from './rules/java-spring-rules';
import { evaluateDotnetCsharpRules } from './rules/dotnet-csharp-rules';


export interface CodeFile {
  path: string;
  content: string;
}

export interface ScanResult {
  score: number;
  gateStatus: 'PASSED' | 'WARNING' | 'FAILED';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  uiClicheCount: number;
  findings: Finding[];
  logs: string[];
  summary?: string;
  detectedDatabases?: string[];
  detectedOrms?: string[];
}

/**
 * Strips single-line (//), multi-line (/* ... *\/), and HTML (<!-- ... -->) comments
 * to prevent false positives in commented-out code snippets or documentation.
 */
export function stripComments(content: string): string {
  if (!content) return '';
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (match) => {
      // F-12 Remediation: Preserve newlines so AST/regex line numbers do not drift
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/<!--[\s\S]*?-->/g, (match) => {
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/(?<!:)\/\/.*$/gm, '');   // Single-line JS/TS comments (preserves http:// and https:// URLs)
}

/**
 * Parses .zelsisignore (or legacy .shipguardignore) file lines to filter out suppressed rule IDs or file paths.
 */
export function parseZelsisIgnore(ignoreContent: string): { ignoredRuleIds: Set<number>; ignoredPaths: string[] } {
  const ignoredRuleIds = new Set<number>();
  const ignoredPaths: string[] = [];

  if (!ignoreContent) return { ignoredRuleIds, ignoredPaths };

  const lines = ignoreContent.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const secMatch = trimmed.match(/^SEC-?(\d+)$/i);
    const uiMatch = trimmed.match(/^UI-?(\d+)$/i);
    const complMatch = trimmed.match(/^COMPL-?(\d+)$/i);
    const infraMatch = trimmed.match(/^INFRA-?(\d+)$/i);
    const ruleMatch = trimmed.match(/^RULE-?(\d+)$/i);
    const numMatch = trimmed.match(/^(\d+)$/);

    const llmMatch = trimmed.match(/^LLM-?(\d+)$/i);
    const clicheMatch = trimmed.match(/^CLICHE-?(\d+)$/i);
    const interactMatch = trimmed.match(/^UI-INTERACT-?(\d+)$/i);
    const secretMatch = trimmed.match(/^SEC-SECRET-?(\d+)$/i);
    const dbMatch = trimmed.match(/^DB-PERF-?(\d+)$/i);
    const cloudMatch = trimmed.match(/^CLOUD-?(\d+)$/i);
    const webPerfMatch = trimmed.match(/^(?:WEB-PERF|PERF)-?(\d+)$/i);
    const apiMatch = trimmed.match(/^API-?(\d+)$/i);
    const supplyMatch = trimmed.match(/^(?:SUPPLY|SBOM)-?(\d+)$/i);
    const llmSecMatch = trimmed.match(/^LLM-SEC-?(\d+)$/i);
    const zeroAuthMatch = trimmed.match(/^ZERO-AUTH-?(\d+)$/i);
    const privacyMatch = trimmed.match(/^PRIVACY-?(\d+)$/i);
    const iacMatch = trimmed.match(/^IAC-?(\d+)$/i);
    const chaosMatch = trimmed.match(/^CHAOS-?(\d+)$/i);
    const gqlMatch = trimmed.match(/^GQL-?(\d+)$/i);
    const next15Match = trimmed.match(/^(?:NEXT15|NEXT)-?(\d+)$/i);
    const web3Match = trimmed.match(/^WEB3-?(\d+)$/i);
    const pyMatch = trimmed.match(/^(?:PY-SEC|PY)-?(\d+)$/i);
    const k8sMatch = trimmed.match(/^K8S-?(\d+)$/i);
    const goMatch = trimmed.match(/^GO-?(\d+)$/i);
    const tenantMatch = trimmed.match(/^TENANT-?(\d+)$/i);
    const cloudSecMatch = trimmed.match(/^CLOUD-SEC-?(\d+)$/i);
    const mobSecMatch = trimmed.match(/^MOB-SEC-?(\d+)$/i);
    const eventMatch = trimmed.match(/^EVENT-?(\d+)$/i);
    const cicdSecMatch = trimmed.match(/^CICD-SEC-?(\d+)$/i);
    const rustMatch = trimmed.match(/^RUST-?(\d+)$/i);
    const fintechMatch = trimmed.match(/^FINTECH-?(\d+)$/i);
    const hipaaMatch = trimmed.match(/^HIPAA-?(\d+)$/i);
    const otelMatch = trimmed.match(/^OTEL-?(\d+)$/i);
    const cppMatch = trimmed.match(/^(?:CPP-SEC|CPP)-?(\d+)$/i);
    const ecommMatch = trimmed.match(/^ECOMM-?(\d+)$/i);
    const grpcMatch = trimmed.match(/^GRPC-?(\d+)$/i);
    const pgMatch = trimmed.match(/^PG-?(\d+)$/i);
    const wafMatch = trimmed.match(/^WAF-?(\d+)$/i);
    const wsMatch = trimmed.match(/^WS-?(\d+)$/i);
    const soc2Match = trimmed.match(/^SOC2-?(\d+)$/i);
    const cacheMatch = trimmed.match(/^CACHE-?(\d+)$/i);
    const isoMatch = trimmed.match(/^ISO-?(\d+)$/i);
    const oauthMatch = trimmed.match(/^OAUTH-?(\d+)$/i);
    const tfMatch = trimmed.match(/^TF-?(\d+)$/i);
    const cdnMatch = trimmed.match(/^CDN-?(\d+)$/i);
    const meshMatch = trimmed.match(/^MESH-?(\d+)$/i);
    const slsMatch = trimmed.match(/^SLS-?(\d+)$/i);
    const gwMatch = trimmed.match(/^GW-?(\d+)$/i);
    const dataMatch = trimmed.match(/^DATA-?(\d+)$/i);
    const aiactMatch = trimmed.match(/^AIACT-?(\d+)$/i);
    const cronMatch = trimmed.match(/^CRON-?(\d+)$/i);
    const dnsMatch = trimmed.match(/^DNS-?(\d+)$/i);
    const nistMatch = trimmed.match(/^NIST-?(\d+)$/i);
    const grphMatch = trimmed.match(/^GRPH-?(\d+)$/i);
    const auditMatch = trimmed.match(/^AUDIT-?(\d+)$/i);
    const containerMatch = trimmed.match(/^CONTAINER-?(\d+)$/i);
    const tlsMatch = trimmed.match(/^TLS-?(\d+)$/i);
    const doraMatch = trimmed.match(/^DORA-?(\d+)$/i);
    const mqMatch = trimmed.match(/^MQ-?(\d+)$/i);
    const sbomMatch = trimmed.match(/^SBOM-?(\d+)$/i);
    const wasmMatch = trimmed.match(/^WASM-?(\d+)$/i);
    const ssoMatch = trimmed.match(/^SSO-?(\d+)$/i);
    const pci4Match = trimmed.match(/^PCI4-?(\d+)$/i);
    const searchMatch = trimmed.match(/^SEARCH-?(\d+)$/i);
    const sdpMatch = trimmed.match(/^SDP-?(\d+)$/i);
    const opaMatch = trimmed.match(/^OPA-?(\d+)$/i);
    const cryptoMatch = trimmed.match(/^CRYPTO-?(\d+)$/i);
    const soxMatch = trimmed.match(/^SOX-?(\d+)$/i);
    const vectorMatch = trimmed.match(/^VECTOR-?(\d+)$/i);
    const threatMatch = trimmed.match(/^THREAT-?(\d+)$/i);
    const fedMatch = trimmed.match(/^FED-?(\d+)$/i);
    const asvsMatch = trimmed.match(/^ASVS-?(\d+)$/i);
    const fedrampMatch = trimmed.match(/^FEDRAMP-?(\d+)$/i);
    const tsdbMatch = trimmed.match(/^TSDB-?(\d+)$/i);
    const slsaMatch = trimmed.match(/^SLSA-?(\d+)$/i);
    const ebpfMatch = trimmed.match(/^EBPF-?(\d+)$/i);
    const apidefMatch = trimmed.match(/^APIDEF-?(\d+)$/i);
    const hipaasecMatch = trimmed.match(/^HIPAASEC-?(\d+)$/i);
    const mqoptMatch = trimmed.match(/^MQOPT-?(\d+)$/i);
    const raspMatch = trimmed.match(/^RASP-?(\d+)$/i);
    const grpcsecMatch = trimmed.match(/^GRPCSEC-?(\d+)$/i);
    const cspmMatch = trimmed.match(/^CSPM-?(\d+)$/i);
    const glbaMatch = trimmed.match(/^GLBA-?(\d+)$/i);
    const geodistMatch = trimmed.match(/^GEODIST-?(\d+)$/i);
    const deceptionMatch = trimmed.match(/^DECEPTION-?(\d+)$/i);
    const wasmEdgeMatch = trimmed.match(/^WASM-EDGE-?(\d+)$/i);
    const pqcMatch = trimmed.match(/^PQC-?(\d+)$/i);
    const nis2Match = trimmed.match(/^NIS2-?(\d+)$/i);
    const shardMatch = trimmed.match(/^SHARD-?(\d+)$/i);
    const ctiMatch = trimmed.match(/^CTI-?(\d+)$/i);
    const kernSecMatch = trimmed.match(/^KERN-SEC-?(\d+)$/i);
    const iso20022Match = trimmed.match(/^ISO20022-?(\d+)$/i);
    const tsdbOptMatch = trimmed.match(/^TSDB-OPT-?(\d+)$/i);
    const aiRedMatch = trimmed.match(/^AI-RED-?(\d+)$/i);
    const fabricMatch = trimmed.match(/^FABRIC-?(\d+)$/i);
    const quantRiskMatch = trimmed.match(/^QUANT-RISK-?(\d+)$/i);
    const llmOrchMatch = trimmed.match(/^LLM-ORCH-?(\d+)$/i);
    const confComputeMatch = trimmed.match(/^CONF-COMPUTE-?(\d+)$/i);
    const fedLearnMatch = trimmed.match(/^FED-LEARN-?(\d+)$/i);
    const vecOptMatch = trimmed.match(/^VEC-OPT-?(\d+)$/i);
    const qkdMatch = trimmed.match(/^QKD-?(\d+)$/i);
    const spaceMeshMatch = trimmed.match(/^SPACE-MESH-?(\d+)$/i);
    const aiEthicsMatch = trimmed.match(/^AI-ETHICS-?(\d+)$/i);
    const fheSecMatch = trimmed.match(/^FHE-SEC-?(\d+)$/i);
    const neuroCompMatch = trimmed.match(/^NEURO-COMP-?(\d+)$/i);
    const avSafetyMatch = trimmed.match(/^AV-SAFETY-?(\d+)$/i);
    const edgeAiOptMatch = trimmed.match(/^EDGE-AI-OPT-?(\d+)$/i);
    const qrngMatch = trimmed.match(/^QRNG-?(\d+)$/i);
    const medDevMatch = trimmed.match(/^MED-DEV-?(\d+)$/i);
    const vecCacheMatch = trimmed.match(/^VEC-CACHE-?(\d+)$/i);
    const dnaStoreMatch = trimmed.match(/^DNA-STORE-?(\d+)$/i);
    const subseaOptMatch = trimmed.match(/^SUBSEA-OPT-?(\d+)$/i);
    const zkRollupMatch = trimmed.match(/^ZK-ROLLUP-?(\d+)$/i);
    const do178cMatch = trimmed.match(/^DO178C-?(\d+)$/i);
    const optSwitchMatch = trimmed.match(/^OPT-SWITCH-?(\d+)$/i);
    const bciSecMatch = trimmed.match(/^BCI-SEC-?(\d+)$/i);
    const scadaSecMatch = trimmed.match(/^SCADA-SEC-?(\d+)$/i);
    const spaceGncMatch = trimmed.match(/^SPACE-GNC-?(\d+)$/i);
    const euvLithoMatch = trimmed.match(/^EUV-LITHO-?(\d+)$/i);
    const iaeaSafeMatch = trimmed.match(/^IAEA-SAFE-?(\d+)$/i);
    const hypersFltMatch = trimmed.match(/^HYPERS-FLT-?(\d+)$/i);
    const maritimeColMatch = trimmed.match(/^MARITIME-COL-?(\d+)$/i);
    const hftSecMatch = trimmed.match(/^HFT-SEC-?(\d+)$/i);
    const pathogenBioMatch = trimmed.match(/^PATHOGEN-BIO-?(\d+)$/i);
    const geothermEngMatch = trimmed.match(/^GEOTHERM-ENG-?(\d+)$/i);
    const launchFaaMatch = trimmed.match(/^LAUNCH-FAA-?(\d+)$/i);
    const cpoOpticsMatch = trimmed.match(/^CPO-OPTICS-?(\d+)$/i);
    const mevDefenseMatch = trimmed.match(/^MEV-DEFENSE-?(\d+)$/i);
    const bioreactEngMatch = trimmed.match(/^BIOREACT-ENG-?(\d+)$/i);
    const hapsStratMatch = trimmed.match(/^HAPS-STRAT-?(\d+)$/i);
    const dacCarbonMatch = trimmed.match(/^DAC-CARBON-?(\d+)$/i);
    const railPtcMatch = trimmed.match(/^RAIL-PTC-?(\d+)$/i);
    const synchroPmuMatch = trimmed.match(/^SYNCHRO-PMU-?(\d+)$/i);
    const alePlasmaMatch = trimmed.match(/^ALE-PLASMA-?(\d+)$/i);
    const didCredMatch = trimmed.match(/^DID-CRED-?(\d+)$/i);
    const subReactorMatch = trimmed.match(/^SUB-REACTOR-?(\d+)$/i);
    const lidarSpaceMatch = trimmed.match(/^LIDAR-SPACE-?(\d+)$/i);
    const flowToxicMatch = trimmed.match(/^FLOW-TOXIC-?(\d+)$/i);
    const ssbAnodeMatch = trimmed.match(/^SSB-ANODE-?(\d+)$/i);
    const subseaAcouMatch = trimmed.match(/^SUBSEA-ACOU-?(\d+)$/i);
    const neutronNdtMatch = trimmed.match(/^NEUTRON-NDT-?(\d+)$/i);
    const hyperSpectMatch = trimmed.match(/^HYPER-SPECT-?(\d+)$/i);
    const hvdcGridMatch = trimmed.match(/^HVDC-GRID-?(\d+)$/i);
    const cryoHydroMatch = trimmed.match(/^CRYO-HYDRO-?(\d+)$/i);
    const zkmlProofMatch = trimmed.match(/^ZKML-PROOF-?(\d+)$/i);
    const tokamakPlasmaMatch = trimmed.match(/^TOKAMAK-PLASMA-?(\d+)$/i);
    const satSwarmMatch = trimmed.match(/^SAT-SWARM-?(\d+)$/i);
    const photonQcMatch = trimmed.match(/^PHOTON-QC-?(\d+)$/i);
    const deepseaRovMatch = trimmed.match(/^DEEPSEA-ROV-?(\d+)$/i);
    const synbioGeneMatch = trimmed.match(/^SYNBIO-GENE-?(\d+)$/i);
    const bciNeuralMatch = trimmed.match(/^BCI-NEURAL-?(\d+)$/i);
    const aeroTrajectMatch = trimmed.match(/^AERO-TRAJECT-?(\d+)$/i);
    const divertorErosionMatch = trimmed.match(/^DIVERTOR-EROSION-?(\d+)$/i);
    const organChipMatch = trimmed.match(/^ORGAN-CHIP-?(\d+)$/i);
    const quantumBellMatch = trimmed.match(/^QUANTUM-BELL-?(\d+)$/i);

    const upper = trimmed.toUpperCase();
    if (upper === 'UI-A11Y-01' || upper === 'UI-A11Y' || upper === 'UI-26') {
      ignoredRuleIds.add(26);
      ignoredRuleIds.add(1026);
    } else if (upper === 'UI-PERF-01' || upper === 'UI-PERF' || upper === 'UI-27') {
      ignoredRuleIds.add(27);
      ignoredRuleIds.add(1027);
    } else if (upper === 'UI-SEO-01' || upper === 'UI-SEO' || upper === 'UI-28') {
      ignoredRuleIds.add(28);
      ignoredRuleIds.add(1028);
    } else if (upper === 'SEC-SCA-01' || upper === 'SEC-SCA' || upper === 'SEC-20') {
      ignoredRuleIds.add(20);
    } else if (upper === 'SEC-LOG-01' || upper === 'SEC-LOG' || upper === 'SEC-21') {
      ignoredRuleIds.add(21);
    } else if (upper === 'SEC-LLM-01' || upper === 'SEC-LLM' || upper === 'SEC-22') {
      ignoredRuleIds.add(22);
    } else if (secMatch) {
      const num = parseInt(secMatch[1], 10);
      if (!isNaN(num)) ignoredRuleIds.add(num);
    } else if (llmMatch) {
      const num = parseInt(llmMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(4000 + num);
        ignoredRuleIds.add(num);
      }
    } else if (clicheMatch) {
      const num = parseInt(clicheMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(200 + num);
      }
    } else if (interactMatch) {
      const num = parseInt(interactMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(1200 + num);
      }
    } else if (secretMatch) {
      const num = parseInt(secretMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(5000 + num);
      }
    } else if (dbMatch) {
      const num = parseInt(dbMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(6000 + num);
      }
    } else if (cloudMatch) {
      const num = parseInt(cloudMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(7000 + num);
      }
    } else if (webPerfMatch) {
      const num = parseInt(webPerfMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(7100 + num);
      }
    } else if (apiMatch) {
      const num = parseInt(apiMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(7200 + num);
      }
    } else if (supplyMatch) {
      const num = parseInt(supplyMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(7300 + num);
      }
    } else if (llmSecMatch) {
      const num = parseInt(llmSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8000 + num);
      }
    } else if (zeroAuthMatch) {
      const num = parseInt(zeroAuthMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8100 + num);
      }
    } else if (privacyMatch) {
      const num = parseInt(privacyMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8200 + num);
      }
    } else if (iacMatch) {
      const num = parseInt(iacMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8300 + num);
      }
    } else if (chaosMatch) {
      const num = parseInt(chaosMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8400 + num);
      }
    } else if (gqlMatch) {
      const num = parseInt(gqlMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8500 + num);
      }
    } else if (next15Match) {
      const num = parseInt(next15Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8600 + num);
      }
    } else if (web3Match) {
      const num = parseInt(web3Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8700 + num);
      }
    } else if (pyMatch) {
      const num = parseInt(pyMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8800 + num);
      }
    } else if (k8sMatch) {
      const num = parseInt(k8sMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(8900 + num);
      }
    } else if (goMatch) {
      const num = parseInt(goMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9000 + num);
      }
    } else if (tenantMatch) {
      const num = parseInt(tenantMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9100 + num);
      }
    } else if (cloudSecMatch) {
      const num = parseInt(cloudSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9200 + num);
      }
    } else if (mobSecMatch) {
      const num = parseInt(mobSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9300 + num);
      }
    } else if (eventMatch) {
      const num = parseInt(eventMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9400 + num);
      }
    } else if (cicdSecMatch) {
      const num = parseInt(cicdSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9500 + num);
      }
    } else if (rustMatch) {
      const num = parseInt(rustMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9600 + num);
      }
    } else if (fintechMatch) {
      const num = parseInt(fintechMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9700 + num);
      }
    } else if (hipaaMatch) {
      const num = parseInt(hipaaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9800 + num);
      }
    } else if (otelMatch) {
      const num = parseInt(otelMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(9900 + num);
      }
    } else if (cppMatch) {
      const num = parseInt(cppMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10000 + num);
      }
    } else if (ecommMatch) {
      const num = parseInt(ecommMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10100 + num);
      }
    } else if (grpcMatch) {
      const num = parseInt(grpcMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10200 + num);
      }
    } else if (pgMatch) {
      const num = parseInt(pgMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10300 + num);
      }
    } else if (wafMatch) {
      const num = parseInt(wafMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10400 + num);
      }
    } else if (wsMatch) {
      const num = parseInt(wsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10500 + num);
      }
    } else if (soc2Match) {
      const num = parseInt(soc2Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10600 + num);
      }
    } else if (cacheMatch) {
      const num = parseInt(cacheMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10700 + num);
      }
    } else if (isoMatch) {
      const num = parseInt(isoMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10800 + num);
      }
    } else if (oauthMatch) {
      const num = parseInt(oauthMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(10900 + num);
      }
    } else if (tfMatch) {
      const num = parseInt(tfMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11000 + num);
      }
    } else if (cdnMatch) {
      const num = parseInt(cdnMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11100 + num);
      }
    } else if (meshMatch) {
      const num = parseInt(meshMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11200 + num);
      }
    } else if (slsMatch) {
      const num = parseInt(slsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11300 + num);
      }
    } else if (gwMatch) {
      const num = parseInt(gwMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11400 + num);
      }
    } else if (dataMatch) {
      const num = parseInt(dataMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11500 + num);
      }
    } else if (aiactMatch) {
      const num = parseInt(aiactMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11600 + num);
      }
    } else if (cronMatch) {
      const num = parseInt(cronMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11700 + num);
      }
    } else if (dnsMatch) {
      const num = parseInt(dnsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11800 + num);
      }
    } else if (nistMatch) {
      const num = parseInt(nistMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(11900 + num);
      }
    } else if (grphMatch) {
      const num = parseInt(grphMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12000 + num);
      }
    } else if (auditMatch) {
      const num = parseInt(auditMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12100 + num);
      }
    } else if (containerMatch) {
      const num = parseInt(containerMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12200 + num);
      }
    } else if (tlsMatch) {
      const num = parseInt(tlsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12300 + num);
      }
    } else if (doraMatch) {
      const num = parseInt(doraMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12400 + num);
      }
    } else if (mqMatch) {
      const num = parseInt(mqMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12500 + num);
      }
    } else if (sbomMatch) {
      const num = parseInt(sbomMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12600 + num);
      }
    } else if (wasmMatch) {
      const num = parseInt(wasmMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12700 + num);
      }
    } else if (ssoMatch) {
      const num = parseInt(ssoMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12800 + num);
      }
    } else if (pci4Match) {
      const num = parseInt(pci4Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(12900 + num);
      }
    } else if (searchMatch) {
      const num = parseInt(searchMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13000 + num);
      }
    } else if (sdpMatch) {
      const num = parseInt(sdpMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13100 + num);
      }
    } else if (opaMatch) {
      const num = parseInt(opaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13200 + num);
      }
    } else if (cryptoMatch) {
      const num = parseInt(cryptoMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13300 + num);
      }
    } else if (soxMatch) {
      const num = parseInt(soxMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13400 + num);
      }
    } else if (vectorMatch) {
      const num = parseInt(vectorMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13500 + num);
      }
    } else if (threatMatch) {
      const num = parseInt(threatMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13600 + num);
      }
    } else if (fedMatch) {
      const num = parseInt(fedMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13700 + num);
      }
    } else if (asvsMatch) {
      const num = parseInt(asvsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13800 + num);
      }
    } else if (fedrampMatch) {
      const num = parseInt(fedrampMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(13900 + num);
      }
    } else if (tsdbMatch) {
      const num = parseInt(tsdbMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14000 + num);
      }
    } else if (slsaMatch) {
      const num = parseInt(slsaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14100 + num);
      }
    } else if (ebpfMatch) {
      const num = parseInt(ebpfMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14200 + num);
      }
    } else if (apidefMatch) {
      const num = parseInt(apidefMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14300 + num);
      }
    } else if (hipaasecMatch) {
      const num = parseInt(hipaasecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14400 + num);
      }
    } else if (mqoptMatch) {
      const num = parseInt(mqoptMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14500 + num);
      }
    } else if (raspMatch) {
      const num = parseInt(raspMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14600 + num);
      }
    } else if (grpcsecMatch) {
      const num = parseInt(grpcsecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14700 + num);
      }
    } else if (cspmMatch) {
      const num = parseInt(cspmMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14800 + num);
      }
    } else if (glbaMatch) {
      const num = parseInt(glbaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(14900 + num);
      }
    } else if (geodistMatch) {
      const num = parseInt(geodistMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15000 + num);
      }
    } else if (deceptionMatch) {
      const num = parseInt(deceptionMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15100 + num);
      }
    } else if (wasmEdgeMatch) {
      const num = parseInt(wasmEdgeMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15200 + num);
      }
    } else if (pqcMatch) {
      const num = parseInt(pqcMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15300 + num);
      }
    } else if (nis2Match) {
      const num = parseInt(nis2Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15400 + num);
      }
    } else if (shardMatch) {
      const num = parseInt(shardMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15500 + num);
      }
    } else if (ctiMatch) {
      const num = parseInt(ctiMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15600 + num);
      }
    } else if (kernSecMatch) {
      const num = parseInt(kernSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15700 + num);
      }
    } else if (iso20022Match) {
      const num = parseInt(iso20022Match[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15800 + num);
      }
    } else if (tsdbOptMatch) {
      const num = parseInt(tsdbOptMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(15900 + num);
      }
    } else if (aiRedMatch) {
      const num = parseInt(aiRedMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16000 + num);
      }
    } else if (fabricMatch) {
      const num = parseInt(fabricMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16100 + num);
      }
    } else if (quantRiskMatch) {
      const num = parseInt(quantRiskMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16200 + num);
      }
    } else if (llmOrchMatch) {
      const num = parseInt(llmOrchMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16300 + num);
      }
    } else if (confComputeMatch) {
      const num = parseInt(confComputeMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16400 + num);
      }
    } else if (fedLearnMatch) {
      const num = parseInt(fedLearnMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16500 + num);
      }
    } else if (vecOptMatch) {
      const num = parseInt(vecOptMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16600 + num);
      }
    } else if (qkdMatch) {
      const num = parseInt(qkdMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16700 + num);
      }
    } else if (spaceMeshMatch) {
      const num = parseInt(spaceMeshMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16800 + num);
      }
    } else if (aiEthicsMatch) {
      const num = parseInt(aiEthicsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(16900 + num);
      }
    } else if (fheSecMatch) {
      const num = parseInt(fheSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17000 + num);
      }
    } else if (neuroCompMatch) {
      const num = parseInt(neuroCompMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17100 + num);
      }
    } else if (avSafetyMatch) {
      const num = parseInt(avSafetyMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17200 + num);
      }
    } else if (edgeAiOptMatch) {
      const num = parseInt(edgeAiOptMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17300 + num);
      }
    } else if (qrngMatch) {
      const num = parseInt(qrngMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17400 + num);
      }
    } else if (medDevMatch) {
      const num = parseInt(medDevMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17500 + num);
      }
    } else if (vecCacheMatch) {
      const num = parseInt(vecCacheMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17600 + num);
      }
    } else if (dnaStoreMatch) {
      const num = parseInt(dnaStoreMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17700 + num);
      }
    } else if (subseaOptMatch) {
      const num = parseInt(subseaOptMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17800 + num);
      }
    } else if (zkRollupMatch) {
      const num = parseInt(zkRollupMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(17900 + num);
      }
    } else if (do178cMatch) {
      const num = parseInt(do178cMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18000 + num);
      }
    } else if (optSwitchMatch) {
      const num = parseInt(optSwitchMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18100 + num);
      }
    } else if (bciSecMatch) {
      const num = parseInt(bciSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18200 + num);
      }
    } else if (scadaSecMatch) {
      const num = parseInt(scadaSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18300 + num);
      }
    } else if (spaceGncMatch) {
      const num = parseInt(spaceGncMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18400 + num);
      }
    } else if (euvLithoMatch) {
      const num = parseInt(euvLithoMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18500 + num);
      }
    } else if (iaeaSafeMatch) {
      const num = parseInt(iaeaSafeMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18600 + num);
      }
    } else if (hypersFltMatch) {
      const num = parseInt(hypersFltMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18700 + num);
      }
    } else if (maritimeColMatch) {
      const num = parseInt(maritimeColMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18800 + num);
      }
    } else if (hftSecMatch) {
      const num = parseInt(hftSecMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(18900 + num);
      }
    } else if (pathogenBioMatch) {
      const num = parseInt(pathogenBioMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19000 + num);
      }
    } else if (geothermEngMatch) {
      const num = parseInt(geothermEngMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19100 + num);
      }
    } else if (launchFaaMatch) {
      const num = parseInt(launchFaaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19200 + num);
      }
    } else if (cpoOpticsMatch) {
      const num = parseInt(cpoOpticsMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19300 + num);
      }
    } else if (mevDefenseMatch) {
      const num = parseInt(mevDefenseMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19400 + num);
      }
    } else if (bioreactEngMatch) {
      const num = parseInt(bioreactEngMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19500 + num);
      }
    } else if (hapsStratMatch) {
      const num = parseInt(hapsStratMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19600 + num);
      }
    } else if (dacCarbonMatch) {
      const num = parseInt(dacCarbonMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19700 + num);
      }
    } else if (railPtcMatch) {
      const num = parseInt(railPtcMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19800 + num);
      }
    } else if (synchroPmuMatch) {
      const num = parseInt(synchroPmuMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(19900 + num);
      }
    } else if (alePlasmaMatch) {
      const num = parseInt(alePlasmaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20000 + num);
      }
    } else if (didCredMatch) {
      const num = parseInt(didCredMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20100 + num);
      }
    } else if (subReactorMatch) {
      const num = parseInt(subReactorMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20200 + num);
      }
    } else if (lidarSpaceMatch) {
      const num = parseInt(lidarSpaceMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20300 + num);
      }
    } else if (flowToxicMatch) {
      const num = parseInt(flowToxicMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20400 + num);
      }
    } else if (ssbAnodeMatch) {
      const num = parseInt(ssbAnodeMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20500 + num);
      }
    } else if (subseaAcouMatch) {
      const num = parseInt(subseaAcouMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20600 + num);
      }
    } else if (neutronNdtMatch) {
      const num = parseInt(neutronNdtMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20700 + num);
      }
    } else if (hyperSpectMatch) {
      const num = parseInt(hyperSpectMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20800 + num);
      }
    } else if (hvdcGridMatch) {
      const num = parseInt(hvdcGridMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(20900 + num);
      }
    } else if (cryoHydroMatch) {
      const num = parseInt(cryoHydroMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21000 + num);
      }
    } else if (zkmlProofMatch) {
      const num = parseInt(zkmlProofMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21100 + num);
      }
    } else if (tokamakPlasmaMatch) {
      const num = parseInt(tokamakPlasmaMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21200 + num);
      }
    } else if (satSwarmMatch) {
      const num = parseInt(satSwarmMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21300 + num);
      }
    } else if (photonQcMatch) {
      const num = parseInt(photonQcMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21400 + num);
      }
    } else if (deepseaRovMatch) {
      const num = parseInt(deepseaRovMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21500 + num);
      }
    } else if (synbioGeneMatch) {
      const num = parseInt(synbioGeneMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21600 + num);
      }
    } else if (bciNeuralMatch) {
      const num = parseInt(bciNeuralMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21700 + num);
      }
    } else if (aeroTrajectMatch) {
      const num = parseInt(aeroTrajectMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21800 + num);
      }
    } else if (divertorErosionMatch) {
      const num = parseInt(divertorErosionMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(21900 + num);
      }
    } else if (organChipMatch) {
      const num = parseInt(organChipMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(22000 + num);
      }
    } else if (quantumBellMatch) {
      const num = parseInt(quantumBellMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(22100 + num);
      }
    } else if (uiMatch) {
      const num = parseInt(uiMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(num);
        ignoredRuleIds.add(num + 1000);
      }
    } else if (complMatch) {
      const num = parseInt(complMatch[1], 10);
      if (!isNaN(num)) {
        if (num >= 1 && num <= 20) {
          ignoredRuleIds.add(2000 + num);
          ignoredRuleIds.add(num);
        } else if (num >= 2001 && num <= 2020) {
          ignoredRuleIds.add(num);
          ignoredRuleIds.add(num - 2000);
        } else {
          ignoredRuleIds.add(num);
        }
      }
    } else if (infraMatch) {
      const num = parseInt(infraMatch[1], 10);
      if (!isNaN(num)) {
        if (num >= 1 && num <= 20) {
          ignoredRuleIds.add(3000 + num);
          ignoredRuleIds.add(num);
        } else if (num >= 3001 && num <= 3020) {
          ignoredRuleIds.add(num);
          ignoredRuleIds.add(num - 3000);
        } else {
          ignoredRuleIds.add(num);
        }
      }
    } else if (ruleMatch) {
      const num = parseInt(ruleMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(num);
        if (num >= 2001 && num <= 2020) {
          ignoredRuleIds.add(num - 2000);
        } else if (num >= 3001 && num <= 3020) {
          ignoredRuleIds.add(num - 3000);
        } else if (num >= 4001 && num <= 4020) {
          ignoredRuleIds.add(num - 4000);
        }
      }
    } else if (numMatch) {
      const num = parseInt(numMatch[1], 10);
      if (!isNaN(num)) {
        ignoredRuleIds.add(num);
        if (num >= 2001 && num <= 2020) {
          ignoredRuleIds.add(num - 2000);
        } else if (num >= 3001 && num <= 3020) {
          ignoredRuleIds.add(num - 3000);
        } else if (num >= 4001 && num <= 4020) {
          ignoredRuleIds.add(num - 4000);
        } else if (num < 1000) {
          ignoredRuleIds.add(num + 1000);
        }
      }
    } else {
      ignoredPaths.push(trimmed.toLowerCase());
    }
  }

  return { ignoredRuleIds, ignoredPaths };
}

export const parseShipguardIgnore = parseZelsisIgnore;

export interface ZelsisRcConfig {
  projectName?: string;
  minScoreThreshold?: number;
  failStrategy?: 'smart' | 'strict' | 'advisory';
  gates?: {
    security?: boolean;
    legalCompliance?: boolean;
    infraDatabase?: boolean;
    designVibePolish?: boolean;
    vibeCareHealth?: boolean;
  };
  ignoreRules?: string[];
  ignoredPaths?: string[];
}

/**
 * F-43 Remediation: Parses Policy-as-Code .zelsisrc.json or .zelsisrc file
 * Standardizes security governance, failStrategy, and gate thresholds across CI/CD and dashboard.
 */
export function parseZelsisRc(rcContent: string): {
  config: ZelsisRcConfig | null;
  ignoredRuleIds: Set<number>;
  ignoredPaths: string[];
  disabledPillars: Set<string>;
} {
  const ignoredRuleIds = new Set<number>();
  const ignoredPaths: string[] = [];
  const disabledPillars = new Set<string>();

  if (!rcContent || typeof rcContent !== 'string') {
    return { config: null, ignoredRuleIds, ignoredPaths, disabledPillars };
  }

  try {
    const rc: ZelsisRcConfig = JSON.parse(rcContent);
    if (Array.isArray(rc.ignoreRules)) {
      for (const ruleStr of rc.ignoreRules) {
        const parsed = parseZelsisIgnore(String(ruleStr));
        parsed.ignoredRuleIds.forEach((id) => ignoredRuleIds.add(id));
      }
    }
    if (Array.isArray(rc.ignoredPaths)) {
      for (const pathStr of rc.ignoredPaths) {
        ignoredPaths.push(String(pathStr).toLowerCase());
      }
    }
    if (rc.gates) {
      if (rc.gates.security === false) disabledPillars.add('SECURITY');
      if (rc.gates.legalCompliance === false) disabledPillars.add('LEGAL_COMPLIANCE');
      if (rc.gates.infraDatabase === false) disabledPillars.add('INFRA_DATABASE');
      if (rc.gates.designVibePolish === false) disabledPillars.add('VIBEPOLISH');
      if (rc.gates.vibeCareHealth === false) disabledPillars.add('VIBECARE');
    }
    return { config: rc, ignoredRuleIds, ignoredPaths, disabledPillars };
  } catch {
    return { config: null, ignoredRuleIds, ignoredPaths, disabledPillars };
  }
}

/**
 * Cooperative scheduling utility for streaming AST analysis.
 * Yields control back to the browser or Node.js event loop to prevent main thread freeze
 * on large (1,000+ files) codebases.
 */
export async function yieldToMain(): Promise<void> {
  if (typeof window !== 'undefined' && 'scheduler' in window && typeof (window as any).scheduler?.yield === 'function') {
    return (window as any).scheduler.yield();
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Real Static AST & Pattern Analysis Engine
 * Scans provided source files against Security Rules and VibePolish & AI Anti-Pattern rules.
 * Implements cooperative streaming via yieldToMain() to prevent UI freeze on 1,000+ files.
 */
export async function runStaticCodeScan(files: CodeFile[], repoName: string = 'Target Repository'): Promise<ScanResult> {
  const findings: Finding[] = [];
  const logs: string[] = [];

  // Parse .zelsisignore or .shipguardignore if present in file tree
  const ignoreFile = files.find(f => (f?.path || '').endsWith('.zelsisignore') || (f?.path || '').endsWith('.shipguardignore'));
  const { ignoredRuleIds, ignoredPaths } = parseZelsisIgnore(ignoreFile?.content || '');

  // F-43 Remediation: Parse Policy-as-Code .zelsisrc.json if present
  const rcFile = files.find(f => (f?.path || '').endsWith('.zelsisrc.json') || (f?.path || '').endsWith('.zelsisrc'));
  const { config: rcConfig, ignoredRuleIds: rcRuleIds, ignoredPaths: rcPaths, disabledPillars } = parseZelsisRc(rcFile?.content || '');
  rcRuleIds.forEach(id => ignoredRuleIds.add(id));
  rcPaths.forEach(p => ignoredPaths.push(p));

  // Pre-detect project database and ORM architecture before streaming loop cleans file memory
  const detectedStack = detectProjectDatabases(files);

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Initializing Zelsis High-Performance Static Pattern & AST Heuristics Engine v3.5...`);
  logs.push(`[${new Date().toLocaleTimeString()}] [TARGET] Repository: ${repoName}`);

  if (detectedStack.databases.length > 0 || detectedStack.orms.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [STACK] Multi-Database Stack Detected: ${[...detectedStack.databases, ...detectedStack.orms].join(', ')}`);
  }

  if (rcConfig) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code active: Loaded ${rcFile?.path || '.zelsisrc.json'} (Strategy: ${rcConfig.failStrategy || 'smart'}, MinScore: ${rcConfig.minScoreThreshold ?? 85}).`);
  }
  if (ignoredRuleIds.size > 0 || ignoredPaths.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Exclusion filter active: Suppressing ${ignoredRuleIds.size} rules & ${ignoredPaths.length} path patterns.`);
  }

  const validFiles = files.filter((f) => {
    if (!f || typeof f.path !== 'string') return false;
    const lowerPath = (f.path || '').toLowerCase();
    if (
      lowerPath.startsWith('dist/') || lowerPath.includes('/dist/') ||
      lowerPath.startsWith('build/') || lowerPath.includes('/build/') ||
      lowerPath.startsWith('out/') || lowerPath.includes('/out/') ||
      lowerPath.startsWith('.next/') || lowerPath.includes('/.next/') ||
      lowerPath.includes('node_modules/') ||
      // F-39 Remediation: Skip minified bundles and third-party vendored assets to avoid noise
      lowerPath.endsWith('.min.js') ||
      lowerPath.endsWith('.min.css') ||
      lowerPath.endsWith('.bundle.js') ||
      lowerPath.endsWith('.map') ||
      lowerPath.includes('vendor/') ||
      lowerPath.includes('third_party/') ||
      lowerPath.includes('public/vendor/') ||
      lowerPath.includes('assets/vendor/') ||
      lowerPath.includes('data/catalogs/') ||
      lowerPath.includes('data/workspacefiles.ts') ||
      lowerPath.startsWith('scratch/') || lowerPath.includes('/scratch/') ||
      lowerPath.endsWith('package-lock.json') || lowerPath.endsWith('yarn.lock') || lowerPath.endsWith('pnpm-lock.yaml') ||
      lowerPath.endsWith('.png') ||
      lowerPath.endsWith('.jpg') ||
      lowerPath.endsWith('.jpeg') ||
      lowerPath.endsWith('.svg') ||
      lowerPath.endsWith('.pdf') ||
      lowerPath.endsWith('.tsbuildinfo') ||
      lowerPath.endsWith('.md')
    ) {
      return false;
    }
    if (ignoredPaths.some(ip => lowerPath.includes(ip))) {
      return false;
    }
    return true;
  });

  const targetFiles = validFiles;
  let fileLimitWarning: string | undefined = undefined;

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Repository tree loaded: ${targetFiles.length} total source files queued for file-by-file audit.`);
  logs.push(`[${new Date().toLocaleTimeString()}] --------------------------------------------------`);

  let findingCounter = 1;
  let fileIndex = 1;

  for (let i = 0; i < targetFiles.length; i++) {
    // Cooperative event-loop slicing every 20 files to prevent browser thread freeze on 1,000+ file repositories
    if (i > 0 && i % 20 === 0) {
      await yieldToMain();
    }

    const file = targetFiles[i];
    let rawContent = file?.content || '';
    let lines = rawContent.split('\n');
    const startFindingsCount = findings.length;
    const lowerFilePath = (file?.path || '').toLowerCase();

    // File size guard (500 KB / 512,000 bytes)
    const MAX_FILE_SIZE_BYTES = 512000;
    const byteLength = typeof Buffer !== 'undefined'
      ? Buffer.byteLength(rawContent, 'utf8')
      : rawContent.length;

    if (byteLength > MAX_FILE_SIZE_BYTES) {
      const fileSizeKb = Math.round(byteLength / 1024);
      logs.push(`[${new Date().toLocaleTimeString()}] [WARN] PERF-OVERSIZE: File ${file.path} (${fileSizeKb}KB) exceeds maximum static scan size limit (500KB). Skipped to prevent regex event loop starvation.`);
      findings.push({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 999,
        type: 'VIBEPOLISH',
        title: `[PERF-OVERSIZE] File ${file.path} (${fileSizeKb}KB) exceeds maximum static scan size limit (500KB). Skipped to prevent regex event loop starvation.`,
        severity: 'LOW',
        category: 'Performance & Scalability',
        filePath: file.path,
        lineRange: 'L1',
        snippet: `[File size: ${fileSizeKb}KB exceeds 500KB limit - regex evaluation bypassed to prevent event loop starvation]`,
        reproductionSteps: [
          `Scanned repository file ${file.path}.`,
          `Detected file size ${fileSizeKb}KB (> 500KB threshold).`,
          'Skipped static regex analysis to prevent regex event loop starvation.'
        ],
        remediationPrompt: `Refactor or split ${file.path}, or add it to .zelsisignore if it is a bundled/generated artifact.`,
        status: 'OPEN',
        owner: 'Engineering Lead',
        falsePositive: false
      });
      fileIndex++;
      continue;
    }

    // Detect if current file is a rule catalog, scanner engine definition, or demo playground component
    const isScannerRuleCatalog =
      lowerFilePath.includes('lib/rules/') ||
      lowerFilePath.includes('data/mockdata.ts') ||
      lowerFilePath.includes('data/workspacefiles.ts') ||
      lowerFilePath.includes('lib/scanner-engine.ts') ||
      lowerFilePath.includes('vulnerabilityplayground.tsx') ||
      lowerFilePath.includes('ruleknowledgebasemodal.tsx') ||
      lowerFilePath.includes('interactiveanalyzer.tsx') ||
      lowerFilePath.includes('05_seed_data.sql');

    // Helper to add finding unless suppressed or false-positive inside rule definition files
    const addFinding = (f: Finding) => {
      if (disabledPillars.has(f.type)) {
        return;
      }
      if (
        ignoredRuleIds.has(f.ruleId) ||
        (f.ruleId >= 1000 && ignoredRuleIds.has(f.ruleId - 1000)) ||
        (f.ruleId < 1000 && ignoredRuleIds.has(f.ruleId + 1000)) ||
        (f.ruleId >= 2001 && f.ruleId <= 2006 && ignoredRuleIds.has(f.ruleId - 2000))
      ) {
        return;
      }
      // Filter out self-referential alerts inside scanner engine definition catalogs and demo playgrounds
      if (isScannerRuleCatalog) {
        return;
      }
      // Deduplicate findings by fingerprint (same file, line, and rule title/family)
      const isDuplicate = findings.some(existing =>
        existing.filePath === f.filePath &&
        existing.lineRange === f.lineRange &&
        (
          existing.title === f.title ||
          existing.ruleId === f.ruleId ||
          (existing.title.includes('Eyebrow') && f.title.includes('Eyebrow'))
        )
      );
      if (isDuplicate) {
        return;
      }
      findings.push(f);
    };

    // 0. AI Comment, Prompt Artifact & Boilerplate Inspector (Runs on raw unstripped content)
    const commentCounter = { count: findingCounter };
    const commentResult = evaluateAiCommentRules(file, lines, rawContent, commentCounter);
    findingCounter = commentCounter.count;
    for (const item of commentResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...commentResult.logs);

    let cleanContent = stripComments(rawContent);

    logs.push(`[${new Date().toLocaleTimeString()}] [INSPECT] [File ${fileIndex}/${validFiles.length}] Inspecting ${file.path} (${lines.length} lines)...`);
    logs.push(`[${new Date().toLocaleTimeString()}]   ├─ [LEXICAL] Syntax inspection: Parsing Syntax Tokens, Cleaned Comment Strips & Heuristic Graphs...`);
    logs.push(`[${new Date().toLocaleTimeString()}]   ├─ [SECURITY] OWASP clearance: Verifying OWASP Security & Secret Token Isolation Controls...`);
    logs.push(`[${new Date().toLocaleTimeString()}]   ├─ [COMPLIANCE] Regulatory clearance: Auditing Privacy, Consent, ePrivacy & PCI-DSS Pre-Flight Gate...`);
    logs.push(`[${new Date().toLocaleTimeString()}]   ├─ [DESIGN] Design token audit: Auditing UI/UX Design System & Micro-Interaction Rules...`);
    logs.push(`[${new Date().toLocaleTimeString()}]   └─ [PATTERNS] Anti-pattern audit: Checking AI Web Design Anti-Patterns & Component Trees...`);

    // Rule 1: Exposed Stripe/OpenAI API Keys (F-16: Scans comments, F-17: Masks secrets in snippet)
    const secretPattern = /sk_live_[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|api[_-]?key\s*=\s*["']sk-[a-zA-Z0-9_-]{20,}["']/i;
    if (secretPattern.test(rawContent)) {
      const matchLineIdx = lines.findIndex(l => secretPattern.test(l) && !/placeholder|EXAMPLE|dummy|test_key/i.test(l));
      if (matchLineIdx !== -1) {
        const lineNum = matchLineIdx + 1;
        const rawLine = lines[matchLineIdx] || '';
        const maskedSnippet = rawLine.replace(/sk-[a-zA-Z0-9_-]{16,}|sk_live_[a-zA-Z0-9]{16,}/gi, (m) => m.slice(0, 4) + '****' + m.slice(-2));

        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 1,
          type: 'SECURITY',
          title: 'Exposed Hardcoded API Key / Secret Token',
          severity: 'CRITICAL',
          category: 'Secret Isolation',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: maskedSnippet || '[REDACTED_SECRET]',
          reproductionSteps: [
            `Scanned file string content at ${file.path}:${lineNum}.`,
            'Detected live secret key prefix (sk_live_ / sk-proj-).'
          ],
          remediationPrompt: `Extract exposed API secret keys from ${file.path} into server-only environment variables and reference process.env.`,
          status: 'OPEN',
          owner: 'Security Lead',
          falsePositive: false
        });

        logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-01 Secret Exposure detected in ${file.path}:${lineNum}`);
      }
    }

    // Rule 3: Supabase Permissive Row Level Security (RLS)
    if (cleanContent.includes('USING (true)') || cleanContent.includes('FOR ALL USING (true)')) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('--') && l.includes('USING (true)'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 3,
        type: 'SECURITY',
        title: 'Permissive Row Level Security (RLS) Policy (USING true)',
        severity: 'CRITICAL',
        category: 'Database',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'USING (true);',
        reproductionSteps: [
          `Scanned database migration SQL at ${file.path}:${lineNum}.`,
          'Detected default allow-all policy using (true).'
        ],
        remediationPrompt: `Replace permissive RLS policy in ${file.path}. Write strict auth.uid() = user_id checks.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });

      logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-03 Permissive RLS Policy in ${file.path}:${lineNum}`);
    }

    if (file.content.includes("origin: '*'") || file.content.includes('Access-Control-Allow-Origin: *')) {
      const matchLineIdx = lines.findIndex(l => l.includes("origin: '*'") || l.includes('Access-Control-Allow-Origin: *'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 8,
        type: 'SECURITY',
        title: 'Wildcard Access-Control-Allow-Origin (*) CORS Vulnerability',
        severity: 'HIGH',
        category: 'Network & CORS',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || "origin: '*'",
        reproductionSteps: [
          `Scanned API server setup at ${file.path}:${lineNum}.`,
          'Detected wildcard Access-Control-Allow-Origin header.'
        ],
        remediationPrompt: `Restrict CORS origin in ${file.path} to process.env.PRODUCTION_CLIENT_URL.`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });

      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-08 Wildcard CORS configuration in ${file.path}:${lineNum}`);
    }

    // Rule 16: Dangerously Set Inner HTML (XSS)
    const isCompiledBundle = file.path.includes('live-deployment/bundle-') || file.path.includes('/vendor/') || file.path.includes('node_modules');
    const isSafeMdxOrJsonLd = isCompiledBundle || file.path.includes('mdx-components') || file.path.includes('syntax-highlight') || file.content.includes('application/ld+json');
    if (!isSafeMdxOrJsonLd && (cleanContent.includes('dangerouslySetInnerHTML') || cleanContent.includes('innerHTML ='))) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && (l.includes('dangerouslySetInnerHTML') || l.includes('innerHTML')));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 16,
        type: 'SECURITY',
        title: 'Unsanitized Direct InnerHTML DOM Mutation (XSS Risk)',
        severity: 'HIGH',
        category: 'Input & Files',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'dangerouslySetInnerHTML={{ __html: content }}',
        reproductionSteps: [
          `Scanned frontend component rendering at ${file.path}:${lineNum}.`,
          'Detected unescaped DOM insertion susceptible to Cross-Site Scripting.'
        ],
        remediationPrompt: `Sanitize input in ${file.path} using DOMPurify before setting innerHTML.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });

      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-16 Unsanitized innerHTML in ${file.path}:${lineNum}`);
    }

    // Advanced Option A Security Rules (SEC-SCA-01, SEC-LOG-01, SEC-LLM-01) & Modular Engine
    const secCounter = { count: findingCounter };
    const secResult = evaluateSecurityRules(file, lines, cleanContent, secCounter);
    findingCounter = secCounter.count;
    for (const sf of secResult.findings) {
      if (!findings.some((existing) => existing.ruleId === sf.ruleId && existing.filePath === sf.filePath && existing.lineRange === sf.lineRange)) {
        addFinding(sf);
      }
    }
    for (const logItem of secResult.logs) {
      if (!logs.includes(logItem)) logs.push(logItem);
    }

    // Live Web Deployment Security Header Rules: Parse missingSecurityHeaders from JSON
    if (file.path.includes('live-deployment/security-headers.json')) {
      try {
        const headerData = JSON.parse(file.content);
        const missing: string[] = headerData.missingSecurityHeaders || [];
        const statusCode: number = headerData.statusCode || 200;

        // Rule 100: Broken Link / Unhealthy Endpoint Detection
        if (statusCode === 404 || statusCode >= 500 || headerData.isHealthy === false) {
          addFinding({
            id: `real-find-${Date.now()}-${findingCounter++}`,
            ruleId: 100,
            type: 'SECURITY',
            title: `SEC-WEB-00: Target Link Unhealthy / Broken Endpoint (HTTP ${statusCode})`,
            severity: 'CRITICAL',
            category: 'Link Health & Availability',
            filePath: 'Live Web Target (Endpoint Check)',
            lineRange: `HTTP ${statusCode}`,
            snippet: `HTTP Status Code: ${statusCode} ${headerData.linkStatusText || ''}`,
            reproductionSteps: [
              `Pinged live URL endpoint: ${headerData.targetUrl || 'Target Web Site'}.`,
              `Server returned status code HTTP ${statusCode} (Link is broken, dead, or misconfigured).`
            ],
            remediationPrompt: `Fix broken URL target link (${headerData.targetUrl}). Verify domain DNS records, SSL certificates, and web server deployment routing.`,
            status: 'OPEN',
            owner: 'DevOps & Infrastructure Lead',
            falsePositive: false
          });
          logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-WEB-00 Broken Link / Unhealthy Target Endpoint (HTTP ${statusCode})`);
        }

        // Rule 101: Missing Content-Security-Policy
        if (missing.some((h: string) => h.includes('Content-Security-Policy'))) {
          addFinding({
            id: `real-find-${Date.now()}-${findingCounter++}`,
            ruleId: 101,
            type: 'SECURITY',
            title: 'SEC-WEB-01: Absence of Content-Security-Policy (CSP) Header',
            severity: 'CRITICAL',
            category: 'Network & Security Headers',
            filePath: 'Live Web Target (HTTP Headers)',
            lineRange: 'Header Deficit',
            snippet: 'Content-Security-Policy: [Missing]',
            reproductionSteps: [
              'Scanned live production HTTP headers.',
              'Detected missing Content-Security-Policy header. Site is vulnerable to XSS and data injection.'
            ],
            remediationPrompt: `Configure strict Content-Security-Policy header (default-src 'self'; script-src 'self' 'nonce-...') on production web server or Next.js headers config.`,
            status: 'OPEN',
            owner: 'Security Architect',
            falsePositive: false
          });
          logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-WEB-01 Missing Content-Security-Policy Header on Live Web Deployment`);
        }

        // Rule 102: Missing HSTS Header
        if (missing.some((h: string) => h.includes('Strict-Transport-Security'))) {
          addFinding({
            id: `real-find-${Date.now()}-${findingCounter++}`,
            ruleId: 102,
            type: 'SECURITY',
            title: 'SEC-WEB-02: Absence of HSTS Strict Transport Security Header',
            severity: 'HIGH',
            category: 'Network & TLS',
            filePath: 'Live Web Target (HTTP Headers)',
            lineRange: 'Header Deficit',
            snippet: 'Strict-Transport-Security: [Missing]',
            reproductionSteps: [
              'Scanned live HTTPS headers.',
              'Detected missing Strict-Transport-Security header, allowing HTTP downgrade attacks.'
            ],
            remediationPrompt: `Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' header to production CDN / Nginx / Vercel headers.`,
            status: 'OPEN',
            owner: 'DevOps Lead',
            falsePositive: false
          });
          logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-WEB-02 Missing HSTS Header on Live Web Target`);
        }

        // Rule 103: Missing X-Frame-Options (Clickjacking)
        const hasCspFrameAncestors = (headerData.headers?.['content-security-policy'] || '').includes('frame-ancestors');
        if (!hasCspFrameAncestors && missing.some((h: string) => h.includes('X-Frame-Options'))) {
          addFinding({
            id: `real-find-${Date.now()}-${findingCounter++}`,
            ruleId: 103,
            type: 'SECURITY',
            title: 'SEC-WEB-03: Clickjacking Exposure (Missing X-Frame-Options Header)',
            severity: 'HIGH',
            category: 'Frame Isolation',
            filePath: 'Live Web Target (HTTP Headers)',
            lineRange: 'Header Deficit',
            snippet: 'X-Frame-Options: [Missing]',
            reproductionSteps: [
              'Scanned HTTP headers.',
              'Detected missing X-Frame-Options header and absence of CSP frame-ancestors directive, allowing malicious framing/clickjacking.'
            ],
            remediationPrompt: `Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' header, or add 'frame-ancestors 'self'' to CSP in production server configuration.`,
            status: 'OPEN',
            owner: 'Security Architect',
            falsePositive: false
          });
          logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-WEB-03 Clickjacking risk: Missing X-Frame-Options header`);
        }

        // Rule 104: Missing X-Content-Type-Options (MIME Sniffing)
        if (missing.some((h: string) => h.includes('X-Content-Type-Options'))) {
          addFinding({
            id: `real-find-${Date.now()}-${findingCounter++}`,
            ruleId: 104,
            type: 'SECURITY',
            title: 'SEC-WEB-04: MIME Sniffing Vulnerability (Missing X-Content-Type-Options)',
            severity: 'MEDIUM',
            category: 'Content Protection',
            filePath: 'Live Web Target (HTTP Headers)',
            lineRange: 'Header Deficit',
            snippet: 'X-Content-Type-Options: [Missing]',
            reproductionSteps: [
              'Scanned HTTP response headers.',
              'Detected missing X-Content-Type-Options header, leaving users vulnerable to MIME-confusion attacks.'
            ],
            remediationPrompt: `Set 'X-Content-Type-Options: nosniff' header across all production HTTP responses.`,
            status: 'OPEN',
            owner: 'DevOps Lead',
            falsePositive: false
          });
          logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-04 Missing X-Content-Type-Options: nosniff`);
        }
      } catch (parseErr) {
        // Not valid JSON, skip header analysis
      }
    }

    // Live Web Deployment Security Rule 4: Insecure target="_blank" Link
    if (file.path.includes('live-deployment') && file.content.includes('target="_blank"') && !file.content.includes('rel="noopener')) {
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 104,
        type: 'SECURITY',
        title: 'SEC-WEB-04: Insecure External Link Target Blank (Tab-Nabbing Risk)',
        severity: 'MEDIUM',
        category: 'HTML Security',
        filePath: file.path,
        lineRange: 'L1',
        snippet: '<a href="..." target="_blank">',
        reproductionSteps: [
          'Scanned HTML links on target web page.',
          'Detected target="_blank" links missing rel="noopener noreferrer".'
        ],
        remediationPrompt: `Add rel="noopener noreferrer" to all target="_blank" links in HTML to prevent window.opener hijacking.`,
        status: 'OPEN',
        owner: 'Frontend Lead',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-04 Insecure target="_blank" link detected`);
    }

    // VibePolish UI-01: Generic Purple-Blue Gradient Cliché
    if (/bg-gradient-to-[rblt]\s+from-(purple|violet|indigo)-[0-9]{3}/i.test(file.content) || file.content.includes('from-purple-600 to-blue-500')) {
      const matchLineIdx = lines.findIndex(l => /from-(purple|violet|indigo)/i.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1001,
        type: 'VIBEPOLISH',
        title: 'UI-01: Generic Purple-Blue Neon Gradient Cliché',
        severity: 'MEDIUM',
        category: 'Color & Background',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'bg-gradient-to-r from-purple-600 to-blue-500',
        reproductionSteps: [`Scanned CSS classes in ${file.path}:${lineNum}.`, 'Detected high-contrast raw purple/neon gradient.'],
        remediationPrompt: `Replace generic purple-blue linear gradients in ${file.path} with semantic flat color tokens (primary, destructive, muted) or subtle monochromatic dark surfaces.`,
        status: 'OPEN',
        owner: 'UI Architect',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-01: Purple-blue gradient detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-03: Sparkle / Magic Wand Icon Overuse
    if (file.content.includes('Sparkles') || file.content.includes('Wand2') || file.content.includes('✨')) {
      const matchLineIdx = lines.findIndex(l => l.includes('Sparkles') || l.includes('Wand2') || l.includes('✨'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1003,
        type: 'VIBEPOLISH',
        title: 'UI-03: Overused Sparkle / Magic Wand Icon Cliché',
        severity: 'LOW',
        category: 'Icons & Micro-copy',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || '<Sparkles className="w-4 h-4" />',
        reproductionSteps: [`Scanned component icons in ${file.path}:${lineNum}.`, 'Detected generic Sparkle icon placed on AI buttons/inputs.'],
        remediationPrompt: `Remove generic Sparkle/Magic Wand icons in ${file.path}. Replace with descriptive action micro-copy (e.g. "Summarize", "Filter", "Analyze").`,
        status: 'OPEN',
        owner: 'UI Architect',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-03: Sparkle icon overuse detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-04: Absence of Empty State Component Fallback (Frontend components only, excluding persistent layout chrome)
    const isFrontendComponent = file.path.endsWith('.tsx') || file.path.endsWith('.jsx');
    const isStructuralChrome = /layout\.[tj]sx$|header\.[tj]sx$|nav\.[tj]sx$|navbar\.[tj]sx$|footer\.[tj]sx$|sidebar\.[tj]sx$/i.test(file.path);
    if (isFrontendComponent && !isStructuralChrome && file.content.includes('.map(') && !file.content.includes('.length === 0') && !file.content.includes('EmptyState') && !file.content.includes('no data') && !file.content.includes('isEmpty')) {
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1004,
        type: 'VIBEPOLISH',
        title: 'UI-04: Absence of Empty State Component Fallback',
        severity: 'MEDIUM',
        category: 'Layout & Onboarding',
        filePath: file.path,
        lineRange: 'L1-L50',
        snippet: 'items.map((item) => <Card key={item.id} ... />)',
        reproductionSteps: [`Scanned list rendering in ${file.path}.`, 'Detected list mapping without empty state / starter prompt fallback.'],
        remediationPrompt: `Add an Empty State component with starter prompts / demo data in ${file.path} when items array is empty.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-04: Missing Empty State component detected (${file.path})`);
    }

    // Note: VibePolish UI-05 is canonically evaluated via CLICHE-76 in evaluateAiClicheRules to prevent duplicate reporting.

    // VibePolish UI-06: Pulsating Status Dot & Glowing Badge Cliché (AI Slop Pattern)
    const hasPulsingDotSlop = /rounded-full\s+bg-emerald-[45]00[^"']*animate-pulse/i.test(file.content) ||
      /animate-pulse[^"']*rounded-full\s+bg-emerald-[45]00/i.test(file.content);
    const isLiveRunner = /ScanRunnerView|TerminalLogWindow/i.test(file.path);
    if (isFrontendComponent && !isLiveRunner && hasPulsingDotSlop) {
      const matchLineIdx = lines.findIndex(l => /animate-pulse/i.test(l) && /bg-emerald/i.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1006,
        type: 'VIBEPOLISH',
        title: 'UI-06: Pulsating Status Dot & Glowing Badge Cliché (AI Slop Anti-Pattern)',
        severity: 'LOW',
        category: 'Visual Polish & Motion',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || '<span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />',
        reproductionSteps: [
          `Scanned status badges and header pills in ${file.path}:${lineNum}.`,
          'Detected pulsating green indicator dot inside static component or card.'
        ],
        remediationPrompt: `Remove distracting pulsating green animation dots in static badges in ${file.path}. Use static, high-contrast, monochromatic or muted status badges for a professional, distraction-free interface.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-06: Pulsing status dot cliché detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-08: Repetitive Checkmark Icon Flooding (AI Slop Pattern)
    const hasCheckmarkFlooding = /<(?:CheckCircle2|CheckCircle)\b[^>]*className="[^"]*text-emerald-400[^"]*shrink-0/i.test(file.content) &&
      /\.map\s*\(/.test(file.content) &&
      file.content.includes('<li');
    if (isFrontendComponent && hasCheckmarkFlooding) {
      const matchLineIdx = lines.findIndex(l => /<(?:CheckCircle2|CheckCircle)\b/i.test(l) && /<li/i.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1008,
        type: 'VIBEPOLISH',
        title: 'UI-08: Repetitive Checkmark Icon Flooding (AI Slop Anti-Pattern)',
        severity: 'LOW',
        category: 'Visual Hierarchy & Typography',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || '<CheckCircle2 size={16} className="text-emerald-400 shrink-0" />',
        reproductionSteps: [
          `Scanned feature list elements in ${file.path}:${lineNum}.`,
          'Detected repetitive CheckCircle icons prepended to every single list item.'
        ],
        remediationPrompt: `Replace repetitive CheckCircle icons in ${file.path} with clean typography dashes (e.g. "—"), subtle numbered steps, or distinct architectural micro-cards.`,
        status: 'OPEN',
        owner: 'UI Architect',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-08: Repetitive checkmark flooding detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-07: Conversational Chat-Wrapper Lock-In Trap
    if (file.content.includes('messages.map') && !file.content.includes('Canvas') && !file.content.includes('Artifact') && !file.content.includes('Table')) {
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1007,
        type: 'VIBEPOLISH',
        title: 'UI-07: Conversational Chat-Wrapper Lock-In Trap',
        severity: 'HIGH',
        category: 'UX Architecture',
        filePath: file.path,
        lineRange: 'L1-L80',
        snippet: '<div className="chat-messages">{messages.map(...)}</div>',
        reproductionSteps: [`Scanned interface structure in ${file.path}.`, 'Detected full chat wrapper without structured side canvas or inline editable tables.'],
        remediationPrompt: `Refactor ${file.path} into a hybrid layout: introduce a side Artifacts/Canvas view or inline structured tables alongside chat.`,
        status: 'OPEN',
        owner: 'UX Architect',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-07: Chat-wrapper lock-in detected (${file.path})`);
    }

    // VibePolish UI-11: Uninformative "AI Thinking..." Spinner
    if (file.content.includes('AI is thinking') || file.content.includes('Thinking...') || (file.content.includes('Spinner') && !file.content.includes('step'))) {
      const matchLineIdx = lines.findIndex(l => l.includes('thinking') || l.includes('Thinking'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1011,
        type: 'VIBEPOLISH',
        title: 'UI-11: Uninformative "AI Thinking..." Spinner',
        severity: 'MEDIUM',
        category: 'State & Feedback',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || '<span>AI is thinking...</span>',
        reproductionSteps: [`Scanned loading state in ${file.path}:${lineNum}.`, 'Detected vague "Thinking..." spinner without step-by-step agent status progress.'],
        remediationPrompt: `Replace vague "Thinking..." text in ${file.path} with a transparent Stepper component showing live agent execution steps (e.g. "Scanning database tables...", "Synthesizing audit findings...").`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-11: Vague AI spinner detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-21: Cliché Fluff & Filler Prefaces
    if (/in today'?s fast-paced/i.test(file.content) || /it'?s important to remember/i.test(file.content)) {
      const matchLineIdx = lines.findIndex(l => /fast-paced|important to remember/i.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1021,
        type: 'VIBEPOLISH',
        title: 'UI-21: Cliché Fluff & Filler Prefaces',
        severity: 'MEDIUM',
        category: 'Text & Copywriting',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || "In today's fast-paced digital world...",
        reproductionSteps: [`Scanned text prompts in ${file.path}:${lineNum}.`, 'Detected LLM fluff starter phrase ("In today\'s fast-paced...").'],
        remediationPrompt: `Add strict system prompt constraints in ${file.path} banning fluff intros ("In today's fast-paced digital world..."). Force direct-to-answer responses.`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-21: Cliché filler text detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-23: Robotic AI Apologies (As an AI language model...)
    if (file.content.includes('As an AI language model') || file.content.includes('As an AI assistant')) {
      const matchLineIdx = lines.findIndex(l => l.includes('As an AI'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1023,
        type: 'VIBEPOLISH',
        title: 'UI-23: Robotic Apology / Refusal Boilerplate',
        severity: 'HIGH',
        category: 'Model Behavior',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'As an AI language model, I cannot fulfill this request.',
        reproductionSteps: [`Scanned error handlers/prompts in ${file.path}:${lineNum}.`, 'Detected robotic fallback text ("As an AI language model...").'],
        remediationPrompt: `Replace robotic refusal messages in ${file.path} with branded, natural fallback messages and direct actionable alternatives.`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-23: Robotic AI apology boilerplate detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-32: Excessive Meta-Announcement Statements
    if (/below (you can find|is the response|is the analysis)/i.test(file.content) || /here is the requested/i.test(file.content)) {
      const matchLineIdx = lines.findIndex(l => /below|here is the/i.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1032,
        type: 'VIBEPOLISH',
        title: 'UI-32: Excessive Meta-Announcement Preface Cliché',
        severity: 'LOW',
        category: 'Text & Copywriting',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'Here is the requested analysis below:',
        reproductionSteps: [`Scanned text templates in ${file.path}:${lineNum}.`, 'Detected meta-announcement prefix ("Below you can find...").'],
        remediationPrompt: `Strip meta-announcement intros in ${file.path} via system prompt rule or regex post-processor. Jump straight into payload data.`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-32: Meta-announcement text detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-39: Missing Structured Schema Validation
    if (file.content.includes('openai.chat.completions') && !file.content.includes('response_format') && !file.content.includes('zodResponseFormat') && !file.content.includes('pydantic')) {
      const matchLineIdx = lines.findIndex(l => l.includes('openai.chat.completions'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1039,
        type: 'VIBEPOLISH',
        title: 'UI-39: Unvalidated Dynamic Outputs (Missing Zod Schema)',
        severity: 'HIGH',
        category: 'Output Hygiene',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ ... });',
        reproductionSteps: [`Scanned LLM API endpoint in ${file.path}:${lineNum}.`, 'Detected OpenAI completion call without response_format or Zod schema validation.'],
        remediationPrompt: `Enforce Structured Outputs in ${file.path} using Zod schema and response_format: zodResponseFormat(Schema, "result") to eliminate formatting drift.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-39: Missing Structured Zod schema detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-41: Monolithic System Prompt Inflation
    if (file.content.includes('system') && file.content.length > 5000 && (file.content.match(/role:\s*['"]system['"]/g) || []).length === 1) {
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1041,
        type: 'VIBEPOLISH',
        title: 'UI-41: Monolithic System Prompt Inflation',
        severity: 'MEDIUM',
        category: 'Prompt Architecture',
        filePath: file.path,
        lineRange: 'L1-L100',
        snippet: 'const systemPrompt = `DO NOT... DO NOT... ALWAYS... YOU ARE AN AI... (5000+ chars)`',
        reproductionSteps: [`Scanned prompt architecture in ${file.path}.`, 'Detected monolithic, bloated system prompt exceeding 5000 chars without step-based modular injection.'],
        remediationPrompt: `Refactor system prompt in ${file.path} into modular sub-prompts. Inject rules dynamically per execution step.`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-41: System prompt inflation detected (${file.path})`);
    }

    // VibePolish UI-48: Dynamic Variable Injection Failures (Exclude config files, dotfiles, test files, and non-JS/TS backend languages)
    const isConfigFileOrDotfile = lowerFilePath.includes('.vscode/') || lowerFilePath.includes('.github/') || lowerFilePath.endsWith('.json') || lowerFilePath.endsWith('.toml') || lowerFilePath.endsWith('.yaml') || lowerFilePath.endsWith('.yml');
    const isTestOrDocFile =
      lowerFilePath.includes('/test/') || lowerFilePath.includes('/tests/') || lowerFilePath.includes('/spec/') ||
      lowerFilePath.startsWith('test/') || lowerFilePath.startsWith('tests/') || lowerFilePath.startsWith('spec/') ||
      lowerFilePath.includes('__tests__/') || /\.(?:test|spec)\.[a-zA-Z0-9]+$/i.test(lowerFilePath) ||
      /(?:^|\/)(?:test_[^/]+|[^/]+_test)\.[a-zA-Z0-9]+$/i.test(lowerFilePath) ||
      lowerFilePath.endsWith('.md') || lowerFilePath.endsWith('.mdx');
    const isNonJsBackend = /\.(?:go|rs|c|cpp|cc|cxx|h|hpp|java|kt|kts|cs|swift|rb|sh|bash|zsh|ps1)$/i.test(lowerFilePath);
    const hasSingleBracePlaceholder = /(?<!\{)\{[a-zA-Z0-9_]+\}(?!\})/.test(file.content);
    if (!isConfigFileOrDotfile && !isTestOrDocFile && !isNonJsBackend && hasSingleBracePlaceholder && !file.content.includes('??') && file.content.includes('template')) {
      const matchLineIdx = lines.findIndex(l => /(?<!\{)\{[a-zA-Z0-9_]+\}(?!\})/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 48,
        type: 'VIBEPOLISH',
        title: 'UI-48: Dynamic Variable Injection Missing Fallback',
        severity: 'HIGH',
        category: 'Variables & Templates',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'Hello {username}, welcome to your account.',
        reproductionSteps: [`Scanned string template interpolation in ${file.path}:${lineNum}.`, 'Detected variable placeholder without fallback check (risk of printing {undefined} / {null}).'],
        remediationPrompt: `Add strict type validation or nullish coalescing (e.g. username ?? "User") to template interpolation in ${file.path}.`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-48: Variable injection missing fallback detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-57: High Temperature on Deterministic Tasks
    if (file.content.includes('temperature: 0.9') || file.content.includes('temperature: 0.8') || file.content.includes('temperature: 1')) {
      if (file.content.includes('json') || file.content.includes('schema') || file.content.includes('code')) {
        const matchLineIdx = lines.findIndex(l => l.includes('temperature'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 57,
          type: 'VIBEPOLISH',
          title: 'UI-57: Excessive Temperature Setting on Deterministic Task',
          severity: 'HIGH',
          category: 'Model Parameters',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: lines[matchLineIdx] || 'temperature: 0.9',
          reproductionSteps: [`Scanned model parameters in ${file.path}:${lineNum}.`, 'Detected high temperature (0.8-1.0) on structured code/JSON extraction task.'],
          remediationPrompt: `Lower temperature in ${file.path} to 0.0 - 0.2 for deterministic code and JSON schema extraction calls.`,
          status: 'OPEN',
          owner: 'Backend Team',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-57: Excessive temperature parameter detected (${file.path}:${lineNum})`);
      }
    }

    // VibePolish UI-61: Naive Fixed-Character Chunking
    if (file.content.includes('CharacterTextSplitter') || (file.content.includes('chunkSize') && !file.content.includes('Semantic') && !file.content.includes('Recursive'))) {
      const matchLineIdx = lines.findIndex(l => l.includes('CharacterTextSplitter') || l.includes('chunkSize'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 61,
        type: 'VIBEPOLISH',
        title: 'UI-61: Naive Fixed-Character Text Splitter',
        severity: 'MEDIUM',
        category: 'RAG Architecture',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'new CharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 200 })',
        reproductionSteps: [`Scanned RAG pipeline in ${file.path}:${lineNum}.`, 'Detected naive fixed-character text splitter slicing sentences/tables mid-word.'],
        remediationPrompt: `Replace naive CharacterTextSplitter in ${file.path} with SemanticChunking or RecursiveCharacterTextSplitter respecting document AST structure.`,
        status: 'OPEN',
        owner: 'AI Architect',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-61: Naive text chunking detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-75: Multi-Tenant RAG Data Leakage
    if ((file.content.includes('similaritySearch') || file.content.includes('match_documents') || file.content.includes('pinecone.query')) && !file.content.includes('tenant_id') && !file.content.includes('user_id')) {
      const matchLineIdx = lines.findIndex(l => l.includes('similaritySearch') || l.includes('match_documents') || l.includes('pinecone.query'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 75,
        type: 'VIBEPOLISH',
        title: 'UI-75: Unfiltered Multi-Tenant Vector Query',
        severity: 'CRITICAL',
        category: 'Metadata & Security',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'await vectorStore.similaritySearch(query, 5);',
        reproductionSteps: [`Scanned vector DB query in ${file.path}:${lineNum}.`, 'Detected vector similarity query executing without mandatory tenant_id / user_id metadata filter.'],
        remediationPrompt: `Enforce mandatory tenant_id and user_id metadata filtering in ${file.path} for vector database queries: vectorStore.similaritySearch(query, 5, { tenant_id: user.tenantId }).`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-75 Unfiltered multi-tenant vector query detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-76: Context Hallucination Vulnerability
    if (file.content.includes('context') && file.content.includes('prompt') && !file.content.includes('not found') && !file.content.includes('information not found')) {
      if (file.content.includes('RAG') || file.content.includes('retrieval') || file.content.includes('vector')) {
        const matchLineIdx = lines.findIndex(l => l.includes('context'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 76,
          type: 'VIBEPOLISH',
          title: 'UI-76: Missing RAG Hallucination Guardrail',
          severity: 'HIGH',
          category: 'RAG Architecture',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: lines[matchLineIdx] || 'Answer the question based on context: {context}',
          reproductionSteps: [`Scanned RAG prompt template in ${file.path}:${lineNum}.`, 'Detected RAG prompt template without explicit fallback instruction ("If the context does not contain the answer, state \'Information not found\'").'],
          remediationPrompt: `Update RAG prompt template in ${file.path}. Add mandatory guardrail: "If the provided context does not contain sufficient information, explicitly respond with 'Information not found' without hallucinating."`,
          status: 'OPEN',
          owner: 'Prompt Engineer',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-76: Missing RAG guardrail detected (${file.path}:${lineNum})`);
      }
    }

    // VibePolish UI-85: Destructive Action Missing Human Approval
    if ((file.content.includes('deleteUser') || file.content.includes('dropTable') || file.content.includes('executePayment') || file.content.includes('sendEmail')) && !file.content.includes('confirm') && !file.content.includes('requireApproval')) {
      if (file.content.includes('agent') || file.content.includes('tool') || file.content.includes('functionCall')) {
        const matchLineIdx = lines.findIndex(l => /deleteUser|dropTable|executePayment|sendEmail/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 85,
          type: 'VIBEPOLISH',
          title: 'UI-85: Destructive Agent Action Missing Human-in-the-Loop Approval',
          severity: 'CRITICAL',
          category: 'Security & Approvals',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: lines[matchLineIdx] || 'async function deleteUserTool(args) { await db.deleteUser(args.id); }',
          reproductionSteps: [`Scanned agent tool execution in ${file.path}:${lineNum}.`, 'Detected destructive action tool (delete/payment/email) executing without Human-in-the-Loop approval gate.'],
          remediationPrompt: `Enforce Human-in-the-Loop (HITL) confirmation step in ${file.path} before executing destructive tools (e.g. require explicit user token / approval UI trigger).`,
          status: 'OPEN',
          owner: 'Security Lead',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-85 Human-in-the-loop approval step missing (${file.path}:${lineNum})`);
      }
    }

    // VibePolish UI-90: Sensitive Data Exposure in Tool Logs
    if ((file.content.includes('console.log(tool') || file.content.includes('logger.info(args)')) && !file.content.includes('redact') && !file.content.includes('mask')) {
      const matchLineIdx = lines.findIndex(l => l.includes('console.log') || l.includes('logger.info'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 90,
        type: 'VIBEPOLISH',
        title: 'UI-90: Unredacted Sensitive Data in Tool Logs',
        severity: 'HIGH',
        category: 'Security & Approvals',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'console.log("Tool Arguments:", args);',
        reproductionSteps: [`Scanned logging Statements in ${file.path}:${lineNum}.`, 'Detected unmasked tool argument logging potentially leaking API keys or user PII.'],
        remediationPrompt: `Add redaction proxy or masking middleware in ${file.path} before logging tool arguments and responses.`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-90 Unredacted sensitive tool log detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-100: Missing User Request Abort Signal
    if ((file.content.includes('agentRunner') || file.content.includes('executeAgent')) && !file.content.includes('AbortController') && !file.content.includes('signal')) {
      const matchLineIdx = lines.findIndex(l => l.includes('agentRunner') || l.includes('executeAgent'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 100,
        type: 'VIBEPOLISH',
        title: 'UI-100: Missing Request AbortSignal Listener',
        severity: 'MEDIUM',
        category: 'Execution & Sandbox',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'export async function runAgent(prompt: string) { ... }',
        reproductionSteps: [`Scanned long-running agent execution route in ${file.path}:${lineNum}.`, 'Detected long-running agent handler without AbortSignal / AbortController cancellation handler.'],
        remediationPrompt: `Add AbortController / AbortSignal support to agent route in ${file.path} to allow instant user cancellation of runaway agent tasks.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-100: Missing AbortController signal listener detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-106: Empty Silent Catch Block
    if (!isCompiledBundle && (/catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*\}/.test(file.content) || file.content.includes('catch (e) {}') || file.content.includes('catch {}'))) {
      const matchLineIdx = lines.findIndex(l => /catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*\}/.test(l) || l.includes('catch (e) {}') || l.includes('catch {}'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 106,
        type: 'VIBEPOLISH',
        title: 'UI-106: Empty Silent Catch Block',
        severity: 'HIGH',
        category: 'Code Quality & Refactoring',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'try { ... } catch (e) {}',
        reproductionSteps: [`Scanned try-catch blocks in ${file.path}:${lineNum}.`, 'Detected empty catch block swallowing runtime errors without logging or rethrowing.'],
        remediationPrompt: `Remove empty catch block in ${file.path}. Log caught error with context and error ID or rethrow to error handling boundary.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-106 Empty catch block detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-111: TypeScript Any Type Safety Escape
    const anyMatches = (file.content.match(/:\s*any\b|as\s+any\b/g) || []).length;
    if (anyMatches > 5) {
      const matchLineIdx = lines.findIndex(l => /:\s*any\b|as\s+any\b/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 111,
        type: 'VIBEPOLISH',
        title: 'UI-111: TypeScript "any" Type Escape',
        severity: 'MEDIUM',
        category: 'TypeScript & Types',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'const data: unknown = response.json();',
        reproductionSteps: [`Scanned TypeScript type definitions in ${file.path}.`, `Detected ${anyMatches} occurrences of "any" type bypassing type safety.`],
        remediationPrompt: `Replace "any" types in ${file.path} with strict Zod interfaces or unknown + type guard functions.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-111: Excessive 'any' type usage detected (${file.path})`);
    }

    // VibePolish UI-115: Monolithic File Overuse (>500 Lines for atomic components, >1200 Lines for composite views/pages)
    const isCompositeViewOrPage = /View\.[tj]sx$|page\.[tj]sx$|Modal\.[tj]sx$|Table\.[tj]sx$/i.test(file.path);
    const maxLinesAllowed = isCompositeViewOrPage ? 1200 : 500;
    if (lines.length > maxLinesAllowed && (file.path.endsWith('.tsx') || file.path.endsWith('.jsx'))) {
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 115,
        type: 'VIBEPOLISH',
        title: 'UI-115: Monolithic Overly Long Source File (>500 Lines)',
        severity: 'MEDIUM',
        category: 'Code Architecture',
        filePath: file.path,
        lineRange: `L1-L${lines.length}`,
        snippet: `// ${file.path} contains ${lines.length} lines of code`,
        reproductionSteps: [`Scanned file line count for ${file.path}.`, `Detected monolithic component containing ${lines.length} lines without sub-component extraction.`],
        remediationPrompt: `Decompose monolithic file ${file.path} (${lines.length} lines) into smaller modular sub-components (max 250 lines per file).`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-115: Monolithic long file detected (${file.path})`);
    }

    // VibePolish UI-117: Uncleaned Event Listener Memory Leaks (Focus on components/hooks, skip third-party vendor & bootstrap entry files)
    const isVendorOrLib = isCompiledBundle || /(?:^|\/)(?:vendor|libs?|external|third_party|dist|bundles|node_modules)\//i.test(lowerFilePath);
    const isBootstrapOrEntry = /(?:boot|client-app|main|index|entry|setup)\.[a-zA-Z0-9]+$/i.test(lowerFilePath);
    const isComponentOrHook = lowerFilePath.includes('/components/') || lowerFilePath.includes('/hooks/') || lowerFilePath.includes('/views/') || file.content.includes('useEffect') || file.content.includes('componentDidMount');
    if (!isVendorOrLib && !isBootstrapOrEntry && isComponentOrHook && file.content.includes('addEventListener(') && !file.content.includes('removeEventListener(')) {
      const matchLineIdx = lines.findIndex(l => l.includes('addEventListener('));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 117,
        type: 'VIBEPOLISH',
        title: 'UI-117: Uncleaned Event Listener Memory Leak',
        severity: 'HIGH',
        category: 'Database & Performance',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'window.addEventListener("resize", handleResize);',
        reproductionSteps: [`Scanned event listener bindings in ${file.path}:${lineNum}.`, 'Detected addEventListener call without matching removeEventListener in cleanup handler.'],
        remediationPrompt: `Add cleanup function returning removeEventListener in useEffect hook in ${file.path} to prevent memory leaks.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-117 Uncleaned event listener detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-121: Synchronous Non-Streaming LLM Completion
    if (file.content.includes('chat.completions.create') && !file.content.includes('stream: true') && !file.content.includes('json') && !file.content.includes('response_format')) {
      const matchLineIdx = lines.findIndex(l => l.includes('chat.completions.create'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 121,
        type: 'VIBEPOLISH',
        title: 'UI-121: Synchronous Non-Streaming LLM Completion (Missing Stream: True)',
        severity: 'HIGH',
        category: 'Streaming & Latency',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ model: "gpt-4o", messages });',
        reproductionSteps: [`Scanned LLM completion call in ${file.path}:${lineNum}.`, 'Detected synchronous text generation call without stream: true (causes high TTFT latency).'],
        remediationPrompt: `Enable stream: true and SSE (Server-Sent Events) streaming response in ${file.path} for instant 300ms Time-to-First-Token UI rendering.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-121: Non-streaming synchronous LLM call detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-134: Unvirtualized Long List DOM Memory Leaks
    if (file.content.includes('messages.map') && !file.content.includes('virtual') && !file.content.includes('useVirtualizer')) {
      const matchLineIdx = lines.findIndex(l => l.includes('messages.map'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 134,
        type: 'VIBEPOLISH',
        title: 'UI-134: Unvirtualized Long List (Missing Virtual Scrolling)',
        severity: 'MEDIUM',
        category: 'Frontend Performance',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'messages.map(msg => <MessageCard key={msg.id} ... />)',
        reproductionSteps: [`Scanned chat list rendering in ${file.path}:${lineNum}.`, 'Detected unvirtualized message history list rendering all items simultaneously to DOM.'],
        remediationPrompt: `Implement Virtual Scrolling using @tanstack/react-virtual in ${file.path} to render only visible message items.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-134: Unvirtualized long list detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-139: Missing Request Abort Signal Listener
    if (file.content.includes('StreamingTextResponse') && !file.content.includes('signal') && !file.content.includes('aborted')) {
      const matchLineIdx = lines.findIndex(l => l.includes('StreamingTextResponse'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 139,
        type: 'VIBEPOLISH',
        title: 'UI-139: Missing Request Cancellation AbortSignal Listener',
        severity: 'HIGH',
        category: 'Streaming & Latency',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'return new StreamingTextResponse(stream);',
        reproductionSteps: [`Scanned streaming route handler in ${file.path}:${lineNum}.`, 'Detected streaming response without request.signal abort listener (backend continues burning tokens if client closes tab).'],
        remediationPrompt: `Listen to req.signal abort event in ${file.path} to instantly terminate backend model API calls when user closes tab.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-139: Missing request cancellation listener detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-141: Unbounded Token Usage Waste
    if (file.content.includes('chat.completions.create') && !file.content.includes('max_tokens') && !file.content.includes('maxTokens')) {
      const matchLineIdx = lines.findIndex(l => l.includes('chat.completions.create'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 141,
        type: 'VIBEPOLISH',
        title: 'UI-141: Unbounded Token Consumption (Missing max_tokens Limit)',
        severity: 'MEDIUM',
        category: 'Token Economy & Costs',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ model: "gpt-4o", messages });',
        reproductionSteps: [`Scanned model completion call in ${file.path}:${lineNum}.`, 'Detected completion call without explicit max_tokens parameter (risks unbounded output token bills).'],
        remediationPrompt: `Add explicit max_tokens boundary in ${file.path} (e.g. max_tokens: 1500) and conciseness system rules to limit token bleed.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-141: Unbounded max_tokens parameter detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-143: Unmonitored Per-User Token Spend
    if (file.content.includes('/api/generate') && !file.content.includes('usage') && !file.content.includes('quota') && !file.content.includes('deductCredits')) {
      const matchLineIdx = lines.findIndex(l => l.includes('/api/generate') || l.includes('export async function POST'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 143,
        type: 'VIBEPOLISH',
        title: 'UI-143: Unmonitored Per-User Token Spend & Quota',
        severity: 'HIGH',
        category: 'User Quotas & Credits',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'export async function POST(req: Request) { ... }',
        reproductionSteps: [`Scanned AI endpoint in ${file.path}:${lineNum}.`, 'Detected completion route generating responses without tracking user-level token usage or deducting user credit quota.'],
        remediationPrompt: `Implement user-level token usage tracking and credit quota deduction in ${file.path} before returning model responses.`,
        status: 'OPEN',
        owner: 'Finance & Billing Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-143 Unmonitored user token usage detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-160: Missing Spend Circuit Breaker
    if (file.content.includes('OpenAI(') && !file.content.includes('budget') && !file.content.includes('circuitBreaker') && !file.content.includes('maxMonthlySpend')) {
      const matchLineIdx = lines.findIndex(l => l.includes('OpenAI('));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 160,
        type: 'VIBEPOLISH',
        title: 'UI-160: Missing Automated Budget Circuit Breaker',
        severity: 'CRITICAL',
        category: 'FinOps & Circuit Breakers',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });',
        reproductionSteps: [`Scanned AI SDK initialization in ${file.path}:${lineNum}.`, 'Detected LLM client initialization without hard budget limit circuit breaker or spending spike guardrails.'],
        remediationPrompt: `Add FinOps Circuit Breaker middleware in ${file.path} to instantly halt API calls if hourly/daily spending spikes exceed safety thresholds.`,
        status: 'OPEN',
        owner: 'DevOps / FinOps Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-160 Missing budget circuit breaker detected (${file.path}:${lineNum})`);
    }

    // VibePolish UI-185: Missing User Feedback Component
    if (file.content.includes('MessageCard') || file.content.includes('AIResponseView')) {
      if (!file.content.includes('onFeedback') && !file.content.includes('thumbsUp') && !file.content.includes('rateResponse')) {
        const matchLineIdx = lines.findIndex(l => l.includes('MessageCard') || l.includes('AIResponseView'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 185,
          type: 'VIBEPOLISH',
          title: 'UI-185: Missing User Feedback Component',
          severity: 'MEDIUM',
          category: 'User Feedback & AB Testing',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: lines[matchLineIdx] || 'export function MessageCard({ content }: MessageCardProps) { ... }',
          reproductionSteps: [`Scanned AI output UI component in ${file.path}:${lineNum}.`, 'Detected response display component without Thumbs Up/Down or tagged feedback trigger.'],
          remediationPrompt: `Add 1-click feedback widget with tags ("Too long", "Inaccurate", "Incomplete") to ${file.path} to feed closed-loop evaluations.`,
          status: 'OPEN',
          owner: 'Frontend Team',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-185: Missing user feedback component detected (${file.path}:${lineNum})`);
      }
    }

    // VibePolish UI-195: Exposing Raw Model Parameters
    if (file.content.includes('top_p') || file.content.includes('presence_penalty') || file.content.includes('frequency_penalty')) {
      if (file.path.endsWith('.tsx') || file.path.endsWith('.jsx')) {
        const matchLineIdx = lines.findIndex(l => /top_p|presence_penalty|frequency_penalty/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 195,
          type: 'VIBEPOLISH',
          title: 'UI-195: Exposing Raw Hyper-parameters to End Users',
          severity: 'LOW',
          category: 'User Experience & Retention',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: lines[matchLineIdx] || '<input type="range" name="top_p" ... />',
          reproductionSteps: [`Scanned user settings UI in ${file.path}:${lineNum}.`, 'Detected raw LLM hyperparameters (top_p / presence_penalty) exposed directly to end-user UI.'],
          remediationPrompt: `Hide raw hyperparameter inputs in ${file.path} behind user-friendly presets ("Creative", "Precise", "Balanced").`,
          status: 'OPEN',
          owner: 'UX Team',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-195: Raw hyper-parameter input detected (${file.path}:${lineNum})`);
      }
    }

    // VibePolish UI-197: Unpinned Generic Model Alias
    if (file.content.includes('model: "gpt-4o"') || file.content.includes('model: "claude-3-5-sonnet"')) {
      const matchLineIdx = lines.findIndex(l => l.includes('model: "gpt-4o"') || l.includes('model: "claude-3-5-sonnet"'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 197,
        type: 'VIBEPOLISH',
        title: 'UI-197: Unpinned Generic Model Tag (Missing Date-Pinned Model Version)',
        severity: 'MEDIUM',
        category: 'LLM Provider & Versioning',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'model: "gpt-4o"',
        reproductionSteps: [`Scanned model configuration in ${file.path}:${lineNum}.`, 'Detected unpinned generic model alias ("gpt-4o") vulnerable to silent breaking changes on upstream model updates.'],
        remediationPrompt: `Pin explicit snapshot version in ${file.path} (e.g. "gpt-4o-2024-08-06" or "claude-3-5-sonnet-20241022") to guarantee output consistency.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-197: Unpinned model alias detected (${file.path}:${lineNum})`);
    }

    // AI Web Design Cliché Detection (25 rules from yapay_zeka_web_tasarim_kliseleri.pdf)
    const clicheCounter = { count: findingCounter };
    const clicheResult = evaluateAiClicheRules(file, lines, cleanContent, clicheCounter);
    findingCounter = clicheCounter.count;
    for (const cf of clicheResult.findings) {
      if (!ignoredRuleIds.has(cf.ruleId)) {
        addFinding(cf);
      }
    }
    logs.push(...clicheResult.logs);

    // Option B: Frontend Performance, WCAG 2.2 AA & SEO Rules (UI-A11Y-01, UI-PERF-01, UI-SEO-01)
    const frontendCounter = { count: findingCounter };
    const frontendResult = evaluateFrontendRules(file, lines, cleanContent, frontendCounter);
    findingCounter = frontendCounter.count;
    for (const ff of frontendResult.findings) {
      addFinding(ff);
    }
    logs.push(...frontendResult.logs);

    // Global Regulatory, Privacy & Legal Pre-Flight Gate (Rules 2001-2006)
    // Global Regulatory, Privacy & Legal Pre-Flight Gate (Rules 2001-2006)
    const complianceCounter = { count: findingCounter };
    const complianceResult = evaluateComplianceRules(file, lines, cleanContent, complianceCounter);
    findingCounter = complianceCounter.count;
    for (const cf of complianceResult.findings) {
      addFinding(cf);
    }
    logs.push(...complianceResult.logs);

    // Infrastructure, Cloud & Database Security Engine (Rules 3001-3006)
    const infraCounter = { count: findingCounter };
    const infraResult = evaluateInfraRules(file, lines, cleanContent, infraCounter);
    findingCounter = infraCounter.count;
    for (const inf of infraResult.findings) {
      addFinding(inf);
    }
    logs.push(...infraResult.logs);

    // Wave 1 Enterprise Release Gate Engines:
    // 1. Frontend Interaction & Modal Traps (UI-INTERACT-01 to 50, Rule IDs 1201-1250)
    const interactCounter = { count: findingCounter };
    const interactResult = evaluateInteractionRules(file, lines, cleanContent, interactCounter);
    findingCounter = interactCounter.count;
    for (const item of interactResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...interactResult.logs);

    // 2. Enterprise Secret Signatures (SEC-SECRET-01 to 100, Rule IDs 5001-5100)
    // F-16 Remediation: Scan unstripped content including comments to eliminate blind spots
    const secretCounter = { count: findingCounter };
    const secretResult = evaluateSecretRules(file, lines, rawContent, secretCounter);
    findingCounter = secretCounter.count;
    for (const item of secretResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...secretResult.logs);

    // 3. Database & ORM Performance Engine (DB-PERF-01 to 50, Rule IDs 6001-6050)
    const dbCounter = { count: findingCounter };
    const dbResult = evaluateDatabaseRules(file, lines, cleanContent, dbCounter);
    findingCounter = dbCounter.count;
    for (const item of dbResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...dbResult.logs);

    // Wave 2 Enterprise Release Gate Engines:
    // 4. Cloud Native, Serverless & Edge (CLOUD-01 to 50, Rule IDs 7001-7050)
    const cloudCounter = { count: findingCounter };
    const cloudResult = evaluateCloudNativeRules(file, lines, cleanContent, cloudCounter);
    findingCounter = cloudCounter.count;
    for (const item of cloudResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cloudResult.logs);

    // 5. Core Web Vitals & Advanced Performance (WEB-PERF-01 to 50, Rule IDs 7101-7150)
    const webPerfCounter = { count: findingCounter };
    const webPerfResult = evaluateWebVitalsRules(file, lines, cleanContent, webPerfCounter);
    findingCounter = webPerfCounter.count;
    for (const item of webPerfResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...webPerfResult.logs);

    // 6. API Architecture & Microservices Reliability (API-01 to 50, Rule IDs 7201-7250)
    const apiCounter = { count: findingCounter };
    const apiResult = evaluateApiRules(file, lines, cleanContent, apiCounter);
    findingCounter = apiCounter.count;
    for (const item of apiResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...apiResult.logs);

    // 7. Supply Chain, SBOM & Dependency Security (SUPPLY-01 to 50, Rule IDs 7301-7350)
    const supplyCounter = { count: findingCounter };
    const supplyResult = evaluateSupplyChainRules(file, lines, cleanContent, supplyCounter);
    findingCounter = supplyCounter.count;
    for (const item of supplyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...supplyResult.logs);

    // Wave 3 Enterprise Release Gate Engines (Milestone 1,000 Rules):
    // 8. AI Safety & LLM Guardrails (LLM-SEC-01 to 60, Rule IDs 8001-8060)
    const aiSafetyCounter = { count: findingCounter };
    const aiSafetyResult = evaluateAiSafetyRules(file, lines, cleanContent, aiSafetyCounter);
    findingCounter = aiSafetyCounter.count;
    for (const item of aiSafetyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...aiSafetyResult.logs);

    // 9. Zero Trust & Authentication Resilience (ZERO-AUTH-01 to 55, Rule IDs 8101-8155)
    const zeroTrustCounter = { count: findingCounter };
    const zeroTrustResult = evaluateZeroTrustRules(file, lines, cleanContent, zeroTrustCounter);
    findingCounter = zeroTrustCounter.count;
    for (const item of zeroTrustResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...zeroTrustResult.logs);

    // 10. Data Privacy & GDPR Compliance (PRIVACY-01 to 50, Rule IDs 8201-8250)
    const privacyCounter = { count: findingCounter };
    const privacyResult = evaluatePrivacyComplianceRules(file, lines, cleanContent, privacyCounter);
    findingCounter = privacyCounter.count;
    for (const item of privacyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...privacyResult.logs);

    // 11. Infrastructure as Code & Container Hardening (IAC-01 to 50, Rule IDs 8301-8350)
    const iacCounter = { count: findingCounter };
    const iacResult = evaluateIacRules(file, lines, cleanContent, iacCounter);
    findingCounter = iacCounter.count;
    for (const item of iacResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...iacResult.logs);

    // 12. Enterprise Reliability & Chaos Engineering (CHAOS-01 to 48, Rule IDs 8401-8448)
    const chaosCounter = { count: findingCounter };
    const chaosResult = evaluateChaosResilienceRules(file, lines, cleanContent, chaosCounter);
    findingCounter = chaosCounter.count;
    for (const item of chaosResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...chaosResult.logs);

    // Wave 4 Enterprise Release Gate Engines (Milestone 1,100 Rules):
    // 13. GraphQL & Modern API Security (GQL-01 to 50, Rule IDs 8501-8550)
    const gqlCounter = { count: findingCounter };
    const gqlResult = evaluateGraphqlSecurityRules(file, lines, cleanContent, gqlCounter);
    findingCounter = gqlCounter.count;
    for (const item of gqlResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...gqlResult.logs);

    // 14. Modern Fullstack Next.js 15 & React 19 (NEXT15-01 to 50, Rule IDs 8601-8650)
    const next15Counter = { count: findingCounter };
    const next15Result = evaluateModernFullstackRules(file, lines, cleanContent, next15Counter);
    findingCounter = next15Counter.count;
    for (const item of next15Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...next15Result.logs);

    // Wave 5 Enterprise Release Gate Engines (Milestone 1,350 Rules):
    // 15. Web3 & Smart Contract Security (WEB3-01 to 50, Rule IDs 8701-8750)
    const web3Counter = { count: findingCounter };
    const web3Result = evaluateWeb3SecurityRules(file, lines, cleanContent, web3Counter);
    findingCounter = web3Counter.count;
    for (const item of web3Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...web3Result.logs);

    // 16. Python & FastAPI / Django Enterprise Gate (PY-SEC-01 to 50, Rule IDs 8801-8850)
    const pyCounter = { count: findingCounter };
    const pyResult = evaluatePythonEnterpriseRules(file, lines, cleanContent, pyCounter);
    findingCounter = pyCounter.count;
    for (const item of pyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...pyResult.logs);

    // 16b. Polyglot Backend Gate (PHP, Java, C#/.NET, Ruby - Rule IDs 18001-18050)
    const polyglotCounter = { count: findingCounter };
    const polyglotResult = evaluatePolyglotBackendRules(file, lines, cleanContent, polyglotCounter);
    findingCounter = polyglotCounter.count;
    for (const item of polyglotResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...polyglotResult.logs);

    // 16c. Universal Multi-Database & ORM Gate (MySQL, MongoDB, Redis, SQLite, Prisma - Rule IDs 18101-18150)
    const multiDbCounter = { count: findingCounter };
    const multiDbResult = evaluateMultiDatabaseRules(file, lines, cleanContent, multiDbCounter);
    findingCounter = multiDbCounter.count;
    for (const item of multiDbResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...multiDbResult.logs);

    // 17. Kubernetes & Cloud Orchestration Hardening (K8S-01 to 50, Rule IDs 8901-8950)
    const k8sCounter = { count: findingCounter };
    const k8sResult = evaluateK8sHardeningRules(file, lines, cleanContent, k8sCounter);
    findingCounter = k8sCounter.count;
    for (const item of k8sResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...k8sResult.logs);

    // 18. Go & Cloud Native Microservices Resilience (GO-01 to 50, Rule IDs 9001-9050)
    const goCounter = { count: findingCounter };
    const goResult = evaluateGoMicroservicesRules(file, lines, cleanContent, goCounter);
    findingCounter = goCounter.count;
    for (const item of goResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...goResult.logs);

    // 19. Multi-Tenant SaaS & Data Isolation Gate (TENANT-01 to 50, Rule IDs 9101-9150)
    const tenantCounter = { count: findingCounter };
    const tenantResult = evaluateTenantIsolationRules(file, lines, cleanContent, tenantCounter);
    findingCounter = tenantCounter.count;
    for (const item of tenantResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...tenantResult.logs);

    // Wave 6 Enterprise Release Gate Engines (Milestone 1,600 Rules):
    // 20. Multi-Cloud AWS/GCP/Azure Security (CLOUD-SEC-01 to 50, Rule IDs 9201-9250)
    const cloudSecCounter = { count: findingCounter };
    const cloudSecResult = evaluateCloudSecurityRules(file, lines, cleanContent, cloudSecCounter);
    findingCounter = cloudSecCounter.count;
    for (const item of cloudSecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cloudSecResult.logs);

    // 21. Mobile App Security & Integrity Gate (MOB-SEC-01 to 50, Rule IDs 9301-9350)
    const mobSecCounter = { count: findingCounter };
    const mobSecResult = evaluateMobileSecurityRules(file, lines, cleanContent, mobSecCounter);
    findingCounter = mobSecCounter.count;
    for (const item of mobSecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...mobSecResult.logs);

    // 22. Kafka & Event Streaming Hardening (EVENT-01 to 50, Rule IDs 9401-9450)
    const eventCounter = { count: findingCounter };
    const eventResult = evaluateEventStreamingRules(file, lines, cleanContent, eventCounter);
    findingCounter = eventCounter.count;
    for (const item of eventResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...eventResult.logs);

    // 23. CI/CD Pipeline & Supply Chain Hardening (CICD-SEC-01 to 50, Rule IDs 9501-9550)
    const cicdSecCounter = { count: findingCounter };
    const cicdSecResult = evaluateCicdSupplyChainRules(file, lines, cleanContent, cicdSecCounter);
    findingCounter = cicdSecCounter.count;
    for (const item of cicdSecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cicdSecResult.logs);

    // 24. Rust & Memory-Safe Systems Gate (RUST-01 to 50, Rule IDs 9601-9650)
    const rustCounter = { count: findingCounter };
    const rustResult = evaluateRustSystemsRules(file, lines, cleanContent, rustCounter);
    findingCounter = rustCounter.count;
    for (const item of rustResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...rustResult.logs);

    // Wave 7 Enterprise Release Gate Engines (Milestone 1,850 Rules):
    // 25. Fintech & PCI-DSS Compliance Gate (FINTECH-01 to 50, Rule IDs 9701-9750)
    const fintechCounter = { count: findingCounter };
    const fintechResult = evaluateFintechComplianceRules(file, lines, cleanContent, fintechCounter);
    findingCounter = fintechCounter.count;
    for (const item of fintechResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...fintechResult.logs);

    // 26. Healthcare & HIPAA Data Privacy Gate (HIPAA-01 to 50, Rule IDs 9801-9850)
    const hipaaCounter = { count: findingCounter };
    const hipaaResult = evaluateHipaaComplianceRules(file, lines, cleanContent, hipaaCounter);
    findingCounter = hipaaCounter.count;
    for (const item of hipaaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...hipaaResult.logs);

    // 27. Cloud Native Observability & Tracing (OTEL-01 to 50, Rule IDs 9901-9950)
    const otelCounter = { count: findingCounter };
    const otelResult = evaluateOtelObservabilityRules(file, lines, cleanContent, otelCounter);
    findingCounter = otelCounter.count;
    for (const item of otelResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...otelResult.logs);

    // 28. C/C++ Systems Memory Safety Gate (CPP-SEC-01 to 50, Rule IDs 10001-10050)
    const cppCounter = { count: findingCounter };
    const cppResult = evaluateCppMemoryRules(file, lines, cleanContent, cppCounter);
    findingCounter = cppCounter.count;
    for (const item of cppResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cppResult.logs);

    // 29. eCommerce & Inventory Integrity Gate (ECOMM-01 to 50, Rule IDs 10101-10150)
    const ecommCounter = { count: findingCounter };
    const ecommResult = evaluateEcommInventoryRules(file, lines, cleanContent, ecommCounter);
    findingCounter = ecommCounter.count;
    for (const item of ecommResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...ecommResult.logs);

    // Wave 8 Enterprise Release Gate Engines (Milestone 2,100 Rules):
    // 30. High-Performance gRPC & Protobuf RPC Architecture (GRPC-01 to 50, Rule IDs 10201-10250)
    const grpcCounter = { count: findingCounter };
    const grpcResult = evaluateGrpcProtobufRules(file, lines, cleanContent, grpcCounter);
    findingCounter = grpcCounter.count;
    for (const item of grpcResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...grpcResult.logs);

    // 31. PostgreSQL Internals, pgvector & Advanced Optimization (PG-01 to 50, Rule IDs 10301-10350)
    const pgCounter = { count: findingCounter };
    const pgResult = evaluatePgvectorPostgresRules(file, lines, cleanContent, pgCounter);
    findingCounter = pgCounter.count;
    for (const item of pgResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...pgResult.logs);

    // 32. Cloud WAF, DDoS Protection & Edge Security (WAF-01 to 50, Rule IDs 10401-10450)
    const wafCounter = { count: findingCounter };
    const wafResult = evaluateWafEdgeRules(file, lines, cleanContent, wafCounter);
    findingCounter = wafCounter.count;
    for (const item of wafResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...wafResult.logs);

    // 33. Real-Time WebSocket & Event Stream Gate (WS-01 to 50, Rule IDs 10501-10550)
    const wsCounter = { count: findingCounter };
    const wsResult = evaluateWebsocketRealtimeRules(file, lines, cleanContent, wsCounter);
    findingCounter = wsCounter.count;
    for (const item of wsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...wsResult.logs);

    // 34. AICPA SOC 2 Type II Trust Services Criteria (SOC2-01 to 50, Rule IDs 10601-10650)
    const soc2Counter = { count: findingCounter };
    const soc2Result = evaluateSoc2AuditRules(file, lines, cleanContent, soc2Counter);
    findingCounter = soc2Counter.count;
    for (const item of soc2Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...soc2Result.logs);

    // Wave 9 Enterprise Release Gate Engines (Milestone 2,350 Rules):
    // 35. Redis & In-Memory Distributed Cache Reliability (CACHE-01 to 50, Rule IDs 10701-10750)
    const cacheCounter = { count: findingCounter };
    const cacheResult = evaluateCacheRedisRules(file, lines, cleanContent, cacheCounter);
    findingCounter = cacheCounter.count;
    for (const item of cacheResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cacheResult.logs);

    // 36. ISO/IEC 27001:2022 Information Security Management Controls (ISO-01 to 50, Rule IDs 10801-10850)
    const isoCounter = { count: findingCounter };
    const isoResult = evaluateIso27001ComplianceRules(file, lines, cleanContent, isoCounter);
    findingCounter = isoCounter.count;
    for (const item of isoResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...isoResult.logs);

    // 37. OAuth 2.1 & OpenID Connect (OIDC) Modern Identity (OAUTH-01 to 50, Rule IDs 10901-10950)
    const oauthCounter = { count: findingCounter };
    const oauthResult = evaluateOauthOidcRules(file, lines, cleanContent, oauthCounter);
    findingCounter = oauthCounter.count;
    for (const item of oauthResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...oauthResult.logs);

    // 38. Terraform & Cloud Infrastructure-as-Code Policy (TF-01 to 50, Rule IDs 11001-11050)
    const tfCounter = { count: findingCounter };
    const tfResult = evaluateTerraformIacRules(file, lines, cleanContent, tfCounter);
    findingCounter = tfCounter.count;
    for (const item of tfResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...tfResult.logs);

    // 39. Edge CDN, HTTP/3 & Asset Delivery Optimization (CDN-01 to 50, Rule IDs 11101-11150)
    const cdnCounter = { count: findingCounter };
    const cdnResult = evaluateEdgeCdnRules(file, lines, cleanContent, cdnCounter);
    findingCounter = cdnCounter.count;
    for (const item of cdnResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cdnResult.logs);

    // Wave 10 Enterprise Release Gate Engines (Milestone 2,600 Rules):
    // 40. Service Mesh, Istio & Envoy Traffic Resilience (MESH-01 to 50, Rule IDs 11201-11250)
    const meshCounter = { count: findingCounter };
    const meshResult = evaluateServiceMeshRules(file, lines, cleanContent, meshCounter);
    findingCounter = meshCounter.count;
    for (const item of meshResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...meshResult.logs);

    // 41. Serverless Functions & AWS Lambda Reliability (SLS-01 to 50, Rule IDs 11301-11350)
    const slsCounter = { count: findingCounter };
    const slsResult = evaluateServerlessLambdaRules(file, lines, cleanContent, slsCounter);
    findingCounter = slsCounter.count;
    for (const item of slsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...slsResult.logs);

    // 42. API Gateway, Rate Limiting & Abuse Defense (GW-01 to 50, Rule IDs 11401-11450)
    const gwCounter = { count: findingCounter };
    const gwResult = evaluateApiGatewayRules(file, lines, cleanContent, gwCounter);
    findingCounter = gwCounter.count;
    for (const item of gwResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...gwResult.logs);

    // 43. Data Engineering, ETL Pipeline & Data Lake Governance (DATA-01 to 50, Rule IDs 11501-11550)
    const dataCounter = { count: findingCounter };
    const dataResult = evaluateDataPipelineRules(file, lines, cleanContent, dataCounter);
    findingCounter = dataCounter.count;
    for (const item of dataResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...dataResult.logs);

    // 44. EU AI Act & Trustworthy Artificial Intelligence Governance (AIACT-01 to 50, Rule IDs 11601-11650)
    const aiactCounter = { count: findingCounter };
    const aiactResult = evaluateEuAiActRules(file, lines, cleanContent, aiactCounter);
    findingCounter = aiactCounter.count;
    for (const item of aiactResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...aiactResult.logs);

    // Wave 11 Enterprise Release Gate Engines (Milestone 2,850 Rules):
    // 45. Distributed Job Scheduling & Cron Reliability (CRON-01 to 50, Rule IDs 11701-11750)
    const cronCounter = { count: findingCounter };
    const cronResult = evaluateCronSchedulerRules(file, lines, cleanContent, cronCounter);
    findingCounter = cronCounter.count;
    for (const item of cronResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cronResult.logs);

    // 46. DNSSEC, BGP & Anycast Routing Defense (DNS-01 to 50, Rule IDs 11801-11850)
    const dnsCounter = { count: findingCounter };
    const dnsResult = evaluateDnsSecurityRules(file, lines, cleanContent, dnsCounter);
    findingCounter = dnsCounter.count;
    for (const item of dnsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...dnsResult.logs);

    // 47. NIST SP 800-53 Rev. 5 & FedRAMP Cloud Controls (NIST-01 to 50, Rule IDs 11901-11950)
    const nistCounter = { count: findingCounter };
    const nistResult = evaluateNistSp80053Rules(file, lines, cleanContent, nistCounter);
    findingCounter = nistCounter.count;
    for (const item of nistResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...nistResult.logs);

    // 48. Graph Database & Cypher Traversal Governance (GRPH-01 to 50, Rule IDs 12001-12050)
    const grphCounter = { count: findingCounter };
    const grphResult = evaluateGraphDatabaseRules(file, lines, cleanContent, grphCounter);
    findingCounter = grphCounter.count;
    for (const item of grphResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...grphResult.logs);

    // 49. Enterprise SIEM & Syslog Audit Integrity (AUDIT-01 to 50, Rule IDs 12101-12150)
    const auditCounter = { count: findingCounter };
    const auditResult = evaluateSiemAuditLoggingRules(file, lines, cleanContent, auditCounter);
    findingCounter = auditCounter.count;
    for (const item of auditResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...auditResult.logs);

    // Wave 12 Enterprise Release Gate Engines (Milestone 3,100 Rules):
    // 50. OCI Container Security & Pod Security Standards (CONTAINER-01 to 50, Rule IDs 12201-12250)
    const containerCounter = { count: findingCounter };
    const containerResult = evaluateContainerSecurityRules(file, lines, cleanContent, containerCounter);
    findingCounter = containerCounter.count;
    for (const item of containerResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...containerResult.logs);

    // 51. TLS 1.3 & Post-Quantum Cryptography (TLS-01 to 50, Rule IDs 12301-12350)
    const tlsCounter = { count: findingCounter };
    const tlsResult = evaluateTlsCryptographyRules(file, lines, cleanContent, tlsCounter);
    findingCounter = tlsCounter.count;
    for (const item of tlsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...tlsResult.logs);

    // 52. EU DORA Digital Operational Resilience (DORA-01 to 50, Rule IDs 12401-12450)
    const doraCounter = { count: findingCounter };
    const doraResult = evaluateDoraComplianceRules(file, lines, cleanContent, doraCounter);
    findingCounter = doraCounter.count;
    for (const item of doraResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...doraResult.logs);

    // 53. Enterprise Message Broker & AMQP 0-9-1 Reliability (MQ-01 to 50, Rule IDs 12501-12550)
    const mqCounter = { count: findingCounter };
    const mqResult = evaluateMessageBrokerRules(file, lines, cleanContent, mqCounter);
    findingCounter = mqCounter.count;
    for (const item of mqResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...mqResult.logs);

    // 54. CycloneDX / SPDX SBOM Deep Supply Chain Attestation (SBOM-01 to 50, Rule IDs 12601-12650)
    const sbomCounter = { count: findingCounter };
    const sbomResult = evaluateSbomAttestationRules(file, lines, cleanContent, sbomCounter);
    findingCounter = sbomCounter.count;
    for (const item of sbomResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...sbomResult.logs);

    // Wave 13 Enterprise Release Gate Engines (Milestone 3,350 Rules):
    // 55. WebAssembly & WASI Sandbox Resilience (WASM-01 to 50, Rule IDs 12701-12750)
    const wasmCounter = { count: findingCounter };
    const wasmResult = evaluateWasmRuntimeRules(file, lines, cleanContent, wasmCounter);
    findingCounter = wasmCounter.count;
    for (const item of wasmResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...wasmResult.logs);

    // 56. Enterprise SAML 2.0 & SCIM Identity Governance (SSO-01 to 50, Rule IDs 12801-12850)
    const ssoCounter = { count: findingCounter };
    const ssoResult = evaluateEnterpriseSsoRules(file, lines, cleanContent, ssoCounter);
    findingCounter = ssoCounter.count;
    for (const item of ssoResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...ssoResult.logs);

    // 57. PCI-DSS v4.0 Modern Payment Security Standards (PCI4-01 to 50, Rule IDs 12901-12950)
    const pci4Counter = { count: findingCounter };
    const pci4Result = evaluatePciDssV4Rules(file, lines, cleanContent, pci4Counter);
    findingCounter = pci4Counter.count;
    for (const item of pci4Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...pci4Result.logs);

    // 58. Elasticsearch & OpenSearch Index Optimization (SEARCH-01 to 50, Rule IDs 13001-13050)
    const searchCounter = { count: findingCounter };
    const searchResult = evaluateSearchEngineRules(file, lines, cleanContent, searchCounter);
    findingCounter = searchCounter.count;
    for (const item of searchResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...searchResult.logs);

    // 59. Software-Defined Perimeter & Zero Trust Mesh (SDP-01 to 50, Rule IDs 13101-13150)
    const sdpCounter = { count: findingCounter };
    const sdpResult = evaluateZeroTrustNetworkRules(file, lines, cleanContent, sdpCounter);
    findingCounter = sdpCounter.count;
    for (const item of sdpResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...sdpResult.logs);

    // Wave 14 Enterprise Release Gate Engines (Milestone 3,600 Rules):
    // 60. Open Policy Agent & Rego Admission Guardrails (OPA-01 to 50, Rule IDs 13201-13250)
    const opaCounter = { count: findingCounter };
    const opaResult = evaluateOpaPolicyRules(file, lines, cleanContent, opaCounter);
    findingCounter = opaCounter.count;
    for (const item of opaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...opaResult.logs);

    // 61. Enterprise KMS, HSM & Cryptographic Hygiene (CRYPTO-01 to 50, Rule IDs 13301-13350)
    const cryptoCounter = { count: findingCounter };
    const cryptoResult = evaluateCryptoKmsRules(file, lines, cleanContent, cryptoCounter);
    findingCounter = cryptoCounter.count;
    for (const item of cryptoResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cryptoResult.logs);

    // 62. SOX Section 404 ITGC Financial Control Compliance (SOX-01 to 50, Rule IDs 13401-13450)
    const soxCounter = { count: findingCounter };
    const soxResult = evaluateSoxComplianceRules(file, lines, cleanContent, soxCounter);
    findingCounter = soxCounter.count;
    for (const item of soxResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...soxResult.logs);

    // 63. Milvus & Qdrant Vector Search Performance & Reliability (VECTOR-01 to 50, Rule IDs 13501-13550)
    const vectorCounter = { count: findingCounter };
    const vectorResult = evaluateVectorDbRules(file, lines, cleanContent, vectorCounter);
    findingCounter = vectorCounter.count;
    for (const item of vectorResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...vectorResult.logs);

    // 64. MITRE ATT&CK Threat Hunting & Canary Deception (THREAT-01 to 50, Rule IDs 13601-13650)
    const threatCounter = { count: findingCounter };
    const threatResult = evaluateThreatDetectionRules(file, lines, cleanContent, threatCounter);
    findingCounter = threatCounter.count;
    for (const item of threatResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...threatResult.logs);

    // Wave 15 Enterprise Release Gate Engines (Milestone 3,850 Rules):
    // 65. Apollo Federation & GraphQL Subgraph Gate (FED-01 to 50, Rule IDs 13701-13750)
    const fedCounter = { count: findingCounter };
    const fedResult = evaluateGraphqlFederationRules(file, lines, cleanContent, fedCounter);
    findingCounter = fedCounter.count;
    for (const item of fedResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...fedResult.logs);

    // 66. OWASP ASVS Level 3 Application Security Verification (ASVS-01 to 50, Rule IDs 13801-13850)
    const asvsCounter = { count: findingCounter };
    const asvsResult = evaluateOwaspAsvsRules(file, lines, cleanContent, asvsCounter);
    findingCounter = asvsCounter.count;
    for (const item of asvsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...asvsResult.logs);

    // 67. FedRAMP High Baseline Cloud Compliance Gate (FEDRAMP-01 to 50, Rule IDs 13901-13950)
    const fedrampCounter = { count: findingCounter };
    const fedrampResult = evaluateFedrampComplianceRules(file, lines, cleanContent, fedrampCounter);
    findingCounter = fedrampCounter.count;
    for (const item of fedrampResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...fedrampResult.logs);

    // 68. Time-Series Databases & Columnar Query Optimization (TSDB-01 to 50, Rule IDs 14001-14050)
    const tsdbCounter = { count: findingCounter };
    const tsdbResult = evaluateTimeSeriesDbRules(file, lines, cleanContent, tsdbCounter);
    findingCounter = tsdbCounter.count;
    for (const item of tsdbResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...tsdbResult.logs);

    // 69. SLSA Level 4 & In-Toto Supply Chain Provenance (SLSA-01 to 50, Rule IDs 14101-14150)
    const slsaCounter = { count: findingCounter };
    const slsaResult = evaluateSlsaProvenanceRules(file, lines, cleanContent, slsaCounter);
    findingCounter = slsaCounter.count;
    for (const item of slsaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...slsaResult.logs);

    // Wave 16 Enterprise Release Gate Engines (Milestone 4,100 Rules):
    // 70. eBPF Kernel Observability & Cilium Security (EBPF-01 to 50, Rule IDs 14201-14250)
    const ebpfCounter = { count: findingCounter };
    const ebpfResult = evaluateEbpfObservabilityRules(file, lines, cleanContent, ebpfCounter);
    findingCounter = ebpfCounter.count;
    for (const item of ebpfResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...ebpfResult.logs);

    // 71. OWASP API Security Top 10 2023 Protocol Defense (APIDEF-01 to 50, Rule IDs 14301-14350)
    const apidefCounter = { count: findingCounter };
    const apidefResult = evaluateOwaspApiSecurityRules(file, lines, cleanContent, apidefCounter);
    findingCounter = apidefCounter.count;
    for (const item of apidefResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...apidefResult.logs);

    // 72. HIPAA Security Rule Safeguards & Audit Trails (HIPAASEC-01 to 50, Rule IDs 14401-14450)
    const hipaasecCounter = { count: findingCounter };
    const hipaasecResult = evaluateHipaaSecurityRules(file, lines, cleanContent, hipaasecCounter);
    findingCounter = hipaasecCounter.count;
    for (const item of hipaasecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...hipaasecResult.logs);

    // 73. RabbitMQ & NATS JetStream Message Ingestion Governance (MQOPT-01 to 50, Rule IDs 14501-14550)
    const mqoptCounter = { count: findingCounter };
    const mqoptResult = evaluateMessageQueueOptRules(file, lines, cleanContent, mqoptCounter);
    findingCounter = mqoptCounter.count;
    for (const item of mqoptResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...mqoptResult.logs);

    // 74. Runtime Application Self-Protection & Binary Anti-Tamper (RASP-01 to 50, Rule IDs 14601-14650)
    const raspCounter = { count: findingCounter };
    const raspResult = evaluateRaspAntiTamperRules(file, lines, cleanContent, raspCounter);
    findingCounter = raspCounter.count;
    for (const item of raspResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...raspResult.logs);

    // Wave 17 Enterprise Release Gate Engines (Milestone 4,350 Rules):
    // 75. gRPC-Web, HTTP/2 & Protobuf Security Gate (GRPCSEC-01 to 50, Rule IDs 14701-14750)
    const grpcsecCounter = { count: findingCounter };
    const grpcsecResult = evaluateGrpcWebSecurityRules(file, lines, cleanContent, grpcsecCounter);
    findingCounter = grpcsecCounter.count;
    for (const item of grpcsecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...grpcsecResult.logs);

    // 76. CSPM Cloud Posture & IAM Privilege Drift (CSPM-01 to 50, Rule IDs 14801-14850)
    const cspmCounter = { count: findingCounter };
    const cspmResult = evaluateCspmCloudPostureRules(file, lines, cleanContent, cspmCounter);
    findingCounter = cspmCounter.count;
    for (const item of cspmResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...cspmResult.logs);

    // 77. GLBA Safeguards Rule Financial Compliance (GLBA-01 to 50, Rule IDs 14901-14950)
    const glbaCounter = { count: findingCounter };
    const glbaResult = evaluateGlbaComplianceRules(file, lines, cleanContent, glbaCounter);
    findingCounter = glbaCounter.count;
    for (const item of glbaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...glbaResult.logs);

    // 78. Geo-Distributed Database Resilience Gate (GEODIST-01 to 50, Rule IDs 15001-15050)
    const geodistCounter = { count: findingCounter };
    const geodistResult = evaluateGeoDistributedDbRules(file, lines, cleanContent, geodistCounter);
    findingCounter = geodistCounter.count;
    for (const item of geodistResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...geodistResult.logs);

    // 79. Cyber Deception, Honeytokens & Threat Trapping (DECEPTION-01 to 50, Rule IDs 15101-15150)
    const deceptionCounter = { count: findingCounter };
    const deceptionResult = evaluateCyberDeceptionRules(file, lines, cleanContent, deceptionCounter);
    findingCounter = deceptionCounter.count;
    for (const item of deceptionResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...deceptionResult.logs);

    // Wave 18 Enterprise Release Gate Engines (Milestone 4,600 Rules):
    // 80. WebAssembly Edge Runtime Sandboxing Gate (WASM-EDGE-01 to 50, Rule IDs 15201-15250)
    const wasmEdgeCounter = { count: findingCounter };
    const wasmEdgeResult = evaluateWasmEdgeRuntimeRules(file, lines, cleanContent, wasmEdgeCounter);
    findingCounter = wasmEdgeCounter.count;
    for (const item of wasmEdgeResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...wasmEdgeResult.logs);

    // 82. EU NIS2 Critical Infrastructure Compliance Gate (NIS2-01 to 50, Rule IDs 15401-15450)
    const nis2Counter = { count: findingCounter };
    const nis2Result = evaluateEuNis2ComplianceRules(file, lines, cleanContent, nis2Counter);
    findingCounter = nis2Counter.count;
    for (const item of nis2Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...nis2Result.logs);

    // 83. Horizontal Database Sharding & VSchema Gate (SHARD-01 to 50, Rule IDs 15501-15550)
    const shardCounter = { count: findingCounter };
    const shardResult = evaluateDatabaseShardingRules(file, lines, cleanContent, shardCounter);
    findingCounter = shardCounter.count;
    for (const item of shardResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...shardResult.logs);

    // 84. Cyber Threat Intelligence (CTI) & STIX/TAXII Gate (CTI-01 to 50, Rule IDs 15601-15650)
    const ctiCounter = { count: findingCounter };
    const ctiResult = evaluateThreatIntelligenceRules(file, lines, cleanContent, ctiCounter);
    findingCounter = ctiCounter.count;
    for (const item of ctiResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...ctiResult.logs);

    // Wave 19 Enterprise Release Gate Engines (Milestone 4,850 Rules):
    // 85. Linux Kernel Hardening & Capabilities Gate (KERN-SEC-01 to 50, Rule IDs 15701-15750)
    const kernSecCounter = { count: findingCounter };
    const kernSecResult = evaluateLinuxKernelSecurityRules(file, lines, cleanContent, kernSecCounter);
    findingCounter = kernSecCounter.count;
    for (const item of kernSecResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...kernSecResult.logs);

    // 86. ISO 20022 Financial Messaging & SLA Gate (ISO20022-01 to 50, Rule IDs 15801-15850)
    const iso20022Counter = { count: findingCounter };
    const iso20022Result = evaluateIso20022FintechRules(file, lines, cleanContent, iso20022Counter);
    findingCounter = iso20022Counter.count;
    for (const item of iso20022Result.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...iso20022Result.logs);

    // 87. Time-Series DB Chunk & Partition Optimization Gate (TSDB-OPT-01 to 50, Rule IDs 15901-15950)
    const tsdbOptCounter = { count: findingCounter };
    const tsdbOptResult = evaluateTimeSeriesDbOptRules(file, lines, cleanContent, tsdbOptCounter);
    findingCounter = tsdbOptCounter.count;
    for (const item of tsdbOptResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...tsdbOptResult.logs);

    // 88. AI Red Teaming & Jailbreak Defense Gate (AI-RED-01 to 50, Rule IDs 16001-16050)
    const aiRedCounter = { count: findingCounter };
    const aiRedResult = evaluateAiRedTeamSecurityRules(file, lines, cleanContent, aiRedCounter);
    findingCounter = aiRedCounter.count;
    for (const item of aiRedResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...aiRedResult.logs);

    // 89. Edge Service Fabric & Anycast Resilience Gate (FABRIC-01 to 50, Rule IDs 16101-16150)
    const fabricCounter = { count: findingCounter };
    const fabricResult = evaluateServiceFabricResilienceRules(file, lines, cleanContent, fabricCounter);
    findingCounter = fabricCounter.count;
    for (const item of fabricResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...fabricResult.logs);

    // Wave 20 Enterprise Release Gate Engines (Milestone 5,100 Rules — 5,000 Barrier Crossed):
    // 90. Basel III & FRTB Quantitative Risk / VaR Gate (QUANT-RISK-01 to 50, Rule IDs 16201-16250)
    const quantRiskCounter = { count: findingCounter };
    const quantRiskResult = evaluateQuantitativeRiskRules(file, lines, cleanContent, quantRiskCounter);
    findingCounter = quantRiskCounter.count;
    for (const item of quantRiskResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...quantRiskResult.logs);

    // 91. LangGraph & Multi-Agent State Machine Gate (LLM-ORCH-01 to 50, Rule IDs 16301-16350)
    const llmOrchCounter = { count: findingCounter };
    const llmOrchResult = evaluateMultiAgentOrchestrationRules(file, lines, cleanContent, llmOrchCounter);
    findingCounter = llmOrchCounter.count;
    for (const item of llmOrchResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...llmOrchResult.logs);

    // 92. AMD SEV-SNP & Intel SGX Hardware Enclave Gate (CONF-COMPUTE-01 to 50, Rule IDs 16401-16450)
    const confComputeCounter = { count: findingCounter };
    const confComputeResult = evaluateConfidentialComputingRules(file, lines, cleanContent, confComputeCounter);
    findingCounter = confComputeCounter.count;
    for (const item of confComputeResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...confComputeResult.logs);

    // 93. Federated Learning Differential Privacy Gate (FED-LEARN-01 to 50, Rule IDs 16501-16550)
    const fedLearnCounter = { count: findingCounter };
    const fedLearnResult = evaluateFederatedLearningRules(file, lines, cleanContent, fedLearnCounter);
    findingCounter = fedLearnCounter.count;
    for (const item of fedLearnResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...fedLearnResult.logs);

    // 94. Vector Index Quantization & SIMD Latency Gate (VEC-OPT-01 to 50, Rule IDs 16601-16650)
    const vecOptCounter = { count: findingCounter };
    const vecOptResult = evaluateVectorIndexOptimizationRules(file, lines, cleanContent, vecOptCounter);
    findingCounter = vecOptCounter.count;
    for (const item of vecOptResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...vecOptResult.logs);

    // Wave 21 Enterprise Release Gate Engines (Milestone 5,350 Rules):

    // 97. AI Agent Ethics & Deception Governance Gate (AI-ETHICS-01 to 50, Rule IDs 16901-16950)
    const aiEthicsCounter = { count: findingCounter };
    const aiEthicsResult = evaluateAiAgentEthicsGovernanceRules(file, lines, cleanContent, aiEthicsCounter);
    findingCounter = aiEthicsCounter.count;
    for (const item of aiEthicsResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...aiEthicsResult.logs);

    // Wave 22 Enterprise Release Gate Engines (Milestone 5,600 Rules):

    // 101. Edge AI Model Quantization & TensorRT Gate (EDGE-AI-OPT-01 to 50, Rule IDs 17301-17350)
    const edgeAiOptCounter = { count: findingCounter };
    const edgeAiOptResult = evaluateEdgeAiModelQuantizationRules(file, lines, cleanContent, edgeAiOptCounter);
    findingCounter = edgeAiOptCounter.count;
    for (const item of edgeAiOptResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...edgeAiOptResult.logs);

    // 104. Serverless Edge Vector Caching & Semantic ANN Gate (VEC-CACHE-01 to 50, Rule IDs 17601-17650)
    const vecCacheCounter = { count: findingCounter };
    const vecCacheResult = evaluateServerlessVectorCacheRules(file, lines, cleanContent, vecCacheCounter);
    findingCounter = vecCacheCounter.count;
    for (const item of vecCacheResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...vecCacheResult.logs);

    // Wave 23 Enterprise Release Gate Engines (Milestone 5,850 Rules):

    // Wave 24 Enterprise Release Gate Engines (Milestone 6,100 Rules — 6,000 Historic Milestone):

    // Wave 25 Enterprise Release Gate Engines (Milestone 6,350 Rules):

    // Wave 26 Enterprise Release Gate Engines (Milestone 6,600 Rules):

    // Wave 27 Enterprise Release Gate Engines (Milestone 6,850 Rules):

    // Wave 28 Enterprise Release Gate Engines (Milestone 7,100 Rules):

    // Wave 29 Enterprise Release Gate Engines (Milestone 7,350 Rules):

    // Wave 30 Enterprise Release Gate Engines (Milestone 7,600 Rules):

    // Enterprise Multi-Stack SAST & Release Gate Engines:

    // Wave 32: Software Composition Analysis (SCA), Dependency CVE & License Compliance Gate
    const scaCounter = { count: findingCounter };
    const scaResult = evaluateScaDependencyRules(file, lines, cleanContent, scaCounter);
    findingCounter = scaCounter.count;
    for (const item of scaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...scaResult.logs);
 
    // Wave 33: Strix AI Penetration Testing & OWASP 2025 Release Gate (SEC-API-01, SEC-SSRF-01, SEC-A10-01, SEC-ERR-02)
    const strixCounter = { count: findingCounter };
    const strixResult = evaluateStrixPentestRules(file, lines, cleanContent, strixCounter);
    findingCounter = strixCounter.count;
    for (const item of strixResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...strixResult.logs);

    // Wave 34: No-AI-Slop & Human Voice Engineering Gate (COPY-SLOP-01, COPY-SLOP-02, UI-CLICHE-04)
    const slopCounter = { count: findingCounter };
    const slopResult = evaluateNoAiSlopRules(file, lines, cleanContent, slopCounter);
    findingCounter = slopCounter.count;
    for (const item of slopResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...slopResult.logs);

    // Wave 35: FinOps, LLM Cost Governance & Denial-of-Wallet Gate (LLM-COST-01 to LLM-COST-06, Rule IDs 8071-8076)
    const llmCostCounter = { count: findingCounter };
    const llmCostResult = evaluateLlmCostGovernanceRules(file, lines, cleanContent, llmCostCounter);
    findingCounter = llmCostCounter.count;
    for (const item of llmCostResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...llmCostResult.logs);

    
    const rubyCounter = { count: findingCounter };
    const rubyResult = evaluateRubyRailsRules(file, lines, cleanContent, rubyCounter);
    findingCounter = rubyCounter.count;
    for (const item of rubyResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...rubyResult.logs);

    const phpCounter = { count: findingCounter };
    const phpResult = evaluatePhpLaravelRules(file, lines, cleanContent, phpCounter);
    findingCounter = phpCounter.count;
    for (const item of phpResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...phpResult.logs);

    const javaCounter = { count: findingCounter };
    const javaResult = evaluateJavaSpringRules(file, lines, cleanContent, javaCounter);
    findingCounter = javaCounter.count;
    for (const item of javaResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...javaResult.logs);

    const dotnetCounter = { count: findingCounter };
    const dotnetResult = evaluateDotnetCsharpRules(file, lines, cleanContent, dotnetCounter);
    findingCounter = dotnetCounter.count;
    for (const item of dotnetResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) addFinding(item);
    }
    logs.push(...dotnetResult.logs);

    const fileFindingsCount = findings.length - startFindingsCount;
    if (fileFindingsCount === 0) {
      logs.push(`[${new Date().toLocaleTimeString()}]   [PASS] ${file.path}: Passed security, compliance & UX quality gates cleanly (0 issues).`);
    } else {
      logs.push(`[${new Date().toLocaleTimeString()}]   [WARN] ${file.path}: Detected ${fileFindingsCount} open finding(s)!`);
    }

    // Immediately discard raw file buffer strings after AST extraction to maintain heap memory < 85MB
    try {
      (file as any).content = '';
    } catch {
      // Ignore if immutable
    }
    rawContent = '';
    cleanContent = '';
    lines = [];

    fileIndex++;
  }

  logs.push(`[${new Date().toLocaleTimeString()}] --------------------------------------------------`);
  logs.push(`[${new Date().toLocaleTimeString()}] [SUMMARY] Deep audit complete: Processed ${targetFiles.length} files. Total findings detected: ${findings.length}.`);

  const openFindings = findings.filter(f => f.status === 'OPEN');
  const criticalCount = openFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = openFindings.filter(f => f.severity === 'LOW').length;
  const uiClicheCount = openFindings.filter(f => f.type === 'VIBEPOLISH').length;

  const score = calculateReadinessScore(findings);
  let gateStatus = calculateGateStatus(findings);

  // Policy-as-Code strategy enforcement (F-43)
  if (rcConfig) {
    if (rcConfig.failStrategy === 'advisory') {
      gateStatus = 'PASSED';
      logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code: Advisory mode active — Release gate set to PASSED.`);
    } else if (rcConfig.failStrategy === 'strict') {
      const minThreshold = typeof rcConfig.minScoreThreshold === 'number' ? rcConfig.minScoreThreshold : 85;
      if (score < minThreshold) {
        gateStatus = 'FAILED';
        logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code: Strict mode active — Score ${score} is below required ${minThreshold} threshold. Release gate BLOCKED.`);
      }
    }
  }

  logs.push(`[${new Date().toLocaleTimeString()}] [COMPLETE] Scan complete: Readiness Score = ${score}/100 | Gate Status = ${gateStatus}`);

  const defaultSummary = gateStatus === 'PASSED'
    ? 'Production Audit PASSED. All security and design compliance checks cleared.'
    : gateStatus === 'WARNING'
    ? `Release WARNING. Detected ${highCount} High and ${mediumCount} Medium findings. Review recommended before production deployment.`
    : `Release BLOCKED. Detected ${criticalCount} Critical blocker(s) requiring immediate remediation.`;

  const summary = fileLimitWarning ? `${defaultSummary} (${fileLimitWarning})` : defaultSummary;

  return {
    score,
    gateStatus,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    uiClicheCount,
    findings,
    logs,
    summary,
    detectedDatabases: detectedStack.databases,
    detectedOrms: detectedStack.orms
  };
}

export function calculateReadinessScore(findings: Finding[]): number {
  const openFindings = findings.filter((f) => f.status === 'OPEN');
  // Separate core security/infra/legal blockers from cosmetic polish/UI items (F-38)
  const securityFindings = openFindings.filter(
    (f) => f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE'
  );
  const cosmeticFindings = openFindings.filter(
    (f) => f.type === 'VIBEPOLISH' || f.type === 'VIBECARE'
  );

  const criticalSecCount = securityFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highSecCount = securityFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumSecCount = securityFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowSecCount = securityFindings.filter((f) => f.severity === 'LOW').length;

  // Soft cosmetic deductions capped at 10 points total so clean repos never score below 90 on style alone
  const highCosmetic = cosmeticFindings.filter((f) => f.severity === 'HIGH').length;
  const medCosmetic = cosmeticFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCosmetic = cosmeticFindings.filter((f) => f.severity === 'LOW').length;
  const cosmeticDeduction = Math.min(10, highCosmetic * 2 + medCosmetic * 1 + lowCosmetic * 0.5);

  // Critical blockers directly deplete production readiness
  if (criticalSecCount > 0) {
    const criticalDeduction =
      criticalSecCount * 25 + Math.min(30, highSecCount * 5) + Math.min(15, mediumSecCount * 2) + cosmeticDeduction;
    return Math.max(0, Math.round(100 - criticalDeduction));
  }

  // Non-blocking repositories (GateStatus = PASSED or WARNING)
  // Bounded weighted deductions prevent score collapse on large multi-file codebases
  const highDeduction = Math.min(40, highSecCount * 7);
  const mediumDeduction = Math.min(25, mediumSecCount * 2);
  const lowDeduction = Math.min(10, lowSecCount * 0.5);

  const totalDeduction = highDeduction + mediumDeduction + lowDeduction + cosmeticDeduction;
  return Math.max(25, Math.min(100, Math.round(100 - totalDeduction)));
}

export function calculateGateStatus(findings: Finding[]): 'PASSED' | 'WARNING' | 'FAILED' {
  const openFindings = findings.filter((f) => f.status === 'OPEN');
  // Gate status is strictly a security, infrastructure & legal release gate (F-38).
  // Pure cosmetic, accessibility suggestions, and vibe polish rules do NOT fail or warn-block the gate.
  const securityFindings = openFindings.filter(
    (f) => f.type === 'SECURITY' || f.type === 'INFRA_DATABASE' || f.type === 'LEGAL_COMPLIANCE'
  );
  const criticalCount = securityFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = securityFindings.filter((f) => f.severity === 'HIGH').length;

  if (criticalCount > 0) return 'FAILED';
  if (highCount > 0) return 'WARNING';
  return 'PASSED';
}
