import type { Finding } from '@/data/schema';
import type { CodeFile } from './types';
import { evaluateAiClicheRules } from '../rules/ai-cliche-rules';
import { evaluateFrontendRules } from '../rules/frontend-rules';
import { evaluateComplianceRules } from '../rules/compliance-rules';
import { evaluateInfraRules } from '../rules/infra-rules';
import { evaluateInteractionRules } from '../rules/interaction-rules';
import { evaluateSecretRules } from '../rules/secrets-rules';
import { evaluateDatabaseRules } from '../rules/database-rules';
import { evaluateCloudNativeRules } from '../rules/cloud-native-rules';
import { evaluateWebVitalsRules } from '../rules/web-vitals-rules';
import { evaluateApiRules } from '../rules/api-rules';
import { evaluateSupplyChainRules } from '../rules/supply-chain-rules';
import { evaluateAiSafetyRules } from '../rules/ai-safety-rules';
import { evaluateZeroTrustRules } from '../rules/zero-trust-rules';
import { evaluatePrivacyComplianceRules } from '../rules/privacy-compliance-rules';
import { evaluateIacRules } from '../rules/iac-rules';
import { evaluateChaosResilienceRules } from '../rules/chaos-resilience-rules';
import { evaluateGraphqlSecurityRules } from '../rules/graphql-security-rules';
import { evaluateModernFullstackRules } from '../rules/modern-fullstack-rules';
import { evaluateWeb3SecurityRules } from '../rules/web3-security-rules';
import { evaluatePythonEnterpriseRules } from '../rules/python-enterprise-rules';
import { evaluatePolyglotBackendRules } from '../rules/polyglot-backend-rules';
import { evaluateMultiDatabaseRules } from '../rules/multi-database-rules';
import { evaluateK8sHardeningRules } from '../rules/k8s-hardening-rules';
import { evaluateGoMicroservicesRules } from '../rules/go-microservices-rules';
import { evaluateTenantIsolationRules } from '../rules/tenant-isolation-rules';
import { evaluateCloudSecurityRules } from '../rules/cloud-security-rules';
import { evaluateMobileSecurityRules } from '../rules/mobile-security-rules';
import { evaluateEventStreamingRules } from '../rules/event-streaming-rules';
import { evaluateCicdSupplyChainRules } from '../rules/cicd-supplychain-rules';
import { evaluateRustSystemsRules } from '../rules/rust-systems-rules';
import { evaluateFintechComplianceRules } from '../rules/fintech-compliance-rules';
import { evaluateHipaaComplianceRules } from '../rules/hipaa-compliance-rules';
import { evaluateOtelObservabilityRules } from '../rules/otel-observability-rules';
import { evaluateCppMemoryRules } from '../rules/cpp-memory-rules';
import { evaluateEcommInventoryRules } from '../rules/ecomm-inventory-rules';
import { evaluateGrpcProtobufRules } from '../rules/grpc-protobuf-rules';
import { evaluatePgvectorPostgresRules } from '../rules/pgvector-postgres-rules';
import { evaluateWafEdgeRules } from '../rules/waf-edge-rules';
import { evaluateWebsocketRealtimeRules } from '../rules/websocket-realtime-rules';
import { evaluateSoc2AuditRules } from '../rules/soc2-audit-rules';
import { evaluateCacheRedisRules } from '../rules/cache-redis-rules';
import { evaluateIso27001ComplianceRules } from '../rules/iso27001-compliance-rules';
import { evaluateOauthOidcRules } from '../rules/oauth-oidc-rules';
import { evaluateTerraformIacRules } from '../rules/terraform-iac-rules';
import { evaluateEdgeCdnRules } from '../rules/edge-cdn-rules';
import { evaluateServiceMeshRules } from '../rules/service-mesh-rules';
import { evaluateServerlessLambdaRules } from '../rules/serverless-lambda-rules';
import { evaluateApiGatewayRules } from '../rules/api-gateway-rules';
import { evaluateDataPipelineRules } from '../rules/data-pipeline-rules';
import { evaluateEuAiActRules } from '../rules/eu-ai-act-rules';
import { evaluateCronSchedulerRules } from '../rules/cron-scheduler-rules';
import { evaluateDnsSecurityRules } from '../rules/dns-security-rules';
import { evaluateNistSp80053Rules } from '../rules/nist-sp800-53-rules';
import { evaluateGraphDatabaseRules } from '../rules/graph-database-rules';
import { evaluateSiemAuditLoggingRules } from '../rules/siem-audit-logging-rules';
import { evaluateContainerSecurityRules } from '../rules/container-security-rules';
import { evaluateTlsCryptographyRules } from '../rules/tls-cryptography-rules';
import { evaluateDoraComplianceRules } from '../rules/dora-compliance-rules';
import { evaluateMessageBrokerRules } from '../rules/message-broker-rules';
import { evaluateSbomAttestationRules } from '../rules/sbom-attestation-rules';
import { evaluateWasmRuntimeRules } from '../rules/wasm-runtime-rules';
import { evaluateEnterpriseSsoRules } from '../rules/enterprise-sso-rules';
import { evaluatePciDssV4Rules } from '../rules/pci-dss-v4-rules';
import { evaluateSearchEngineRules } from '../rules/search-engine-rules';
import { evaluateZeroTrustNetworkRules } from '../rules/zero-trust-network-rules';
import { evaluateOpaPolicyRules } from '../rules/opa-policy-rules';
import { evaluateCryptoKmsRules } from '../rules/crypto-kms-rules';
import { evaluateSoxComplianceRules } from '../rules/sox-compliance-rules';
import { evaluateVectorDbRules } from '../rules/vector-db-rules';
import { evaluateThreatDetectionRules } from '../rules/threat-detection-rules';
import { evaluateGraphqlFederationRules } from '../rules/graphql-federation-rules';
import { evaluateOwaspAsvsRules } from '../rules/owasp-asvs-rules';
import { evaluateFedrampComplianceRules } from '../rules/fedramp-compliance-rules';
import { evaluateTimeSeriesDbRules } from '../rules/time-series-db-rules';
import { evaluateSlsaProvenanceRules } from '../rules/slsa-provenance-rules';
import { evaluateEbpfObservabilityRules } from '../rules/ebpf-observability-rules';
import { evaluateOwaspApiSecurityRules } from '../rules/owasp-api-security-rules';
import { evaluateHipaaSecurityRules } from '../rules/hipaa-security-rules';
import { evaluateMessageQueueOptRules } from '../rules/message-queue-opt-rules';
import { evaluateRaspAntiTamperRules } from '../rules/rasp-anti-tamper-rules';
import { evaluateGrpcWebSecurityRules } from '../rules/grpc-web-security-rules';
import { evaluateCspmCloudPostureRules } from '../rules/cspm-cloud-posture-rules';
import { evaluateGlbaComplianceRules } from '../rules/glba-compliance-rules';
import { evaluateGeoDistributedDbRules } from '../rules/geo-distributed-db-rules';
import { evaluateCyberDeceptionRules } from '../rules/cyber-deception-rules';
import { evaluateWasmEdgeRuntimeRules } from '../rules/wasm-edge-runtime-rules';
import { evaluateEuNis2ComplianceRules } from '../rules/eu-nis2-compliance-rules';
import { evaluateDatabaseShardingRules } from '../rules/database-sharding-rules';
import { evaluateThreatIntelligenceRules } from '../rules/threat-intelligence-rules';
import { evaluateLinuxKernelSecurityRules } from '../rules/linux-kernel-security-rules';
import { evaluateIso20022FintechRules } from '../rules/iso20022-fintech-rules';
import { evaluateTimeSeriesDbOptRules } from '../rules/time-series-db-opt-rules';
import { evaluateAiRedTeamSecurityRules } from '../rules/ai-red-team-security-rules';
import { evaluateServiceFabricResilienceRules } from '../rules/service-fabric-resilience-rules';
import { evaluateQuantitativeRiskRules } from '../rules/quantitative-risk-rules';
import { evaluateMultiAgentOrchestrationRules } from '../rules/multi-agent-orchestration-rules';
import { evaluateConfidentialComputingRules } from '../rules/confidential-computing-rules';
import { evaluateFederatedLearningRules } from '../rules/federated-learning-rules';
import { evaluateVectorIndexOptimizationRules } from '../rules/vector-index-optimization-rules';
import { evaluateAiAgentEthicsGovernanceRules } from '../rules/ai-agent-ethics-governance-rules';
import { evaluateEdgeAiModelQuantizationRules } from '../rules/edge-ai-model-quantization-rules';
import { evaluateServerlessVectorCacheRules } from '../rules/serverless-vector-cache-rules';
import { evaluateScaDependencyRules } from '../rules/sca-dependency-rules';
import { evaluateStrixPentestRules } from '../rules/strix-pentest-rules';
import { evaluateNoAiSlopRules } from '../rules/no-ai-slop-rules';
import { evaluateLlmCostGovernanceRules } from '../rules/llm-cost-governance-rules';
import { evaluateRubyRailsRules } from '../rules/ruby-rails-rules';
import { evaluatePhpLaravelRules } from '../rules/php-laravel-rules';
import { evaluateJavaSpringRules } from '../rules/java-spring-rules';
import { evaluateDotnetCsharpRules } from '../rules/dotnet-csharp-rules';
import { evaluateSaasCoreRules } from '../rules/saas-core-rules';

export type RuleEngine = (
  file: CodeFile,
  lines: string[],
  content: string,
  findingCounter: { count: number }
) => { findings: Finding[]; logs: string[] };

/**
 * Modular rule engines, run in order for every file after the built-in rules.
 * `scanRawContent` engines receive the file with comments intact (secrets hide in comments too).
 */
export const RULE_ENGINES: ReadonlyArray<{ evaluate: RuleEngine; scanRawContent?: boolean }> = [
  // AI Web Design Cliché Detection (25 rules from yapay_zeka_web_tasarim_kliseleri.pdf)
  { evaluate: evaluateAiClicheRules },
  // Option B: Frontend Performance, WCAG 2.2 AA & SEO Rules (UI-A11Y-01, UI-PERF-01, UI-SEO-01)
  { evaluate: evaluateFrontendRules },
  // Global Regulatory, Privacy & Legal Pre-Flight Gate (Rules 2001-2006)
  { evaluate: evaluateComplianceRules },
  // Infrastructure, Cloud & Database Security Engine (Rules 3001-3006)
  { evaluate: evaluateInfraRules },
  // Wave 1 Enterprise Release Gate Engines:
  // 1. Frontend Interaction & Modal Traps (UI-INTERACT-01 to 50, Rule IDs 1201-1250)
  { evaluate: evaluateInteractionRules },
  // 2. Enterprise Secret Signatures (SEC-SECRET-01 to 100, Rule IDs 5001-5100)
  // F-16 Remediation: Scan unstripped content including comments to eliminate blind spots
  { evaluate: evaluateSecretRules, scanRawContent: true },
  // 3. Database & ORM Performance Engine (DB-PERF-01 to 50, Rule IDs 6001-6050)
  { evaluate: evaluateDatabaseRules },
  // Wave 2 Enterprise Release Gate Engines:
  // 4. Cloud Native, Serverless & Edge (CLOUD-01 to 50, Rule IDs 7001-7050)
  { evaluate: evaluateCloudNativeRules },
  // 5. Core Web Vitals & Advanced Performance (WEB-PERF-01 to 50, Rule IDs 7101-7150)
  { evaluate: evaluateWebVitalsRules },
  // 6. API Architecture & Microservices Reliability (API-01 to 50, Rule IDs 7201-7250)
  { evaluate: evaluateApiRules },
  // 7. Supply Chain, SBOM & Dependency Security (SUPPLY-01 to 50, Rule IDs 7301-7350)
  { evaluate: evaluateSupplyChainRules },
  // Wave 3 Enterprise Release Gate Engines (Milestone 1,000 Rules):
  // 8. AI Safety & LLM Guardrails (LLM-SEC-01 to 60, Rule IDs 8001-8060)
  { evaluate: evaluateAiSafetyRules },
  // 9. Zero Trust & Authentication Resilience (ZERO-AUTH-01 to 55, Rule IDs 8101-8155)
  { evaluate: evaluateZeroTrustRules },
  // 10. Data Privacy & GDPR Compliance (PRIVACY-01 to 50, Rule IDs 8201-8250)
  { evaluate: evaluatePrivacyComplianceRules },
  // 11. Infrastructure as Code & Container Hardening (IAC-01 to 50, Rule IDs 8301-8350)
  { evaluate: evaluateIacRules },
  // 12. Enterprise Reliability & Chaos Engineering (CHAOS-01 to 48, Rule IDs 8401-8448)
  { evaluate: evaluateChaosResilienceRules },
  // Wave 4 Enterprise Release Gate Engines (Milestone 1,100 Rules):
  // 13. GraphQL & Modern API Security (GQL-01 to 50, Rule IDs 8501-8550)
  { evaluate: evaluateGraphqlSecurityRules },
  // 14. Modern Fullstack Next.js 15 & React 19 (NEXT15-01 to 50, Rule IDs 8601-8650)
  { evaluate: evaluateModernFullstackRules },
  // Wave 5 Enterprise Release Gate Engines (Milestone 1,350 Rules):
  // 15. Web3 & Smart Contract Security (WEB3-01 to 50, Rule IDs 8701-8750)
  { evaluate: evaluateWeb3SecurityRules },
  // 16. Python & FastAPI / Django Enterprise Gate (PY-SEC-01 to 50, Rule IDs 8801-8850)
  { evaluate: evaluatePythonEnterpriseRules },
  // 16b. Polyglot Backend Gate (PHP, Java, C#/.NET, Ruby - Rule IDs 18001-18050)
  { evaluate: evaluatePolyglotBackendRules },
  // 16c. Universal Multi-Database & ORM Gate (MySQL, MongoDB, Redis, SQLite, Prisma - Rule IDs 18101-18150)
  { evaluate: evaluateMultiDatabaseRules },
  // 17. Kubernetes & Cloud Orchestration Hardening (K8S-01 to 50, Rule IDs 8901-8950)
  { evaluate: evaluateK8sHardeningRules },
  // 18. Go & Cloud Native Microservices Resilience (GO-01 to 50, Rule IDs 9001-9050)
  { evaluate: evaluateGoMicroservicesRules },
  // 19. Multi-Tenant SaaS & Data Isolation Gate (TENANT-01 to 50, Rule IDs 9101-9150)
  { evaluate: evaluateTenantIsolationRules },
  // Wave 6 Enterprise Release Gate Engines (Milestone 1,600 Rules):
  // 20. Multi-Cloud AWS/GCP/Azure Security (CLOUD-SEC-01 to 50, Rule IDs 9201-9250)
  { evaluate: evaluateCloudSecurityRules },
  // 21. Mobile App Security & Integrity Gate (MOB-SEC-01 to 50, Rule IDs 9301-9350)
  { evaluate: evaluateMobileSecurityRules },
  // 22. Kafka & Event Streaming Hardening (EVENT-01 to 50, Rule IDs 9401-9450)
  { evaluate: evaluateEventStreamingRules },
  // 23. CI/CD Pipeline & Supply Chain Hardening (CICD-SEC-01 to 50, Rule IDs 9501-9550)
  { evaluate: evaluateCicdSupplyChainRules },
  // 24. Rust & Memory-Safe Systems Gate (RUST-01 to 50, Rule IDs 9601-9650)
  { evaluate: evaluateRustSystemsRules },
  // Wave 7 Enterprise Release Gate Engines (Milestone 1,850 Rules):
  // 25. Fintech & PCI-DSS Compliance Gate (FINTECH-01 to 50, Rule IDs 9701-9750)
  { evaluate: evaluateFintechComplianceRules },
  // 26. Healthcare & HIPAA Data Privacy Gate (HIPAA-01 to 50, Rule IDs 9801-9850)
  { evaluate: evaluateHipaaComplianceRules },
  // 27. Cloud Native Observability & Tracing (OTEL-01 to 50, Rule IDs 9901-9950)
  { evaluate: evaluateOtelObservabilityRules },
  // 28. C/C++ Systems Memory Safety Gate (CPP-SEC-01 to 50, Rule IDs 10001-10050)
  { evaluate: evaluateCppMemoryRules },
  // 29. eCommerce & Inventory Integrity Gate (ECOMM-01 to 50, Rule IDs 10101-10150)
  { evaluate: evaluateEcommInventoryRules },
  // Wave 8 Enterprise Release Gate Engines (Milestone 2,100 Rules):
  // 30. High-Performance gRPC & Protobuf RPC Architecture (GRPC-01 to 50, Rule IDs 10201-10250)
  { evaluate: evaluateGrpcProtobufRules },
  // 31. PostgreSQL Internals, pgvector & Advanced Optimization (PG-01 to 50, Rule IDs 10301-10350)
  { evaluate: evaluatePgvectorPostgresRules },
  // 32. Cloud WAF, DDoS Protection & Edge Security (WAF-01 to 50, Rule IDs 10401-10450)
  { evaluate: evaluateWafEdgeRules },
  // 33. Real-Time WebSocket & Event Stream Gate (WS-01 to 50, Rule IDs 10501-10550)
  { evaluate: evaluateWebsocketRealtimeRules },
  // 34. AICPA SOC 2 Type II Trust Services Criteria (SOC2-01 to 50, Rule IDs 10601-10650)
  { evaluate: evaluateSoc2AuditRules },
  // Wave 9 Enterprise Release Gate Engines (Milestone 2,350 Rules):
  // 35. Redis & In-Memory Distributed Cache Reliability (CACHE-01 to 50, Rule IDs 10701-10750)
  { evaluate: evaluateCacheRedisRules },
  // 36. ISO/IEC 27001:2022 Information Security Management Controls (ISO-01 to 50, Rule IDs 10801-10850)
  { evaluate: evaluateIso27001ComplianceRules },
  // 37. OAuth 2.1 & OpenID Connect (OIDC) Modern Identity (OAUTH-01 to 50, Rule IDs 10901-10950)
  { evaluate: evaluateOauthOidcRules },
  // 38. Terraform & Cloud Infrastructure-as-Code Policy (TF-01 to 50, Rule IDs 11001-11050)
  { evaluate: evaluateTerraformIacRules },
  // 39. Edge CDN, HTTP/3 & Asset Delivery Optimization (CDN-01 to 50, Rule IDs 11101-11150)
  { evaluate: evaluateEdgeCdnRules },
  // Wave 10 Enterprise Release Gate Engines (Milestone 2,600 Rules):
  // 40. Service Mesh, Istio & Envoy Traffic Resilience (MESH-01 to 50, Rule IDs 11201-11250)
  { evaluate: evaluateServiceMeshRules },
  // 41. Serverless Functions & AWS Lambda Reliability (SLS-01 to 50, Rule IDs 11301-11350)
  { evaluate: evaluateServerlessLambdaRules },
  // 42. API Gateway, Rate Limiting & Abuse Defense (GW-01 to 50, Rule IDs 11401-11450)
  { evaluate: evaluateApiGatewayRules },
  // 43. Data Engineering, ETL Pipeline & Data Lake Governance (DATA-01 to 50, Rule IDs 11501-11550)
  { evaluate: evaluateDataPipelineRules },
  // 44. EU AI Act & Trustworthy Artificial Intelligence Governance (AIACT-01 to 50, Rule IDs 11601-11650)
  { evaluate: evaluateEuAiActRules },
  // Wave 11 Enterprise Release Gate Engines (Milestone 2,850 Rules):
  // 45. Distributed Job Scheduling & Cron Reliability (CRON-01 to 50, Rule IDs 11701-11750)
  { evaluate: evaluateCronSchedulerRules },
  // 46. DNSSEC, BGP & Anycast Routing Defense (DNS-01 to 50, Rule IDs 11801-11850)
  { evaluate: evaluateDnsSecurityRules },
  // 47. NIST SP 800-53 Rev. 5 & FedRAMP Cloud Controls (NIST-01 to 50, Rule IDs 11901-11950)
  { evaluate: evaluateNistSp80053Rules },
  // 48. Graph Database & Cypher Traversal Governance (GRPH-01 to 50, Rule IDs 12001-12050)
  { evaluate: evaluateGraphDatabaseRules },
  // 49. Enterprise SIEM & Syslog Audit Integrity (AUDIT-01 to 50, Rule IDs 12101-12150)
  { evaluate: evaluateSiemAuditLoggingRules },
  // Wave 12 Enterprise Release Gate Engines (Milestone 3,100 Rules):
  // 50. OCI Container Security & Pod Security Standards (CONTAINER-01 to 50, Rule IDs 12201-12250)
  { evaluate: evaluateContainerSecurityRules },
  // 51. TLS 1.3 & Post-Quantum Cryptography (TLS-01 to 50, Rule IDs 12301-12350)
  { evaluate: evaluateTlsCryptographyRules },
  // 52. EU DORA Digital Operational Resilience (DORA-01 to 50, Rule IDs 12401-12450)
  { evaluate: evaluateDoraComplianceRules },
  // 53. Enterprise Message Broker & AMQP 0-9-1 Reliability (MQ-01 to 50, Rule IDs 12501-12550)
  { evaluate: evaluateMessageBrokerRules },
  // 54. CycloneDX / SPDX SBOM Deep Supply Chain Attestation (SBOM-01 to 50, Rule IDs 12601-12650)
  { evaluate: evaluateSbomAttestationRules },
  // Wave 13 Enterprise Release Gate Engines (Milestone 3,350 Rules):
  // 55. WebAssembly & WASI Sandbox Resilience (WASM-01 to 50, Rule IDs 12701-12750)
  { evaluate: evaluateWasmRuntimeRules },
  // 56. Enterprise SAML 2.0 & SCIM Identity Governance (SSO-01 to 50, Rule IDs 12801-12850)
  { evaluate: evaluateEnterpriseSsoRules },
  // 57. PCI-DSS v4.0 Modern Payment Security Standards (PCI4-01 to 50, Rule IDs 12901-12950)
  { evaluate: evaluatePciDssV4Rules },
  // 58. Elasticsearch & OpenSearch Index Optimization (SEARCH-01 to 50, Rule IDs 13001-13050)
  { evaluate: evaluateSearchEngineRules },
  // 59. Software-Defined Perimeter & Zero Trust Mesh (SDP-01 to 50, Rule IDs 13101-13150)
  { evaluate: evaluateZeroTrustNetworkRules },
  // Wave 14 Enterprise Release Gate Engines (Milestone 3,600 Rules):
  // 60. Open Policy Agent & Rego Admission Guardrails (OPA-01 to 50, Rule IDs 13201-13250)
  { evaluate: evaluateOpaPolicyRules },
  // 61. Enterprise KMS, HSM & Cryptographic Hygiene (CRYPTO-01 to 50, Rule IDs 13301-13350)
  { evaluate: evaluateCryptoKmsRules },
  // 62. SOX Section 404 ITGC Financial Control Compliance (SOX-01 to 50, Rule IDs 13401-13450)
  { evaluate: evaluateSoxComplianceRules },
  // 63. Milvus & Qdrant Vector Search Performance & Reliability (VECTOR-01 to 50, Rule IDs 13501-13550)
  { evaluate: evaluateVectorDbRules },
  // 64. MITRE ATT&CK Threat Hunting & Canary Deception (THREAT-01 to 50, Rule IDs 13601-13650)
  { evaluate: evaluateThreatDetectionRules },
  // Wave 15 Enterprise Release Gate Engines (Milestone 3,850 Rules):
  // 65. Apollo Federation & GraphQL Subgraph Gate (FED-01 to 50, Rule IDs 13701-13750)
  { evaluate: evaluateGraphqlFederationRules },
  // 66. OWASP ASVS Level 3 Application Security Verification (ASVS-01 to 50, Rule IDs 13801-13850)
  { evaluate: evaluateOwaspAsvsRules },
  // 67. FedRAMP High Baseline Cloud Compliance Gate (FEDRAMP-01 to 50, Rule IDs 13901-13950)
  { evaluate: evaluateFedrampComplianceRules },
  // 68. Time-Series Databases & Columnar Query Optimization (TSDB-01 to 50, Rule IDs 14001-14050)
  { evaluate: evaluateTimeSeriesDbRules },
  // 69. SLSA Level 4 & In-Toto Supply Chain Provenance (SLSA-01 to 50, Rule IDs 14101-14150)
  { evaluate: evaluateSlsaProvenanceRules },
  // Wave 16 Enterprise Release Gate Engines (Milestone 4,100 Rules):
  // 70. eBPF Kernel Observability & Cilium Security (EBPF-01 to 50, Rule IDs 14201-14250)
  { evaluate: evaluateEbpfObservabilityRules },
  // 71. OWASP API Security Top 10 2023 Protocol Defense (APIDEF-01 to 50, Rule IDs 14301-14350)
  { evaluate: evaluateOwaspApiSecurityRules },
  // 72. HIPAA Security Rule Safeguards & Audit Trails (HIPAASEC-01 to 50, Rule IDs 14401-14450)
  { evaluate: evaluateHipaaSecurityRules },
  // 73. RabbitMQ & NATS JetStream Message Ingestion Governance (MQOPT-01 to 50, Rule IDs 14501-14550)
  { evaluate: evaluateMessageQueueOptRules },
  // 74. Runtime Application Self-Protection & Binary Anti-Tamper (RASP-01 to 50, Rule IDs 14601-14650)
  { evaluate: evaluateRaspAntiTamperRules },
  // Wave 17 Enterprise Release Gate Engines (Milestone 4,350 Rules):
  // 75. gRPC-Web, HTTP/2 & Protobuf Security Gate (GRPCSEC-01 to 50, Rule IDs 14701-14750)
  { evaluate: evaluateGrpcWebSecurityRules },
  // 76. CSPM Cloud Posture & IAM Privilege Drift (CSPM-01 to 50, Rule IDs 14801-14850)
  { evaluate: evaluateCspmCloudPostureRules },
  // 77. GLBA Safeguards Rule Financial Compliance (GLBA-01 to 50, Rule IDs 14901-14950)
  { evaluate: evaluateGlbaComplianceRules },
  // 78. Geo-Distributed Database Resilience Gate (GEODIST-01 to 50, Rule IDs 15001-15050)
  { evaluate: evaluateGeoDistributedDbRules },
  // 79. Cyber Deception, Honeytokens & Threat Trapping (DECEPTION-01 to 50, Rule IDs 15101-15150)
  { evaluate: evaluateCyberDeceptionRules },
  // Wave 18 Enterprise Release Gate Engines (Milestone 4,600 Rules):
  // 80. WebAssembly Edge Runtime Sandboxing Gate (WASM-EDGE-01 to 50, Rule IDs 15201-15250)
  { evaluate: evaluateWasmEdgeRuntimeRules },
  // 82. EU NIS2 Critical Infrastructure Compliance Gate (NIS2-01 to 50, Rule IDs 15401-15450)
  { evaluate: evaluateEuNis2ComplianceRules },
  // 83. Horizontal Database Sharding & VSchema Gate (SHARD-01 to 50, Rule IDs 15501-15550)
  { evaluate: evaluateDatabaseShardingRules },
  // 84. Cyber Threat Intelligence (CTI) & STIX/TAXII Gate (CTI-01 to 50, Rule IDs 15601-15650)
  { evaluate: evaluateThreatIntelligenceRules },
  // Wave 19 Enterprise Release Gate Engines (Milestone 4,850 Rules):
  // 85. Linux Kernel Hardening & Capabilities Gate (KERN-SEC-01 to 50, Rule IDs 15701-15750)
  { evaluate: evaluateLinuxKernelSecurityRules },
  // 86. ISO 20022 Financial Messaging & SLA Gate (ISO20022-01 to 50, Rule IDs 15801-15850)
  { evaluate: evaluateIso20022FintechRules },
  // 87. Time-Series DB Chunk & Partition Optimization Gate (TSDB-OPT-01 to 50, Rule IDs 15901-15950)
  { evaluate: evaluateTimeSeriesDbOptRules },
  // 88. AI Red Teaming & Jailbreak Defense Gate (AI-RED-01 to 50, Rule IDs 16001-16050)
  { evaluate: evaluateAiRedTeamSecurityRules },
  // 89. Edge Service Fabric & Anycast Resilience Gate (FABRIC-01 to 50, Rule IDs 16101-16150)
  { evaluate: evaluateServiceFabricResilienceRules },
  // Wave 20 Enterprise Release Gate Engines (Milestone 5,100 Rules — 5,000 Barrier Crossed):
  // 90. Basel III & FRTB Quantitative Risk / VaR Gate (QUANT-RISK-01 to 50, Rule IDs 16201-16250)
  { evaluate: evaluateQuantitativeRiskRules },
  // 91. LangGraph & Multi-Agent State Machine Gate (LLM-ORCH-01 to 50, Rule IDs 16301-16350)
  { evaluate: evaluateMultiAgentOrchestrationRules },
  // 92. AMD SEV-SNP & Intel SGX Hardware Enclave Gate (CONF-COMPUTE-01 to 50, Rule IDs 16401-16450)
  { evaluate: evaluateConfidentialComputingRules },
  // 93. Federated Learning Differential Privacy Gate (FED-LEARN-01 to 50, Rule IDs 16501-16550)
  { evaluate: evaluateFederatedLearningRules },
  // 94. Vector Index Quantization & SIMD Latency Gate (VEC-OPT-01 to 50, Rule IDs 16601-16650)
  { evaluate: evaluateVectorIndexOptimizationRules },
  // Wave 21 Enterprise Release Gate Engines (Milestone 5,350 Rules):
  // 97. AI Agent Ethics & Deception Governance Gate (AI-ETHICS-01 to 50, Rule IDs 16901-16950)
  { evaluate: evaluateAiAgentEthicsGovernanceRules },
  // Wave 22 Enterprise Release Gate Engines (Milestone 5,600 Rules):
  // 101. Edge AI Model Quantization & TensorRT Gate (EDGE-AI-OPT-01 to 50, Rule IDs 17301-17350)
  { evaluate: evaluateEdgeAiModelQuantizationRules },
  // 104. Serverless Edge Vector Caching & Semantic ANN Gate (VEC-CACHE-01 to 50, Rule IDs 17601-17650)
  { evaluate: evaluateServerlessVectorCacheRules },
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
  { evaluate: evaluateScaDependencyRules },
  // Wave 33: Strix AI Penetration Testing & OWASP 2025 Release Gate (SEC-API-01, SEC-SSRF-01, SEC-A10-01, SEC-ERR-02)
  { evaluate: evaluateStrixPentestRules },
  // Wave 34: No-AI-Slop & Human Voice Engineering Gate (COPY-SLOP-01, COPY-SLOP-02, UI-CLICHE-04)
  { evaluate: evaluateNoAiSlopRules },
  // Wave 35: FinOps, LLM Cost Governance & Denial-of-Wallet Gate (LLM-COST-01 to LLM-COST-06, Rule IDs 8071-8076)
  { evaluate: evaluateLlmCostGovernanceRules },
  { evaluate: evaluateRubyRailsRules },
  { evaluate: evaluatePhpLaravelRules },
  { evaluate: evaluateJavaSpringRules },
  { evaluate: evaluateDotnetCsharpRules },
  // SaaS core risks: tenant RLS, billing, auth trust, cron, prompt injection (SAAS-01 to 08, Rule IDs 23001-23008)
  { evaluate: evaluateSaasCoreRules },
];
