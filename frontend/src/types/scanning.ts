/**
 * 🛡️ SecureScan Framework - Scanning Types
 * 
 * TypeScript type definitions for security scanning operations
 * 
 * Features:
 * - Multi-scanner support (SAST, DAST, SCA, IaC, Secrets)
 * - SARIF-compliant vulnerability reporting
 * - Real-time scan progress tracking
 * - Scan configuration and scheduling
 * - Scanner-specific settings
 * 
 * Author: SecureScan Team
 */

// =============================================================================
// 📊 PROJECT TYPES
// =============================================================================

export interface Project {
  id: string;
  name: string;
  description: string;
  ownerId: string;
  repositoryUrl?: string;
  repositoryBranch?: string;
  language?: string;
  framework?: string;
  isActive: boolean;
  settings: ProjectSettings;
  stats: ProjectStats;
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string;
  tags: string[];
  collaborators: ProjectCollaborator[];
}

export interface ProjectSettings {
  scanners: ScannerConfig[];
  schedule?: ScanSchedule;
  notifications: ProjectNotificationSettings;
  integrations: ProjectIntegrations;
  security: ProjectSecuritySettings;
}

export interface ProjectStats {
  totalScans: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  infoVulnerabilities: number;
  resolvedVulnerabilities: number;
  lastScanDuration?: number;
  avgScanDuration: number;
  successRate: number;
}

export interface ProjectCollaborator {
  userId: string;
  username: string;
  email: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  addedAt: string;
  addedBy: string;
}

export interface ProjectNotificationSettings {
  scanComplete: boolean;
  vulnerabilityFound: boolean;
  highSeverityOnly: boolean;
  channels: string[];
}

export interface ProjectIntegrations {
  slack?: { channelId: string; webhookUrl: string };
  jira?: { projectKey: string; issueType: string };
  github?: { createIssues: boolean; labelPrefix: string };
}

export interface ProjectSecuritySettings {
  requireApproval: boolean;
  allowedScanners: ScannerType[];
  maxConcurrentScans: number;
  retentionPeriod: number; // days
}

// =============================================================================
// 🔍 SCANNER TYPES
// =============================================================================

export type ScannerType = 'sast' | 'dast' | 'sca' | 'iac' | 'secrets';

export interface ScannerConfig {
  type: ScannerType;
  enabled: boolean;
  tool: string;
  version?: string;
  config: Record<string, any>;
  priority: number;
}

export interface Scanner {
  id: string;
  type: ScannerType;
  name: string;
  description: string;
  version: string;
  isAvailable: boolean;
  isDefault: boolean;
  supportedLanguages: string[];
  supportedFrameworks: string[];
  dockerImage: string;
  configSchema: Record<string, any>;
  documentation: string;
  vendor: string;
  license: string;
}

// Specific scanner configurations
export interface SemgrepConfig {
  rules: string[];
  excludePaths: string[];
  includePaths: string[];
  severity: string[];
  confidence: string[];
  timeout: number;
}

export interface TrivyConfig {
  scanType: 'filesystem' | 'image' | 'repository';
  format: 'json' | 'sarif' | 'table';
  severity: string[];
  ignoreUnfixed: boolean;
  timeout: number;
}

export interface ZAPConfig {
  targetUrl: string;
  scanType: 'baseline' | 'fullscan' | 'apiscan';
  authentication?: ZAPAuthentication;
  excludeUrls: string[];
  includeUrls: string[];
  timeout: number;
}

export interface ZAPAuthentication {
  type: 'form' | 'script' | 'http' | 'manual';
  loginUrl?: string;
  username?: string;
  password?: string;
  usernameField?: string;
  passwordField?: string;
  extraPostData?: string;
}

export interface GitleaksConfig {
  rules: string[];
  allowlist: string[];
  paths: string[];
  verbose: boolean;
  redact: boolean;
}

export interface CheckovConfig {
  framework: string[];
  check: string[];
  skipCheck: string[];
  severity: string[];
  quiet: boolean;
}

// =============================================================================
// 🚀 SCAN TYPES
// =============================================================================

export interface Scan {
  id: string;
  projectId: string;
  name: string;
  description?: string;
  type: ScanType;
  status: ScanStatus;
  config: ScanConfig;
  progress: ScanProgress;
  results?: ScanResults;
  metrics: ScanMetrics;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  duration?: number;
  triggeredBy: string;
  triggerType: ScanTriggerType;
  parentScanId?: string;
  tags: string[];
}

export type ScanType = 'manual' | 'scheduled' | 'webhook' | 'api' | 'continuous';

export type ScanStatus = 
  | 'pending'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timeout';

export type ScanTriggerType = 'manual' | 'schedule' | 'webhook' | 'api' | 'git_push' | 'pull_request';

export interface ScanConfig {
  scanners: ScannerExecution[];
  target: ScanTarget;
  options: ScanOptions;
}

export interface ScannerExecution {
  type: ScannerType;
  tool: string;
  config: Record<string, any>;
  timeout: number;
  retry: number;
  enabled: boolean;
}

export interface ScanTarget {
  type: 'repository' | 'filesystem' | 'url' | 'image';
  source: string;
  branch?: string;
  commit?: string;
  paths?: string[];
  excludePaths?: string[];
}

export interface ScanOptions {
  parallel: boolean;
  continueOnError: boolean;
  reportFormat: 'sarif' | 'json' | 'xml' | 'html';
  includeLowSeverity: boolean;
  deduplication: boolean;
  baseline?: string;
}

export interface ScanProgress {
  overall: number; // 0-100
  scanners: ScannerProgress[];
  currentStage: string;
  estimatedCompletion?: string;
  messagesLog: string[];
}

export interface ScannerProgress {
  type: ScannerType;
  tool: string;
  status: ScanStatus;
  progress: number;
  startedAt?: string;
  completedAt?: string;
  duration?: number;
  vulnerabilities: number;
  errors: string[];
}

// =============================================================================
// 📊 SCAN RESULTS TYPES
// =============================================================================

export interface ScanResults {
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
  sarif?: SARIFReport;
  rawResults: Record<string, any>;
  metrics: ResultMetrics;
}

export interface ScanSummary {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  newVulnerabilities: number;
  fixedVulnerabilities: number;
  scannerResults: ScannerSummary[];
}

export interface ScannerSummary {
  type: ScannerType;
  tool: string;
  vulnerabilities: number;
  status: ScanStatus;
  duration: number;
  errors: string[];
}

export interface ResultMetrics {
  codeLines: number;
  filesScanned: number;
  testsRun: number;
  coverage?: number;
  duplicatesRemoved: number;
  falsePositives: number;
}

// =============================================================================
// 🚨 VULNERABILITY TYPES
// =============================================================================

export interface Vulnerability {
  id: string;
  scanId: string;
  projectId: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  confidence: VulnerabilityConfidence;
  status: VulnerabilityStatus;
  category: VulnerabilityCategory;
  cwe?: string;
  owasp?: string;
  cvss?: CVSSScore;
  location: VulnerabilityLocation;
  scanner: VulnerabilityScanner;
  evidence: VulnerabilityEvidence;
  remediation?: VulnerabilityRemediation;
  assignee?: string;
  dueDate?: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  verifiedAt?: string;
  falsePositive: boolean;
  riskAccepted: boolean;
  notes: VulnerabilityNote[];
}

export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type VulnerabilityConfidence = 'high' | 'medium' | 'low';

export type VulnerabilityStatus = 
  | 'open'
  | 'in_progress'
  | 'resolved'
  | 'false_positive'
  | 'risk_accepted'
  | 'duplicate';

export type VulnerabilityCategory =
  | 'injection'
  | 'broken_auth'
  | 'sensitive_data'
  | 'xxe'
  | 'broken_access'
  | 'security_misconfig'
  | 'xss'
  | 'insecure_deserialization'
  | 'known_vulnerabilities'
  | 'insufficient_logging'
  | 'secrets'
  | 'crypto'
  | 'other';

export interface CVSSScore {
  version: '3.1' | '3.0' | '2.0';
  baseScore: number;
  temporalScore?: number;
  environmentalScore?: number;
  vector: string;
  metrics: Record<string, string>;
}

export interface VulnerabilityLocation {
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  function?: string;
  class?: string;
  method?: string;
  url?: string;
  parameter?: string;
}

export interface VulnerabilityScanner {
  type: ScannerType;
  tool: string;
  version: string;
  ruleId: string;
  ruleName: string;
  ruleUrl?: string;
}

export interface VulnerabilityEvidence {
  snippet?: string;
  request?: string;
  response?: string;
  headers?: Record<string, string>;
  payload?: string;
  stackTrace?: string;
}

export interface VulnerabilityRemediation {
  description: string;
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
  steps: string[];
  links: string[];
  code?: string;
  diff?: string;
}

export interface VulnerabilityNote {
  id: string;
  userId: string;
  username: string;
  content: string;
  type: 'comment' | 'status_change' | 'assignment' | 'resolution';
  createdAt: string;
  updatedAt?: string;
}

// =============================================================================
// 📅 SCHEDULING TYPES
// =============================================================================

export interface ScanSchedule {
  id: string;
  projectId: string;
  name: string;
  description?: string;
  cron: string;
  timezone: string;
  isActive: boolean;
  config: ScanConfig;
  lastRun?: string;
  nextRun?: string;
  runCount: number;
  failureCount: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

// =============================================================================
// 📊 METRICS TYPES
// =============================================================================

export interface ScanMetrics {
  executionTime: number;
  queueTime: number;
  resourceUsage: ResourceUsage;
  performance: PerformanceMetrics;
}

export interface ResourceUsage {
  cpu: number; // percentage
  memory: number; // MB
  disk: number; // MB
  network: number; // MB
}

export interface PerformanceMetrics {
  linesPerSecond: number;
  filesPerSecond: number;
  vulnerabilitiesPerSecond: number;
  throughput: number;
}

// =============================================================================
// 📄 SARIF TYPES
// =============================================================================

export interface SARIFReport {
  version: string;
  $schema: string;
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: SARIFTool;
  results: SARIFResult[];
  artifacts?: SARIFArtifact[];
  invocations?: SARIFInvocation[];
}

export interface SARIFTool {
  driver: SARIFToolDriver;
}

export interface SARIFToolDriver {
  name: string;
  version: string;
  informationUri?: string;
  rules?: SARIFRule[];
}

export interface SARIFRule {
  id: string;
  name: string;
  shortDescription: SARIFMessage;
  fullDescription?: SARIFMessage;
  help?: SARIFMessage;
  properties?: Record<string, any>;
}

export interface SARIFResult {
  ruleId: string;
  ruleIndex?: number;
  message: SARIFMessage;
  level?: 'error' | 'warning' | 'note' | 'info';
  locations?: SARIFLocation[];
  fixes?: SARIFFix[];
  suppressions?: SARIFSuppression[];
}

export interface SARIFMessage {
  text: string;
  markdown?: string;
}

export interface SARIFLocation {
  physicalLocation?: SARIFPhysicalLocation;
  logicalLocations?: SARIFLogicalLocation[];
}

export interface SARIFPhysicalLocation {
  artifactLocation: SARIFArtifactLocation;
  region?: SARIFRegion;
  contextRegion?: SARIFRegion;
}

export interface SARIFArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SARIFRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: SARIFArtifactContent;
}

export interface SARIFArtifactContent {
  text: string;
}

export interface SARIFLogicalLocation {
  name?: string;
  fullyQualifiedName?: string;
  kind?: string;
}

export interface SARIFArtifact {
  location: SARIFArtifactLocation;
  length?: number;
  roles?: string[];
  mimeType?: string;
  contents?: SARIFArtifactContent;
}

export interface SARIFInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  exitCode?: number;
  stderr?: SARIFArtifactContent;
  stdout?: SARIFArtifactContent;
}

export interface SARIFFix {
  description: SARIFMessage;
  artifactChanges: SARIFArtifactChange[];
}

export interface SARIFArtifactChange {
  artifactLocation: SARIFArtifactLocation;
  replacements: SARIFReplacement[];
}

export interface SARIFReplacement {
  deletedRegion: SARIFRegion;
  insertedContent?: SARIFArtifactContent;
}

export interface SARIFSuppression {
  kind: string;
  justification?: string;
  location?: SARIFLocation;
}