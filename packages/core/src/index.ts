import * as yaml from 'js-yaml';
import type {
  AnalysisResult,
  AnalysisOptions,
  Finding,
  Severity,
  FindingSummary,
} from './types.js';
import { IstioSecurityAnalyzer } from './analyzers/istio.js';
import { ConsulSecurityAnalyzer } from './analyzers/consul.js';
import { LinkerdSecurityAnalyzer } from './analyzers/linkerd.js';
import { detectMeshType, normalizeConfig } from './utils/meshDetector.js';

// Re-export types
export type {
  Finding,
  FindingSummary,
  AnalysisResult,
  AnalysisOptions,
  MeshType,
  MeshConfig,
  Severity,
  NistControl,
  ConfigFix,
  ComplianceFramework,
  IstioConfig,
  ConsulConfig,
  LinkerdConfig,
} from './types.js';

// Re-export analyzers
export { BaseSecurityAnalyzer, resetFindingIdCounter } from './analyzers/base.js';
export { IstioSecurityAnalyzer } from './analyzers/istio.js';
export { ConsulSecurityAnalyzer } from './analyzers/consul.js';
export { LinkerdSecurityAnalyzer } from './analyzers/linkerd.js';

// Re-export utilities
export { detectMeshType, normalizeConfig, validateConfig } from './utils/meshDetector.js';

// Re-export NIST controls
export { NIST_CONTROLS, getNistControl, getNistControls } from './frameworks/nist.js';

/**
 * Calculate summary statistics from findings
 */
function calculateSummary(findings: Finding[]): FindingSummary {
  return {
    critical: findings.filter((f) => f.severity === 'Critical').length,
    high: findings.filter((f) => f.severity === 'High').length,
    medium: findings.filter((f) => f.severity === 'Medium').length,
    low: findings.filter((f) => f.severity === 'Low').length,
    total: findings.length,
  };
}

/**
 * Filter findings by minimum severity level
 */
function filterBySeverity(findings: Finding[], minSeverity?: Severity): Finding[] {
  if (!minSeverity) return findings;

  const severityOrder: Severity[] = ['Low', 'Medium', 'High', 'Critical'];
  const minIndex = severityOrder.indexOf(minSeverity);

  return findings.filter((f) => severityOrder.indexOf(f.severity) >= minIndex);
}

/**
 * Analyze a configuration object
 */
export function analyzeConfig(
  config: unknown,
  options: AnalysisOptions = {}
): AnalysisResult {
  // Detect mesh type
  let meshType = detectMeshType(config);

  if (!meshType) {
    return {
      success: false,
      meshType: null,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      error:
        'Could not determine mesh type. Please ensure the file is a valid service mesh configuration (Istio, Consul, or Linkerd).',
    };
  }

  // Check if this mesh type is enabled
  if (options.enabledMeshTypes && !options.enabledMeshTypes.includes(meshType)) {
    return {
      success: false,
      meshType,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      error: `Mesh type ${meshType} is not enabled in options.`,
    };
  }

  // Normalize config for the detected mesh type
  const normalizedConfig = normalizeConfig(config, meshType);

  // Create appropriate analyzer
  let analyzer;
  switch (meshType) {
    case 'Istio':
      analyzer = new IstioSecurityAnalyzer();
      break;
    case 'Consul':
      analyzer = new ConsulSecurityAnalyzer();
      if (options.framework === 'fedramp') {
        analyzer.setFedRAMPMode(true);
      }
      break;
    case 'Linkerd':
      analyzer = new LinkerdSecurityAnalyzer();
      break;
  }

  // Run analysis
  let findings = analyzer.analyze(normalizedConfig);

  // Filter by severity if specified
  findings = filterBySeverity(findings, options.minSeverity);

  return {
    success: true,
    meshType,
    findings,
    summary: calculateSummary(findings),
  };
}

/**
 * Parse YAML content and analyze it
 */
export function analyzeYaml(
  content: string,
  options: AnalysisOptions = {}
): AnalysisResult {
  try {
    const config = yaml.load(content);
    return analyzeConfig(config, options);
  } catch (error) {
    return {
      success: false,
      meshType: null,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      error: `Failed to parse YAML: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Parse JSON content and analyze it
 */
export function analyzeJson(
  content: string,
  options: AnalysisOptions = {}
): AnalysisResult {
  try {
    const config = JSON.parse(content);
    return analyzeConfig(config, options);
  } catch (error) {
    return {
      success: false,
      meshType: null,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      error: `Failed to parse JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Analyze content, auto-detecting format (YAML or JSON)
 */
export function analyzeContent(
  content: string,
  options: AnalysisOptions = {}
): AnalysisResult {
  const trimmed = content.trim();

  // Try to detect format
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return analyzeJson(content, options);
  }

  // Default to YAML
  return analyzeYaml(content, options);
}
