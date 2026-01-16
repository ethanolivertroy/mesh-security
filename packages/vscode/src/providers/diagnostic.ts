import * as vscode from 'vscode';
import {
  analyzeContent,
  type Finding,
  type Severity,
  type MeshType,
  type AnalysisOptions,
} from '@mesh-security/core';
import { findLocationInDocument } from '../utils/rangeCalculator';

/**
 * Provides diagnostics (squiggly lines) for mesh config security issues
 */
export class DiagnosticProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
  private findingsCache: Map<string, Finding[]> = new Map();

  constructor(diagnosticCollection: vscode.DiagnosticCollection) {
    this.diagnosticCollection = diagnosticCollection;
  }

  /**
   * Analyze a document and update diagnostics
   */
  analyzeDocument(document: vscode.TextDocument): void {
    // Only process YAML and JSON files
    if (document.languageId !== 'yaml' && document.languageId !== 'json') {
      return;
    }

    // Debounce analysis
    const uri = document.uri.toString();
    const existingTimer = this.debounceTimers.get(uri);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timer = setTimeout(() => {
      this.doAnalysis(document);
      this.debounceTimers.delete(uri);
    }, 300);

    this.debounceTimers.set(uri, timer);
  }

  /**
   * Get cached findings for a document
   */
  getFindings(uri: string): Finding[] {
    return this.findingsCache.get(uri) || [];
  }

  private doAnalysis(document: vscode.TextDocument): void {
    const config = vscode.workspace.getConfiguration('meshSecurity');

    // Check if extension is enabled
    if (!config.get('enable', true)) {
      this.diagnosticCollection.delete(document.uri);
      return;
    }

    const content = document.getText();

    // Quick check - try to detect if this looks like a mesh config
    const meshType = this.quickDetectMeshType(content);
    if (!meshType) {
      this.diagnosticCollection.delete(document.uri);
      this.findingsCache.delete(document.uri.toString());
      return;
    }

    // Build analysis options from settings
    const minSeverity = config.get<string>('minSeverity', 'low');
    const frameworks = config.get<string[]>('frameworks', ['nist']);
    const meshTypes = config.get<string[]>('meshTypes', ['istio', 'consul', 'linkerd']);

    const options: AnalysisOptions = {
      minSeverity: this.mapSeverity(minSeverity),
      framework: frameworks.includes('fedramp') ? 'fedramp' : 'nist',
      enabledMeshTypes: meshTypes.map((t) => this.mapMeshType(t)).filter(Boolean) as MeshType[],
    };

    // Run analysis
    const result = analyzeContent(content, options);

    if (!result.success) {
      this.diagnosticCollection.delete(document.uri);
      this.findingsCache.delete(document.uri.toString());
      return;
    }

    // Cache findings for hover/code action providers
    this.findingsCache.set(document.uri.toString(), result.findings);

    // Convert findings to diagnostics
    const diagnostics = result.findings.map((finding) =>
      this.findingToDiagnostic(finding, document)
    );

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  private quickDetectMeshType(content: string): boolean {
    // Quick string-based detection to avoid parsing every file
    const meshIndicators = [
      'meshMTLS',
      'peerAuthentication',
      'MeshConfig',
      'istio.io',
      'mesh_type',
      'consul',
      'linkerd',
      'connect:',
      'identity:',
      'proxy:',
      'trustDomain',
    ];

    return meshIndicators.some((indicator) => content.includes(indicator));
  }

  private findingToDiagnostic(finding: Finding, document: vscode.TextDocument): vscode.Diagnostic {
    // Calculate range from finding location
    const range = findLocationInDocument(document, finding.location);

    // Map severity
    const severity = this.mapDiagnosticSeverity(finding.severity);

    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
    diagnostic.source = 'Mesh Security';
    diagnostic.code = finding.category;

    // Add related information for NIST controls
    if (finding.nistControls.length > 0) {
      diagnostic.relatedInformation = finding.nistControls.map((control) => {
        return new vscode.DiagnosticRelatedInformation(
          new vscode.Location(document.uri, range),
          `${control.id}: ${control.title}`
        );
      });
    }

    return diagnostic;
  }

  private mapDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'Critical':
      case 'High':
        return vscode.DiagnosticSeverity.Error;
      case 'Medium':
        return vscode.DiagnosticSeverity.Warning;
      case 'Low':
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  private mapSeverity(severity: string): Severity {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'Critical';
      case 'high':
        return 'High';
      case 'medium':
        return 'Medium';
      case 'low':
      default:
        return 'Low';
    }
  }

  private mapMeshType(type: string): MeshType | null {
    switch (type.toLowerCase()) {
      case 'istio':
        return 'Istio';
      case 'consul':
        return 'Consul';
      case 'linkerd':
        return 'Linkerd';
      default:
        return null;
    }
  }
}
