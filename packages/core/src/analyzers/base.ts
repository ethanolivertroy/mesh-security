import type { Finding, NistControl, Severity, ConfigFix } from '../types.js';
import { NIST_CONTROLS, getNistControls } from '../frameworks/nist.js';

let findingIdCounter = 0;

/**
 * Generate a unique finding ID
 */
function generateFindingId(): string {
  return `finding-${++findingIdCounter}`;
}

/**
 * Reset the finding ID counter (useful for testing)
 */
export function resetFindingIdCounter(): void {
  findingIdCounter = 0;
}

/**
 * Base class for security analyzers with common functionality
 */
export abstract class BaseSecurityAnalyzer {
  protected findings: Finding[] = [];

  constructor() {
    this.reset();
  }

  /**
   * Reset the analyzer state
   */
  reset(): void {
    this.findings = [];
  }

  /**
   * Add a security finding
   */
  protected addFinding(
    severity: Severity,
    category: string,
    message: string,
    recommendation: string,
    location: string | null = null,
    nistControlIds: string[] = [],
    nistGuidance: string | null = null,
    fix?: ConfigFix
  ): void {
    const controlRefs = getNistControls(nistControlIds);

    this.findings.push({
      id: generateFindingId(),
      severity,
      category,
      message,
      recommendation,
      location,
      nistControls: controlRefs,
      nistGuidance,
      autoFixable: fix !== undefined,
      fix,
    });
  }

  /**
   * Get all NIST controls
   */
  protected getNISTControls(): Record<string, NistControl> {
    return NIST_CONTROLS;
  }

  /**
   * Get the current findings
   */
  getFindings(): Finding[] {
    return [...this.findings];
  }

  /**
   * Analyze configuration - must be implemented by subclasses
   */
  abstract analyze(config: unknown): Finding[];
}
