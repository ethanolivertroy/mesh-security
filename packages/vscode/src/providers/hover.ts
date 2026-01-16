import * as vscode from 'vscode';
import { analyzeContent } from '@mesh-security/core';
import { getPathAtPosition } from '../utils/rangeCalculator';

/**
 * Provides hover information for mesh config security issues
 */
export class HoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.Hover | null {
    // Only process YAML and JSON files
    if (document.languageId !== 'yaml' && document.languageId !== 'json') {
      return null;
    }

    const content = document.getText();
    const result = analyzeContent(content);

    if (!result.success || result.findings.length === 0) {
      return null;
    }

    // Get the path at the current position
    const pathAtPosition = getPathAtPosition(document, position);
    if (!pathAtPosition) {
      return null;
    }

    // Find findings that match this location
    const relevantFindings = result.findings.filter((finding) => {
      if (!finding.location) return false;
      // Check if the finding location matches or is a parent of the current path
      return (
        pathAtPosition.startsWith(finding.location) ||
        finding.location.startsWith(pathAtPosition)
      );
    });

    if (relevantFindings.length === 0) {
      return null;
    }

    // Build hover content
    const contents = new vscode.MarkdownString();
    contents.isTrusted = true;

    for (const finding of relevantFindings) {
      contents.appendMarkdown(`### ${this.getSeverityIcon(finding.severity)} ${finding.category}\n\n`);
      contents.appendMarkdown(`**${finding.message}**\n\n`);
      contents.appendMarkdown(`${finding.recommendation}\n\n`);

      if (finding.nistControls.length > 0) {
        contents.appendMarkdown('**NIST Controls:**\n');
        for (const control of finding.nistControls) {
          contents.appendMarkdown(`- \`${control.id}\`: ${control.title}\n`);
        }
        contents.appendMarkdown('\n');
      }

      if (finding.nistGuidance) {
        contents.appendMarkdown('**NIST Guidance:**\n');
        contents.appendMarkdown(`> ${finding.nistGuidance.substring(0, 300)}...\n\n`);
      }

      contents.appendMarkdown('---\n\n');
    }

    return new vscode.Hover(contents);
  }

  private getSeverityIcon(severity: string): string {
    switch (severity) {
      case 'Critical':
        return '🔴';
      case 'High':
        return '🟠';
      case 'Medium':
        return '🟡';
      case 'Low':
        return '🟢';
      default:
        return '⚪';
    }
  }
}
