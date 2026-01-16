import * as vscode from 'vscode';
import { analyzeContent, type Finding } from '@mesh-security/core';
import { findLocationInDocument } from '../utils/rangeCalculator';

/**
 * Provides code actions (quick fixes) for mesh config security issues
 */
export class CodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    // Only process YAML and JSON files
    if (document.languageId !== 'yaml' && document.languageId !== 'json') {
      return [];
    }

    // Get diagnostics at this location
    const diagnostics = context.diagnostics.filter((d) => d.source === 'Mesh Security');
    if (diagnostics.length === 0) {
      return [];
    }

    // Analyze the document to get findings with fix information
    const content = document.getText();
    const result = analyzeContent(content);

    if (!result.success) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of diagnostics) {
      // Find the matching finding
      const finding = result.findings.find(
        (f) => f.message === diagnostic.message && f.category === diagnostic.code
      );

      if (!finding) {
        continue;
      }

      // If the finding has an auto-fix, create a quick fix action
      if (finding.autoFixable && finding.fix) {
        const fixAction = this.createFixAction(document, finding, diagnostic);
        if (fixAction) {
          actions.push(fixAction);
        }
      }

      // Always add a "Learn more" action
      const learnMoreAction = this.createLearnMoreAction(finding, diagnostic);
      actions.push(learnMoreAction);
    }

    return actions;
  }

  private createFixAction(
    document: vscode.TextDocument,
    finding: Finding,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | null {
    if (!finding.fix) {
      return null;
    }

    const action = new vscode.CodeAction(
      `Fix: ${finding.recommendation.substring(0, 50)}...`,
      vscode.CodeActionKind.QuickFix
    );

    action.diagnostics = [diagnostic];
    action.isPreferred = true;

    // Create the edit
    const edit = new vscode.WorkspaceEdit();
    const range = findLocationInDocument(document, finding.location);

    // For YAML/JSON, we need to construct the proper value
    const fix = finding.fix;
    let newValue: string;

    if (typeof fix.value === 'boolean') {
      newValue = fix.value ? 'true' : 'false';
    } else if (typeof fix.value === 'string') {
      newValue = `"${fix.value}"`;
    } else {
      newValue = String(fix.value);
    }

    // This is a simplified fix - in practice we'd need more sophisticated YAML/JSON editing
    // For now, we'll just show what the fix would be in the action title
    action.command = {
      command: 'meshSecurity.showFix',
      title: 'Show Fix',
      arguments: [finding.fix],
    };

    // Note: A full implementation would use a YAML/JSON parser to make precise edits
    // For now, we'll add a placeholder edit that shows the user what needs to change
    const comment =
      document.languageId === 'yaml'
        ? `# TODO: Set ${fix.path} to ${newValue}`
        : `// TODO: Set ${fix.path} to ${newValue}`;

    edit.insert(document.uri, new vscode.Position(range.start.line, 0), comment + '\n');
    action.edit = edit;

    return action;
  }

  private createLearnMoreAction(finding: Finding, diagnostic: vscode.Diagnostic): vscode.CodeAction {
    const action = new vscode.CodeAction('Learn more about this issue', vscode.CodeActionKind.QuickFix);

    action.diagnostics = [diagnostic];

    // Create a command that shows detailed information
    action.command = {
      command: 'meshSecurity.showDetails',
      title: 'Show Details',
      arguments: [finding],
    };

    return action;
  }
}

// Register the showDetails command
vscode.commands.registerCommand('meshSecurity.showDetails', (finding: Finding) => {
  const panel = vscode.window.createWebviewPanel(
    'meshSecurityDetails',
    `Security Issue: ${finding.category}`,
    vscode.ViewColumn.Beside,
    {}
  );

  const nistControlsList = finding.nistControls
    .map((c) => `<li><strong>${c.id}</strong>: ${c.title}<br><em>${c.description}</em></li>`)
    .join('');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: var(--vscode-font-family); padding: 20px; }
        .severity-Critical { color: #ff4444; }
        .severity-High { color: #ff8800; }
        .severity-Medium { color: #ffcc00; }
        .severity-Low { color: #44aa44; }
        h1 { font-size: 1.5em; }
        h2 { font-size: 1.2em; margin-top: 20px; }
        blockquote { border-left: 3px solid #666; padding-left: 10px; margin-left: 0; }
        ul { padding-left: 20px; }
      </style>
    </head>
    <body>
      <h1 class="severity-${finding.severity}">${finding.severity}: ${finding.category}</h1>
      <p><strong>${finding.message}</strong></p>
      <p>${finding.recommendation}</p>

      ${finding.location ? `<p><em>Location: ${finding.location}</em></p>` : ''}

      ${
        finding.nistControls.length > 0
          ? `
        <h2>NIST 800-53 Controls</h2>
        <ul>${nistControlsList}</ul>
      `
          : ''
      }

      ${
        finding.nistGuidance
          ? `
        <h2>NIST Guidance</h2>
        <blockquote>${finding.nistGuidance}</blockquote>
      `
          : ''
      }

      ${
        finding.autoFixable && finding.fix
          ? `
        <h2>Suggested Fix</h2>
        <p>Set <code>${finding.fix.path}</code> to <code>${JSON.stringify(finding.fix.value)}</code></p>
      `
          : ''
      }
    </body>
    </html>
  `;
});

// Register the showFix command
vscode.commands.registerCommand('meshSecurity.showFix', (fix: { path: string; action: string; value: unknown }) => {
  vscode.window.showInformationMessage(
    `To fix this issue, set "${fix.path}" to ${JSON.stringify(fix.value)}`
  );
});
