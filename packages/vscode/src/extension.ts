import * as vscode from 'vscode';
import { DiagnosticProvider } from './providers/diagnostic';
import { HoverProvider } from './providers/hover';
import { CodeActionProvider } from './providers/codeAction';

let diagnosticProvider: DiagnosticProvider;

export function activate(context: vscode.ExtensionContext): void {
  console.log('Mesh Security Analyzer is now active');

  // Create diagnostic collection
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('meshSecurity');
  context.subscriptions.push(diagnosticCollection);

  // Initialize providers
  diagnosticProvider = new DiagnosticProvider(diagnosticCollection);

  // Register hover provider for YAML and JSON
  const hoverProvider = new HoverProvider();
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      [{ language: 'yaml' }, { language: 'json' }],
      hoverProvider
    )
  );

  // Register code action provider
  const codeActionProvider = new CodeActionProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [{ language: 'yaml' }, { language: 'json' }],
      codeActionProvider,
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      }
    )
  );

  // Subscribe to document events
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      diagnosticProvider.analyzeDocument(doc);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      diagnosticProvider.analyzeDocument(event.document);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('meshSecurity.analyzeFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        diagnosticProvider.analyzeDocument(editor.document);
        vscode.window.showInformationMessage('Mesh Security: Analysis complete');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('meshSecurity.analyzeWorkspace', async () => {
      const files = await vscode.workspace.findFiles('**/*.{yaml,yml,json}', '**/node_modules/**');
      let analyzedCount = 0;

      for (const file of files) {
        const doc = await vscode.workspace.openTextDocument(file);
        diagnosticProvider.analyzeDocument(doc);
        analyzedCount++;
      }

      vscode.window.showInformationMessage(`Mesh Security: Analyzed ${analyzedCount} files`);
    })
  );

  // Analyze all open documents on activation
  vscode.workspace.textDocuments.forEach((doc) => {
    diagnosticProvider.analyzeDocument(doc);
  });
}

export function deactivate(): void {
  // Cleanup if needed
}
