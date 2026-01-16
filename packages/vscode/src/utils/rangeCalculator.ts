import * as vscode from 'vscode';

/**
 * Find the range in a document for a given JSON path location
 */
export function findLocationInDocument(
  document: vscode.TextDocument,
  location: string | null
): vscode.Range {
  if (!location) {
    // Default to the first line if no location is specified
    return new vscode.Range(0, 0, 0, document.lineAt(0).text.length);
  }

  const text = document.getText();
  const pathParts = location.split('.');

  // Try to find the key in the document
  let searchKey = pathParts[pathParts.length - 1];

  // Handle array notation like "services[0]"
  const arrayMatch = searchKey.match(/^(\w+)\[(\d+)\]$/);
  if (arrayMatch) {
    searchKey = arrayMatch[1];
  }

  // Build regex patterns to find the key
  const patterns = [
    // YAML style: "key:" at start of line
    new RegExp(`^\\s*${escapeRegex(searchKey)}\\s*:`, 'm'),
    // YAML style with quotes: '"key":' or "'key':"
    new RegExp(`^\\s*["']${escapeRegex(searchKey)}["']\\s*:`, 'm'),
    // JSON style: "key":
    new RegExp(`"${escapeRegex(searchKey)}"\\s*:`, 'm'),
    // Nested path - try to find the full path context
    new RegExp(`${escapeRegex(pathParts.slice(-2).join('.'))}`, 'm'),
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) {
      const startIndex = match.index;
      const pos = document.positionAt(startIndex);
      const line = document.lineAt(pos.line);
      return new vscode.Range(pos.line, 0, pos.line, line.text.length);
    }
  }

  // If we can't find the specific location, try to find parent keys
  for (let i = pathParts.length - 2; i >= 0; i--) {
    const parentKey = pathParts[i];
    const parentPattern = new RegExp(`^\\s*["']?${escapeRegex(parentKey)}["']?\\s*:`, 'm');
    const match = parentPattern.exec(text);
    if (match) {
      const startIndex = match.index;
      const pos = document.positionAt(startIndex);
      const line = document.lineAt(pos.line);
      return new vscode.Range(pos.line, 0, pos.line, line.text.length);
    }
  }

  // Default to the first line
  return new vscode.Range(0, 0, 0, document.lineAt(0).text.length);
}

/**
 * Get the JSON/YAML path at a given position in the document
 */
export function getPathAtPosition(
  document: vscode.TextDocument,
  position: vscode.Position
): string | null {
  // Simple approach: look at the current line and extract the key
  const line = document.lineAt(position.line).text;

  // Try to extract key from YAML format
  const yamlMatch = line.match(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:/);
  if (yamlMatch) {
    return buildPathFromLine(document, position.line, yamlMatch[1]);
  }

  // Try to extract key from JSON format
  const jsonMatch = line.match(/"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:/);
  if (jsonMatch) {
    return buildPathFromLine(document, position.line, jsonMatch[1]);
  }

  return null;
}

/**
 * Build the full path by looking at indentation levels above the current line
 */
function buildPathFromLine(
  document: vscode.TextDocument,
  lineNumber: number,
  currentKey: string
): string {
  const parts: string[] = [currentKey];
  const currentLine = document.lineAt(lineNumber).text;
  const currentIndent = getIndentLevel(currentLine);

  // Walk backwards to find parent keys
  for (let i = lineNumber - 1; i >= 0; i--) {
    const line = document.lineAt(i).text;
    const indent = getIndentLevel(line);

    // If this line is less indented, it might be a parent
    if (indent < currentIndent) {
      const yamlMatch = line.match(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:/);
      const jsonMatch = line.match(/"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:/);
      const key = yamlMatch?.[1] || jsonMatch?.[1];

      if (key) {
        parts.unshift(key);
      }
    }
  }

  return parts.join('.');
}

/**
 * Get the indentation level of a line (number of leading spaces)
 */
function getIndentLevel(line: string): number {
  const match = line.match(/^(\s*)/);
  return match ? match[1].length : 0;
}

/**
 * Escape special regex characters in a string
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
