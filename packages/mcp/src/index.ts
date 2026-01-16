#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import * as fs from 'fs';
import * as path from 'path';
import {
  analyzeYaml,
  analyzeJson,
  type AnalysisResult,
  type AnalysisOptions,
  type Finding,
  type ComplianceFramework,
  type Severity,
} from '@mesh-security/core';

// Define available tools
const tools: Tool[] = [
  {
    name: 'analyze_config',
    description:
      'Analyze a service mesh configuration file for security issues. Supports Istio, Consul, and Linkerd configurations in YAML or JSON format.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path to the configuration file to analyze',
        },
        framework: {
          type: 'string',
          enum: ['nist', 'fedramp'],
          description: 'Compliance framework to check against (default: nist)',
        },
        minSeverity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity level to report (default: low)',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'analyze_directory',
    description:
      'Analyze all service mesh configuration files in a directory. Supports recursive scanning.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Directory path to scan for configuration files',
        },
        recursive: {
          type: 'boolean',
          description: 'Whether to scan subdirectories (default: true)',
        },
        framework: {
          type: 'string',
          enum: ['nist', 'fedramp'],
          description: 'Compliance framework to check against (default: nist)',
        },
        minSeverity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Minimum severity level to report (default: low)',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'get_findings',
    description:
      'Get findings from a previous analysis, optionally filtered by severity or category.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path to the configuration file to analyze',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Filter by severity level',
        },
        category: {
          type: 'string',
          description: 'Filter by category (e.g., "mTLS", "RBAC", "TLS Security")',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'suggest_fix',
    description:
      'Get detailed remediation suggestions for a specific finding or security issue.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path to the configuration file',
        },
        findingId: {
          type: 'string',
          description: 'ID of the specific finding to get fix suggestions for',
        },
        category: {
          type: 'string',
          description: 'Category of findings to get fix suggestions for',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'generate_report',
    description:
      'Generate a compliance report from analysis results in various formats.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path to the configuration file or directory to analyze',
        },
        format: {
          type: 'string',
          enum: ['markdown', 'json', 'html'],
          description: 'Output format (default: markdown)',
        },
        framework: {
          type: 'string',
          enum: ['nist', 'fedramp'],
          description: 'Compliance framework to report against (default: nist)',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'compare_configs',
    description:
      'Compare security posture between two configuration files or versions.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path1: {
          type: 'string',
          description: 'Path to the first configuration file',
        },
        path2: {
          type: 'string',
          description: 'Path to the second configuration file',
        },
        framework: {
          type: 'string',
          enum: ['nist', 'fedramp'],
          description: 'Compliance framework to check against (default: nist)',
        },
      },
      required: ['path1', 'path2'],
    },
  },
];

// Helper functions

function mapSeverity(severity: string | undefined): Severity | undefined {
  if (!severity) return undefined;
  const map: Record<string, Severity> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
  };
  return map[severity.toLowerCase()];
}

function analyzeFile(filePath: string, options: AnalysisOptions = {}): AnalysisResult {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    return {
      success: false,
      meshType: null,
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      error: `File not found: ${absolutePath}`,
    };
  }

  const content = fs.readFileSync(absolutePath, 'utf-8');
  const ext = path.extname(absolutePath).toLowerCase();

  if (ext === '.json') {
    return analyzeJson(content, options);
  }
  return analyzeYaml(content, options);
}

function findConfigFiles(dirPath: string, recursive: boolean = true): string[] {
  const absolutePath = path.resolve(dirPath);
  const files: string[] = [];
  const extensions = ['.yaml', '.yml', '.json'];

  function scan(dir: string): void {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory() && recursive) {
        // Skip common non-config directories
        if (!['node_modules', '.git', 'dist', 'build'].includes(entry.name)) {
          scan(fullPath);
        }
      } else if (entry.isFile() && extensions.includes(path.extname(entry.name).toLowerCase())) {
        files.push(fullPath);
      }
    }
  }

  scan(absolutePath);
  return files;
}

function formatFinding(finding: Finding): string {
  let output = `### ${finding.severity}: ${finding.category}\n\n`;
  output += `**${finding.message}**\n\n`;
  output += `${finding.recommendation}\n\n`;

  if (finding.location) {
    output += `*Location: \`${finding.location}\`*\n\n`;
  }

  if (finding.nistControls.length > 0) {
    output += '**NIST Controls:**\n';
    for (const control of finding.nistControls) {
      output += `- ${control.id}: ${control.title}\n`;
    }
    output += '\n';
  }

  if (finding.autoFixable && finding.fix) {
    output += `**Auto-fix available:** Set \`${finding.fix.path}\` to \`${JSON.stringify(finding.fix.value)}\`\n\n`;
  }

  return output;
}

function generateMarkdownReport(result: AnalysisResult, filePath: string): string {
  let report = `# Mesh Security Analysis Report\n\n`;
  report += `**File:** ${filePath}\n`;
  report += `**Mesh Type:** ${result.meshType || 'Unknown'}\n`;
  report += `**Analysis Date:** ${new Date().toISOString()}\n\n`;

  report += `## Summary\n\n`;
  report += `| Severity | Count |\n`;
  report += `|----------|-------|\n`;
  report += `| Critical | ${result.summary.critical} |\n`;
  report += `| High | ${result.summary.high} |\n`;
  report += `| Medium | ${result.summary.medium} |\n`;
  report += `| Low | ${result.summary.low} |\n`;
  report += `| **Total** | **${result.summary.total}** |\n\n`;

  if (result.findings.length > 0) {
    report += `## Findings\n\n`;
    for (const finding of result.findings) {
      report += formatFinding(finding);
      report += '---\n\n';
    }
  } else {
    report += `No security issues found.\n`;
  }

  return report;
}

// Create MCP server
const server = new Server(
  {
    name: 'mesh-security',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'analyze_config': {
        const filePath = args?.path as string;
        const framework = args?.framework as ComplianceFramework | undefined;
        const minSeverity = mapSeverity(args?.minSeverity as string);

        const result = analyzeFile(filePath, { framework, minSeverity });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'analyze_directory': {
        const dirPath = args?.path as string;
        const recursive = args?.recursive !== false;
        const framework = args?.framework as ComplianceFramework | undefined;
        const minSeverity = mapSeverity(args?.minSeverity as string);

        const files = findConfigFiles(dirPath, recursive);
        const results: Record<string, AnalysisResult> = {};

        for (const file of files) {
          const result = analyzeFile(file, { framework, minSeverity });
          if (result.success && result.findings.length > 0) {
            results[file] = result;
          }
        }

        const summary = {
          filesScanned: files.length,
          filesWithIssues: Object.keys(results).length,
          totalFindings: Object.values(results).reduce((sum, r) => sum + r.summary.total, 0),
          results,
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      }

      case 'get_findings': {
        const filePath = args?.path as string;
        const severity = mapSeverity(args?.severity as string);
        const category = args?.category as string | undefined;

        const result = analyzeFile(filePath);

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error}` }],
          };
        }

        let findings = result.findings;

        if (severity) {
          const severityOrder: Severity[] = ['Low', 'Medium', 'High', 'Critical'];
          const minIndex = severityOrder.indexOf(severity);
          findings = findings.filter((f) => severityOrder.indexOf(f.severity) >= minIndex);
        }

        if (category) {
          findings = findings.filter((f) =>
            f.category.toLowerCase().includes(category.toLowerCase())
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ meshType: result.meshType, findings }, null, 2),
            },
          ],
        };
      }

      case 'suggest_fix': {
        const filePath = args?.path as string;
        const findingId = args?.findingId as string | undefined;
        const category = args?.category as string | undefined;

        const result = analyzeFile(filePath);

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error}` }],
          };
        }

        let findings = result.findings.filter((f) => f.autoFixable);

        if (findingId) {
          findings = findings.filter((f) => f.id === findingId);
        }

        if (category) {
          findings = findings.filter((f) =>
            f.category.toLowerCase().includes(category.toLowerCase())
          );
        }

        const fixes = findings.map((f) => ({
          id: f.id,
          category: f.category,
          severity: f.severity,
          message: f.message,
          recommendation: f.recommendation,
          fix: f.fix,
          nistGuidance: f.nistGuidance,
        }));

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ meshType: result.meshType, fixes }, null, 2),
            },
          ],
        };
      }

      case 'generate_report': {
        const filePath = args?.path as string;
        const format = (args?.format as string) || 'markdown';
        const framework = args?.framework as ComplianceFramework | undefined;

        const result = analyzeFile(filePath, { framework });

        if (!result.success) {
          return {
            content: [{ type: 'text', text: `Error: ${result.error}` }],
          };
        }

        let report: string;
        switch (format) {
          case 'json':
            report = JSON.stringify(result, null, 2);
            break;
          case 'html':
            // Simple HTML report
            report = `<!DOCTYPE html><html><head><title>Mesh Security Report</title></head><body>`;
            report += `<h1>Mesh Security Report</h1>`;
            report += `<p>File: ${filePath}</p>`;
            report += `<p>Mesh Type: ${result.meshType}</p>`;
            report += `<h2>Summary</h2>`;
            report += `<ul>`;
            report += `<li>Critical: ${result.summary.critical}</li>`;
            report += `<li>High: ${result.summary.high}</li>`;
            report += `<li>Medium: ${result.summary.medium}</li>`;
            report += `<li>Low: ${result.summary.low}</li>`;
            report += `</ul>`;
            report += `</body></html>`;
            break;
          case 'markdown':
          default:
            report = generateMarkdownReport(result, filePath);
            break;
        }

        return {
          content: [{ type: 'text', text: report }],
        };
      }

      case 'compare_configs': {
        const path1 = args?.path1 as string;
        const path2 = args?.path2 as string;
        const framework = args?.framework as ComplianceFramework | undefined;

        const result1 = analyzeFile(path1, { framework });
        const result2 = analyzeFile(path2, { framework });

        if (!result1.success) {
          return {
            content: [{ type: 'text', text: `Error analyzing ${path1}: ${result1.error}` }],
          };
        }

        if (!result2.success) {
          return {
            content: [{ type: 'text', text: `Error analyzing ${path2}: ${result2.error}` }],
          };
        }

        // Compare findings
        const findingsIn1Only = result1.findings.filter(
          (f1) => !result2.findings.some((f2) => f2.message === f1.message)
        );
        const findingsIn2Only = result2.findings.filter(
          (f2) => !result1.findings.some((f1) => f1.message === f2.message)
        );
        const commonFindings = result1.findings.filter((f1) =>
          result2.findings.some((f2) => f2.message === f1.message)
        );

        const comparison = {
          file1: {
            path: path1,
            meshType: result1.meshType,
            summary: result1.summary,
          },
          file2: {
            path: path2,
            meshType: result2.meshType,
            summary: result2.summary,
          },
          analysis: {
            issuesFixedIn2: findingsIn1Only.length,
            newIssuesIn2: findingsIn2Only.length,
            commonIssues: commonFindings.length,
            overallChange:
              result2.summary.total - result1.summary.total > 0
                ? 'worse'
                : result2.summary.total - result1.summary.total < 0
                  ? 'better'
                  : 'same',
          },
          details: {
            fixedIssues: findingsIn1Only.map((f) => ({
              severity: f.severity,
              category: f.category,
              message: f.message,
            })),
            newIssues: findingsIn2Only.map((f) => ({
              severity: f.severity,
              category: f.category,
              message: f.message,
            })),
          },
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(comparison, null, 2),
            },
          ],
        };
      }

      default:
        return {
          content: [{ type: 'text', text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Mesh Security MCP Server running on stdio');
}

main().catch(console.error);
