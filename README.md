# Mesh Security Analyzer

A comprehensive security analysis toolkit for service mesh configurations (Istio, Consul, Linkerd) with NIST 800-53 compliance mapping.

## Features

- **Multi-mesh support**: Analyze Istio, Consul, and Linkerd configurations
- **NIST 800-53 Rev. 5 compliance**: Findings mapped to specific security controls
- **FedRAMP support**: Additional checks for federal compliance requirements
- **Auto-detection**: Automatically detects mesh type from configuration structure
- **Auto-fix suggestions**: Many findings include specific remediation code

## Packages

| Package | Description |
|---------|-------------|
| `@mesh-security/core` | Core analysis library (TypeScript) |
| `mesh-security-vscode` | VS Code extension with inline diagnostics |
| `@mesh-security/mcp` | MCP server for Claude integration |

## Quick Start

### Using the Core Library

```typescript
import { analyzeYaml, analyzeJson, analyzeContent } from '@mesh-security/core';

// Analyze YAML content
const result = analyzeYaml(yamlContent);

// Analyze JSON content
const result = analyzeJson(jsonContent);

// Auto-detect format
const result = analyzeContent(content);

// With options
const result = analyzeContent(content, {
  framework: 'fedramp',      // 'nist' | 'fedramp'
  minSeverity: 'Medium',     // 'Critical' | 'High' | 'Medium' | 'Low'
  enabledMeshTypes: ['Istio', 'Consul']
});
```

### VS Code Extension

1. Build the extension: `pnpm --filter mesh-security-vscode build`
2. Press F5 in VS Code to launch the extension in debug mode
3. Open any mesh configuration file (.yaml, .json)
4. Security issues appear as squiggly lines with hover details

### MCP Server (Claude Integration)

Add to your Claude configuration:

```json
{
  "mcpServers": {
    "mesh-security": {
      "command": "node",
      "args": ["/path/to/mesh-security/packages/mcp/dist/index.js"]
    }
  }
}
```

Then ask Claude:
- "Analyze my Istio mesh config at ./config.yaml"
- "Generate a FedRAMP compliance report for my Consul configuration"
- "What security issues does my Linkerd config have?"

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_config` | Analyze a single configuration file |
| `analyze_directory` | Scan all configs in a directory |
| `get_findings` | Get findings filtered by severity/category |
| `suggest_fix` | Get detailed remediation for findings |
| `generate_report` | Generate compliance report (markdown/json/html) |
| `compare_configs` | Compare security posture between configs |

## Security Checks

### Istio (10+ checks)
- mTLS configuration and enforcement mode
- Certificate authority and validity periods
- Peer authentication policies
- Proxy configuration (privileged mode, image pinning)
- Secret Discovery Service (SDS)
- Trust domain configuration
- Authorization policies (default deny)
- Telemetry and access logging
- RBAC enforcement
- Outbound traffic policy

### Consul (12+ checks)
- Service mesh (Connect) enabled
- Proxy security settings
- TLS verification (incoming/outgoing/hostname)
- ACL system and default policy
- Agent and default tokens
- Auto-encrypt and auto-config
- Gossip encryption and verification
- **FedRAMP-specific**: TLS 1.2+, FIPS ciphers, audit logging, secure bootstrap

### Linkerd (12+ checks)
- TLS enabled and enforced
- Cipher suite validation (no weak ciphers)
- Minimum TLS version (1.2+)
- Service identity configuration
- Trust anchors
- Proxy configuration and resource limits
- Policy enforcement (default deny)
- Authentication mode
- Distributed tracing
- Metrics collection
- Destination rules TLS settings

## NIST 800-53 Controls

Findings are mapped to relevant NIST controls:

| Control | Title |
|---------|-------|
| AC-3 | Access Enforcement |
| AC-4 | Information Flow Enforcement |
| AC-17 | Remote Access |
| AU-2/3/12 | Audit Events, Content, Generation |
| CM-2/6/7 | Baseline Configuration, Settings, Least Functionality |
| IA-2/5 | Identification/Authentication, Authenticator Management |
| SC-7/8/12/13/23 | Boundary Protection, Transmission Security, Crypto |
| SI-4 | Information System Monitoring |

## Development

### Prerequisites

- Node.js 18+
- pnpm 8+

### Setup

```bash
git clone https://github.com/yourusername/mesh-security.git
cd mesh-security
pnpm install
```

### Build

```bash
# Build all packages
pnpm build

# Build specific package
pnpm --filter @mesh-security/core build
pnpm --filter mesh-security-vscode build
pnpm --filter @mesh-security/mcp build
```

### Test

```bash
pnpm test
```

## Project Structure

```
mesh-security/
├── packages/
│   ├── core/                 # Shared analyzer library
│   │   ├── src/
│   │   │   ├── analyzers/    # Istio, Consul, Linkerd analyzers
│   │   │   ├── frameworks/   # NIST controls
│   │   │   ├── utils/        # Mesh detection, config normalization
│   │   │   ├── types.ts      # TypeScript types
│   │   │   └── index.ts      # Public API
│   │   └── package.json
│   │
│   ├── vscode/               # VS Code extension
│   │   ├── src/
│   │   │   ├── providers/    # Diagnostic, hover, code action
│   │   │   ├── utils/        # Range calculation
│   │   │   └── extension.ts  # Extension entry point
│   │   └── package.json
│   │
│   └── mcp/                  # MCP server
│       ├── src/
│       │   └── index.ts      # Server with 6 tools
│       └── package.json
│
├── samples/                  # Test configurations
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

## License

MIT
