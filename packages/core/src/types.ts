/**
 * Severity levels for security findings
 */
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

/**
 * NIST 800-53 control reference
 */
export interface NistControl {
  id: string;
  title: string;
  description: string;
}

/**
 * Suggested fix for auto-remediation
 */
export interface ConfigFix {
  path: string;
  action: 'set' | 'add' | 'remove';
  value: unknown;
}

/**
 * A security finding from the analyzer
 */
export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  message: string;
  recommendation: string;
  location: string | null;
  nistControls: NistControl[];
  nistGuidance: string | null;
  autoFixable: boolean;
  fix?: ConfigFix;
}

/**
 * Summary of findings by severity
 */
export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/**
 * Result of analyzing a configuration
 */
export interface AnalysisResult {
  success: boolean;
  meshType: MeshType | null;
  findings: Finding[];
  summary: FindingSummary;
  error?: string;
}

/**
 * Supported service mesh types
 */
export type MeshType = 'Istio' | 'Consul' | 'Linkerd';

/**
 * Compliance frameworks supported
 */
export type ComplianceFramework = 'nist' | 'fedramp' | 'soc2' | 'pci-dss';

/**
 * Options for running analysis
 */
export interface AnalysisOptions {
  framework?: ComplianceFramework;
  minSeverity?: Severity;
  enabledMeshTypes?: MeshType[];
}

// Config types for each mesh

/**
 * Istio MeshConfig structure (simplified)
 */
export interface IstioConfig {
  kind?: string;
  apiVersion?: string;
  meshMTLS?: {
    enabled?: boolean;
    mode?: string;
  };
  ca?: {
    provider?: string;
    certValidityDuration?: string;
  };
  peerAuthentication?: {
    mode?: string;
  };
  defaultConfig?: {
    privileged?: boolean;
    image?: string;
    holdApplicationUntilProxyStarts?: boolean;
    sds?: {
      enabled?: boolean;
    };
  };
  trustDomain?: string;
  defaultAuthorizationPolicy?: {
    action?: string;
  };
  telemetry?: {
    enabled?: boolean;
    accessLogging?: {
      enabled?: boolean;
    };
  };
  rbac?: {
    mode?: string;
  };
  outboundTrafficPolicy?: {
    mode?: string;
  };
  [key: string]: unknown;
}

/**
 * Consul configuration structure (simplified)
 */
export interface ConsulConfig {
  mesh_type?: string;
  connect?: {
    enabled?: boolean;
    proxy?: {
      allow_privileged?: boolean;
    };
    ca_provider?: string;
    ca_config?: {
      root_cert_ttl?: string;
      leaf_cert_ttl?: string;
      rotation_period?: string;
      rotate_cert_ttl?: string;
    };
  };
  tls?: {
    defaults?: {
      verify_incoming?: boolean;
      verify_outgoing?: boolean;
    };
    internal_rpc?: {
      verify_server_hostname?: boolean;
    };
    cipher_suites?: string[];
    min_version?: string;
  };
  acl?: {
    enabled?: boolean;
    default_policy?: string;
    tokens?: {
      agent?: string;
      default?: string;
    };
  };
  telemetry?: {
    enable_service_metrics?: boolean;
  };
  auto_encrypt?: {
    tls?: boolean;
  };
  auto_config?: {
    enabled?: boolean;
    authorization?: {
      enabled?: boolean;
    };
  };
  gossip?: {
    encryption?: {
      key?: string;
    };
    verify_incoming?: boolean;
    verify_outgoing?: boolean;
  };
  secure_bootstrap?: boolean;
  audit?: {
    enabled?: boolean;
  };
  services?: Array<{
    name?: string;
    connect?: {
      sidecar_service?: {
        proxy?: {
          local_service_address?: string;
        };
      };
    };
  }>;
  [key: string]: unknown;
}

/**
 * Linkerd configuration structure (simplified)
 */
export interface LinkerdConfig {
  mesh_type?: string;
  tls?: {
    enabled?: boolean;
    enforced?: boolean;
    cipherSuites?: string[];
    minimumVersion?: string;
  };
  identity?: {
    enabled?: boolean;
    issuer?: string;
    certValidityPeriod?: number;
    trustAnchorsPEM?: string[];
  };
  proxy?: {
    privileged?: boolean;
    image?: string;
    outboundConnectTimeout?: string;
    resources?: {
      cpu?: string;
      memory?: string;
    };
  };
  policy?: {
    enabled?: boolean;
    defaultDeny?: boolean;
    serverPolicies?: Array<{
      clients?: Array<{
        namespace?: string;
      }>;
    }>;
  };
  authentication?: {
    enabled?: boolean;
    mode?: string;
  };
  tracing?: {
    enabled?: boolean;
    sampling?: number;
    collector?: {
      service?: string;
    };
  };
  metrics?: {
    enabled?: boolean;
    prometheus?: {
      enabled?: boolean;
    };
    retention?: string;
  };
  destinationRules?: Array<{
    host?: string;
    tls?: {
      mode?: string;
    };
  }>;
  [key: string]: unknown;
}

/**
 * Union type for any mesh config
 */
export type MeshConfig = IstioConfig | ConsulConfig | LinkerdConfig;
