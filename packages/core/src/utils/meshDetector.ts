import type { MeshType, MeshConfig, IstioConfig, ConsulConfig, LinkerdConfig } from '../types.js';

/**
 * Detect the mesh type from a configuration object
 */
export function detectMeshType(config: unknown): MeshType | null {
  if (!config || typeof config !== 'object') {
    return null;
  }

  const obj = config as Record<string, unknown>;

  // Check for explicit Istio markers
  if (obj.kind === 'MeshConfig' && typeof obj.apiVersion === 'string' && obj.apiVersion.includes('istio.io')) {
    return 'Istio';
  }

  // Check for explicit mesh_type field
  if (obj.mesh_type === 'consul') {
    return 'Consul';
  }

  if (obj.mesh_type === 'linkerd') {
    return 'Linkerd';
  }

  // Auto-detect based on configuration patterns

  // Consul patterns
  if (obj.connect && obj.tls && obj.acl) {
    return 'Consul';
  }

  // Istio patterns
  if (obj.meshMTLS || obj.defaultConfig || obj.peerAuthentication) {
    return 'Istio';
  }

  // Linkerd patterns
  if (obj.identity && obj.proxy && (obj.tls || obj.policy)) {
    return 'Linkerd';
  }

  return null;
}

/**
 * Normalize a configuration by adding required markers for the detected mesh type
 */
export function normalizeConfig(config: unknown, meshType: MeshType): MeshConfig {
  const obj = { ...(config as object) };

  switch (meshType) {
    case 'Istio': {
      const istioConfig = obj as IstioConfig;
      if (!istioConfig.kind) {
        istioConfig.kind = 'MeshConfig';
      }
      if (!istioConfig.apiVersion) {
        istioConfig.apiVersion = 'networking.istio.io/v1alpha1';
      }
      return istioConfig;
    }
    case 'Consul': {
      const consulConfig = obj as ConsulConfig;
      if (!consulConfig.mesh_type) {
        consulConfig.mesh_type = 'consul';
      }
      return consulConfig;
    }
    case 'Linkerd': {
      const linkerdConfig = obj as LinkerdConfig;
      if (!linkerdConfig.mesh_type) {
        linkerdConfig.mesh_type = 'linkerd';
      }
      return linkerdConfig;
    }
  }
}

/**
 * Validate that a configuration is valid for its mesh type
 */
export function validateConfig(config: unknown, meshType: MeshType): boolean {
  if (!config || typeof config !== 'object') {
    return false;
  }

  const obj = config as Record<string, unknown>;

  switch (meshType) {
    case 'Istio':
      return obj.kind === 'MeshConfig' && typeof obj.apiVersion === 'string';
    case 'Consul':
      return obj.mesh_type === 'consul';
    case 'Linkerd':
      return obj.mesh_type === 'linkerd';
    default:
      return false;
  }
}
