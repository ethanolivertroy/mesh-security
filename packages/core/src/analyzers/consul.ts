import { BaseSecurityAnalyzer } from './base.js';
import type { Finding, ConsulConfig } from '../types.js';

/**
 * Security analyzer for Consul service mesh configurations
 */
export class ConsulSecurityAnalyzer extends BaseSecurityAnalyzer {
  private fedRAMPMode: boolean = true;

  /**
   * Enable or disable FedRAMP compliance checks
   */
  setFedRAMPMode(enabled: boolean): void {
    this.fedRAMPMode = enabled;
  }

  analyze(config: unknown): Finding[] {
    this.reset();

    const consulConfig = config as ConsulConfig;

    // Analyze overall structure
    if (!consulConfig) {
      this.addFinding(
        'Critical',
        'File Format',
        'Invalid or empty configuration file',
        'Provide a valid Consul configuration'
      );
      return this.getFindings();
    }

    // Check if it's a Consul configuration
    if (consulConfig.mesh_type !== 'consul') {
      this.addFinding(
        'Critical',
        'Resource Type',
        'File is not a Consul service mesh configuration',
        'Ensure the file has mesh_type field set to "consul"'
      );
      return this.getFindings();
    }

    // Run security checks
    this.checkConnect(consulConfig);
    this.checkTLS(consulConfig);
    this.checkACL(consulConfig);
    this.checkTelemetry(consulConfig);
    this.checkAutoEncrypt(consulConfig);
    this.checkAutoConfig(consulConfig);
    this.checkGossipEncryption(consulConfig);

    if (this.fedRAMPMode) {
      this.checkFedRAMPCompliance(consulConfig);
    }

    return this.getFindings();
  }

  private checkConnect(config: ConsulConfig): void {
    const connect = config.connect || {};

    // Check if service mesh is enabled
    if (!connect.enabled) {
      this.addFinding(
        'Critical',
        'Service Mesh',
        'Consul service mesh is not enabled',
        'Enable connect.enabled for service-to-service communication security',
        'connect.enabled',
        ['SC-8', 'SC-13'],
        'NIST SP 800-204B recommends implementing service mesh for secure service-to-service communication.',
        { path: 'connect.enabled', action: 'set', value: true }
      );
    }

    // Check proxy configuration
    const proxy = connect.proxy || {};
    if (proxy.allow_privileged === true) {
      this.addFinding(
        'High',
        'Proxy Security',
        'Proxies are allowed to run in privileged mode',
        'Disable connect.proxy.allow_privileged to prevent proxies from running with elevated privileges',
        'connect.proxy.allow_privileged',
        ['CM-7', 'AC-6'],
        'NIST SP 800-53 Rev. 5 emphasizes the principle of least privilege.',
        { path: 'connect.proxy.allow_privileged', action: 'set', value: false }
      );
    }

    // Check CA configuration
    if (connect.ca_provider === 'consul') {
      this.addFinding(
        'Medium',
        'Certificate Authority',
        'Using built-in Consul CA instead of an external CA',
        'Consider using a production-grade external CA for production environments',
        'connect.ca_provider',
        ['SC-12', 'IA-5', 'SC-13'],
        'NIST SP 800-204B recommends using a robust certificate authority infrastructure for production environments.'
      );
    }

    // Check certificate TTL settings
    const caConfig = connect.ca_config || {};
    if (caConfig.root_cert_ttl && caConfig.root_cert_ttl.includes('h')) {
      const hours = parseInt(caConfig.root_cert_ttl);
      if (hours > 8760) {
        // More than a year in hours
        this.addFinding(
          'Medium',
          'Certificate Security',
          'Root certificate has a very long TTL',
          'Consider shorter certificate validity periods for better security',
          'connect.ca_config.root_cert_ttl',
          ['IA-5', 'SC-12'],
          'NIST SP 800-57 recommends shorter certificate validity periods with automatic rotation.'
        );
      }
    }

    if (!caConfig.leaf_cert_ttl) {
      this.addFinding(
        'Medium',
        'Certificate Security',
        'Leaf certificate TTL not explicitly configured',
        'Set appropriate leaf_cert_ttl value based on your security policies',
        'connect.ca_config.leaf_cert_ttl',
        ['IA-5', 'SC-12'],
        'NIST SP 800-57 specifies that certificates should have appropriate validity periods.'
      );
    }
  }

  private checkTLS(config: ConsulConfig): void {
    const tls = config.tls || {};
    const defaults = tls.defaults || {};
    const internalRpc = tls.internal_rpc || {};

    // Check incoming verification
    if (defaults.verify_incoming !== true) {
      this.addFinding(
        'High',
        'TLS Security',
        'TLS verify_incoming is not enabled',
        'Enable tls.defaults.verify_incoming to validate client certificates',
        'tls.defaults.verify_incoming',
        ['SC-8', 'SC-13', 'IA-2', 'IA-5'],
        'NIST SP 800-52 Rev. 2 ("Guidelines for TLS Implementations") emphasizes the importance of certificate validation. Without incoming certificate verification, the system cannot verify the authenticity of client connections, potentially allowing unauthorized clients to establish connections.',
        { path: 'tls.defaults.verify_incoming', action: 'set', value: true }
      );
    }

    // Check outgoing verification
    if (defaults.verify_outgoing !== true) {
      this.addFinding(
        'High',
        'TLS Security',
        'TLS verify_outgoing is not enabled',
        'Enable tls.defaults.verify_outgoing to validate server certificates',
        'tls.defaults.verify_outgoing',
        ['SC-8', 'SC-13', 'SC-23'],
        'NIST SP 800-52 Rev. 2 requires TLS implementations to validate server certificates. Without outgoing certificate verification, clients cannot verify server identities, making them vulnerable to man-in-the-middle attacks.',
        { path: 'tls.defaults.verify_outgoing', action: 'set', value: true }
      );
    }

    // Check hostname verification
    if (internalRpc.verify_server_hostname !== true) {
      this.addFinding(
        'High',
        'TLS Security',
        'Server hostname verification is not enabled for internal RPC',
        'Enable tls.internal_rpc.verify_server_hostname to prevent MITM attacks',
        'tls.internal_rpc.verify_server_hostname',
        ['SC-8', 'SC-23', 'IA-5'],
        'NIST SP 800-52 Rev. 2 specifically requires hostname verification as part of certificate validation. Without hostname verification, an attacker with a valid certificate for one hostname could impersonate a server with a different hostname.',
        {
          path: 'tls.internal_rpc.verify_server_hostname',
          action: 'set',
          value: true,
        }
      );
    }
  }

  private checkACL(config: ConsulConfig): void {
    const acl = config.acl || {};

    // Check if ACL system is enabled
    if (acl.enabled !== true) {
      this.addFinding(
        'Critical',
        'Access Control',
        'ACL system is not enabled',
        'Enable acl.enabled to control access to Consul resources',
        'acl.enabled',
        ['AC-3', 'AC-4', 'AC-17', 'CM-7'],
        'NIST SP 800-204B recommends implementing access control for all service mesh components. Without ACLs, there is no mechanism to restrict which entities can access Consul resources and APIs.',
        { path: 'acl.enabled', action: 'set', value: true }
      );
    }

    // Check default policy
    if (acl.default_policy === 'allow') {
      this.addFinding(
        'High',
        'Access Control',
        'ACL default policy is set to "allow"',
        'Set acl.default_policy to "deny" and explicitly allow required operations',
        'acl.default_policy',
        ['AC-3', 'CM-7', 'CM-6'],
        'NIST SP 800-204B advocates for deny-by-default access control policies in line with zero trust principles. A default policy of "allow" contradicts this principle by permitting all actions unless explicitly denied.',
        { path: 'acl.default_policy', action: 'set', value: 'deny' }
      );
    }

    // Check for token configuration
    const tokens = acl.tokens || {};
    if (!tokens.agent || tokens.agent === '') {
      this.addFinding(
        'High',
        'Access Control',
        'Agent token is not configured',
        'Set a specific agent token with appropriate permissions',
        'acl.tokens.agent',
        ['IA-2', 'IA-5', 'AC-3'],
        'NIST SP 800-204A emphasizes the importance of properly configured service identity. Without a configured agent token, Consul agents may use the anonymous token or other default credentials.'
      );
    }

    if (!tokens.default || tokens.default === '') {
      this.addFinding(
        'Medium',
        'Access Control',
        'Default token is not configured',
        'Set a specific default token with minimal permissions',
        'acl.tokens.default',
        ['IA-5', 'AC-3', 'CM-6'],
        'NIST SP 800-204B recommends restricting default access. An unconfigured default token may fall back to using anonymous access or default permissions that are too permissive.'
      );
    }
  }

  private checkTelemetry(config: ConsulConfig): void {
    const telemetry = config.telemetry || {};

    if (telemetry.enable_service_metrics !== true) {
      this.addFinding(
        'Medium',
        'Monitoring',
        'Service metrics are not enabled',
        'Enable telemetry.enable_service_metrics for security monitoring and incident detection',
        'telemetry.enable_service_metrics',
        ['SI-4', 'AU-2', 'AU-12'],
        'NIST SP 800-53 Rev. 5 requires monitoring information systems to detect attacks.',
        { path: 'telemetry.enable_service_metrics', action: 'set', value: true }
      );
    }
  }

  private checkAutoEncrypt(config: ConsulConfig): void {
    const autoEncrypt = config.auto_encrypt || {};

    if (autoEncrypt.tls !== true) {
      this.addFinding(
        'Medium',
        'Encryption',
        'Auto-encrypt feature is not enabled for TLS',
        'Enable auto_encrypt.tls for automatic TLS certificate distribution',
        'auto_encrypt.tls',
        ['SC-8', 'SC-12', 'SC-13'],
        'NIST SP 800-204B recommends automatic certificate distribution for service mesh deployments.',
        { path: 'auto_encrypt.tls', action: 'set', value: true }
      );
    }
  }

  private checkAutoConfig(config: ConsulConfig): void {
    const autoConfig = config.auto_config || {};

    if (autoConfig.enabled !== true) {
      this.addFinding(
        'Low',
        'Configuration Management',
        'Auto-config feature is not enabled',
        'Consider enabling auto_config.enabled for secure configuration management',
        'auto_config.enabled',
        ['CM-2', 'CM-6'],
        'NIST SP 800-53 Rev. 5 requires configuration management for information systems.'
      );
    }

    if (autoConfig.authorization && autoConfig.authorization.enabled !== true) {
      this.addFinding(
        'Medium',
        'Authorization',
        'Auto-config authorization is not enabled',
        'Enable auto_config.authorization.enabled for secure auto-config',
        'auto_config.authorization.enabled',
        ['AC-3', 'IA-2'],
        'NIST SP 800-204B recommends implementing authorization for all configuration management interfaces.'
      );
    }
  }

  private checkGossipEncryption(config: ConsulConfig): void {
    const gossip = config.gossip || {};

    if (!gossip.encryption || !gossip.encryption.key) {
      this.addFinding(
        'Critical',
        'Gossip Security',
        'Gossip encryption key is not configured',
        'Configure gossip.encryption.key to encrypt Consul gossip protocol communications',
        'gossip.encryption.key',
        ['SC-8', 'SC-12', 'SC-13'],
        'NIST SP 800-53 Rev. 5 requires the protection of transmitted information (SC-8). According to NIST SP 800-204B, inter-node communications like gossip protocols must be encrypted to prevent eavesdropping and tampering.'
      );
    } else if (gossip.encryption.key.length < 32) {
      this.addFinding(
        'High',
        'Gossip Security',
        'Gossip encryption key may be too short',
        'Use a strong encryption key of at least 32 characters for gossip encryption',
        'gossip.encryption.key',
        ['SC-12', 'SC-13', 'IA-5'],
        'NIST SP 800-57 ("Recommendation for Key Management") provides guidelines for cryptographic key length. Short encryption keys can be vulnerable to brute force attacks.'
      );
    }

    if (gossip.verify_incoming !== true || gossip.verify_outgoing !== true) {
      this.addFinding(
        'High',
        'Gossip Security',
        'Gossip message verification is not fully enabled',
        'Enable both gossip.verify_incoming and gossip.verify_outgoing for secure cluster communication',
        'gossip.verify_incoming/outgoing',
        ['SC-8', 'SC-23', 'IA-2'],
        'NIST SP 800-53 Rev. 5 (SC-8) requires the protection of transmission integrity. Without message verification, an attacker could potentially inject malicious gossip messages into the cluster.'
      );
    }
  }

  private checkFedRAMPCompliance(config: ConsulConfig): void {
    const connect = config.connect || {};
    const caConfig = connect.ca_config || {};
    const tls = config.tls || {};
    const acl = config.acl || {};

    // Check for strong TLS ciphers
    if (!tls.cipher_suites || tls.cipher_suites.length === 0) {
      this.addFinding(
        'High',
        'FedRAMP Compliance',
        'No explicit TLS cipher suites configured',
        'Explicitly configure FIPS-compliant cipher suites in tls.cipher_suites for FedRAMP compliance',
        'tls.cipher_suites',
        ['SC-8', 'SC-13', 'CM-6'],
        'NIST SP 800-52 Rev. 2 requires the use of specific cipher suites that provide adequate security. FedRAMP builds on this requirement by mandating FIPS 140-2 validated cryptographic modules.'
      );
    }

    // Check minimum TLS version
    if (!tls.min_version || tls.min_version < 'TLSv1.2') {
      this.addFinding(
        'Critical',
        'FedRAMP Compliance',
        'TLS minimum version not set to TLS 1.2 or higher',
        'Configure tls.min_version to "TLSv1.2" or higher for FedRAMP compliance',
        'tls.min_version',
        ['SC-8', 'SC-13', 'CM-6'],
        'NIST SP 800-52 Rev. 2 explicitly requires the use of TLS 1.2 or higher for all federal systems.',
        { path: 'tls.min_version', action: 'set', value: 'TLSv1.2' }
      );
    }

    // Check for secure bootstrap
    if (!config.secure_bootstrap || config.secure_bootstrap !== true) {
      this.addFinding(
        'High',
        'FedRAMP Compliance',
        'Secure bootstrapping is not enabled',
        'Enable secure_bootstrap for ensuring secure cluster initialization',
        'secure_bootstrap',
        ['CM-2', 'CM-6', 'SC-7', 'SC-8'],
        'NIST SP 800-53 Rev. 5 emphasizes the importance of secure system initialization.',
        { path: 'secure_bootstrap', action: 'set', value: true }
      );
    }

    // Check for certificate rotation settings
    if (!caConfig.rotation_period || !caConfig.rotate_cert_ttl) {
      this.addFinding(
        'Medium',
        'FedRAMP Compliance',
        'Certificate rotation settings not fully configured',
        'Configure connect.ca_config.rotation_period and rotate_cert_ttl for regular certificate rotation',
        'connect.ca_config.rotation_period',
        ['SC-12', 'IA-5', 'SC-13'],
        'NIST SP 800-57 mandates that cryptographic keys and certificates be rotated regularly to minimize the impact of potential compromises.'
      );
    }

    // Check for audit logging
    if (!config.audit || config.audit.enabled !== true) {
      this.addFinding(
        'Critical',
        'FedRAMP Compliance',
        'Audit logging is not enabled',
        'Enable audit.enabled for capturing security events required by FedRAMP',
        'audit.enabled',
        ['AU-2', 'AU-3', 'AU-12', 'SI-4'],
        'NIST SP 800-53 Rev. 5 requires comprehensive audit logging for security-relevant events. FedRAMP specifically mandates audit logging for all authentication and authorization decisions.',
        { path: 'audit.enabled', action: 'set', value: true }
      );
    }

    // Check service registration configuration
    if (config.services) {
      const services = Array.isArray(config.services)
        ? config.services
        : [config.services];

      services.forEach((service, index) => {
        if (service.connect && !service.connect.sidecar_service) {
          this.addFinding(
            'Medium',
            'FedRAMP Compliance',
            `Service "${service.name || index}" registered without sidecar proxy configuration`,
            'Configure connect.sidecar_service for all services to enforce mTLS',
            `services[${index}].connect.sidecar_service`,
            ['SC-8', 'SC-13'],
            'NIST SP 800-204B recommends using sidecar proxies for all services to ensure mTLS enforcement.'
          );
        }

        // Check proxy configuration for security
        if (
          service.connect &&
          service.connect.sidecar_service &&
          service.connect.sidecar_service.proxy
        ) {
          const proxy = service.connect.sidecar_service.proxy;

          if (
            proxy.local_service_address !== '127.0.0.1' &&
            proxy.local_service_address !== 'localhost'
          ) {
            this.addFinding(
              'High',
              'FedRAMP Compliance',
              `Service "${service.name || index}" proxy configured to non-localhost address`,
              'Set connect.sidecar_service.proxy.local_service_address to "127.0.0.1" for security',
              `services[${index}].connect.sidecar_service.proxy.local_service_address`,
              ['SC-7', 'AC-4'],
              'NIST SP 800-53 Rev. 5 requires boundary protection. Proxies should only bind to localhost to prevent unauthorized direct access to services.'
            );
          }
        }
      });
    }

    // FedRAMP requires explicit settings for default policies
    if (acl.default_policy !== 'deny') {
      this.addFinding(
        'Critical',
        'FedRAMP Compliance',
        'ACL default policy is not set to "deny"',
        'Set acl.default_policy to "deny" for FedRAMP compliance (zero-trust model)',
        'acl.default_policy',
        ['AC-3', 'CM-7'],
        'FedRAMP requires zero-trust architecture with deny-by-default access control.'
      );
    }
  }
}
