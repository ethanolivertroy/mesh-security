import { BaseSecurityAnalyzer } from './base.js';
import type { Finding, LinkerdConfig } from '../types.js';

/**
 * Security analyzer for Linkerd service mesh configurations
 */
export class LinkerdSecurityAnalyzer extends BaseSecurityAnalyzer {
  analyze(config: unknown): Finding[] {
    this.reset();

    const linkerdConfig = config as LinkerdConfig;

    // Analyze overall structure
    if (!linkerdConfig) {
      this.addFinding(
        'Critical',
        'File Format',
        'Invalid or empty configuration file',
        'Provide a valid Linkerd configuration'
      );
      return this.getFindings();
    }

    // Check if it's a Linkerd configuration
    if (linkerdConfig.mesh_type !== 'linkerd') {
      this.addFinding(
        'Critical',
        'Resource Type',
        'File is not a Linkerd service mesh configuration',
        'Ensure the file has mesh_type field set to "linkerd"'
      );
      return this.getFindings();
    }

    // Run security checks
    this.checkTLS(linkerdConfig);
    this.checkIdentity(linkerdConfig);
    this.checkProxyConfig(linkerdConfig);
    this.checkPolicy(linkerdConfig);
    this.checkAuthenticationPolicy(linkerdConfig);
    this.checkTracing(linkerdConfig);
    this.checkMetrics(linkerdConfig);
    this.checkDestinationRules(linkerdConfig);

    return this.getFindings();
  }

  private checkTLS(config: LinkerdConfig): void {
    const tls = config.tls || {};

    if (!tls.enabled) {
      this.addFinding(
        'Critical',
        'TLS Security',
        'TLS is not enabled for the mesh',
        'Enable TLS for secure service-to-service communication',
        'tls.enabled',
        ['SC-8', 'SC-13', 'IA-5', 'SC-23'],
        'NIST SP 800-204B recommends implementing Transport Layer Security for service-to-service communications. Without TLS, traffic between services is transmitted in plaintext and may be intercepted or tampered with.',
        { path: 'tls.enabled', action: 'set', value: true }
      );
    }

    if (tls.enabled && !tls.enforced) {
      this.addFinding(
        'High',
        'TLS Security',
        'TLS is enabled but not enforced (PERMISSIVE mode)',
        'Enable TLS enforcement to ensure all traffic is encrypted',
        'tls.enforced',
        ['SC-8', 'CM-6', 'CM-7'],
        'NIST SP 800-204A recommends enforcing TLS for all service communications. Permissive mode allows unencrypted traffic to flow within the mesh.',
        { path: 'tls.enforced', action: 'set', value: true }
      );
    }

    if (tls.cipherSuites) {
      const weakCiphers = tls.cipherSuites.filter(
        (cipher) =>
          cipher.includes('NULL') ||
          cipher.includes('EXPORT') ||
          cipher.includes('DES') ||
          cipher.includes('RC4') ||
          cipher.includes('MD5')
      );

      if (weakCiphers.length > 0) {
        this.addFinding(
          'Critical',
          'TLS Security',
          'Weak TLS cipher suites configured: ' + weakCiphers.join(', '),
          'Remove weak cipher suites and use only strong, modern ciphers',
          'tls.cipherSuites',
          ['SC-8', 'SC-13', 'CM-6'],
          'NIST SP 800-52 Rev. 2 explicitly prohibits the use of known weak cipher suites. These deprecated algorithms have known vulnerabilities and can be exploited to decrypt traffic.'
        );
      }
    }

    if (!tls.minimumVersion || tls.minimumVersion < 'TLSv1.2') {
      this.addFinding(
        'High',
        'TLS Security',
        'TLS minimum version is set below TLS 1.2',
        'Configure minimum TLS version to 1.2 or higher',
        'tls.minimumVersion',
        ['SC-8', 'SC-13', 'CM-6'],
        'NIST SP 800-52 Rev. 2 requires the use of TLS 1.2 or higher for all government systems. Earlier versions of TLS have known vulnerabilities.',
        { path: 'tls.minimumVersion', action: 'set', value: 'TLSv1.2' }
      );
    }
  }

  private checkIdentity(config: LinkerdConfig): void {
    const identity = config.identity || {};

    if (!identity.enabled) {
      this.addFinding(
        'Critical',
        'Service Identity',
        'Service identity feature is not enabled',
        'Enable the identity feature to allow secure service-to-service authentication',
        'identity.enabled',
        ['IA-2', 'IA-5', 'SC-8'],
        'NIST SP 800-204B emphasizes the importance of strong identity for components within service mesh architectures. Without service identity, the mesh cannot securely authenticate services.',
        { path: 'identity.enabled', action: 'set', value: true }
      );
    }

    // Check certificate issuer settings
    if (identity.issuer === 'self-signed') {
      this.addFinding(
        'Medium',
        'Certificate Authority',
        'Using self-signed certificates for service identity',
        'Consider using an external certificate authority for production environments',
        'identity.issuer',
        ['SC-12', 'IA-5'],
        'NIST SP 800-57 provides guidelines for cryptographic key management and recommends using proper certificate authorities in production environments.'
      );
    }

    if (identity.certValidityPeriod && identity.certValidityPeriod > 8760) {
      // More than a year in hours
      this.addFinding(
        'Medium',
        'Certificate Security',
        'Certificate validity period is set to a long duration',
        'Reduce certificate validity period for better security',
        'identity.certValidityPeriod',
        ['IA-5', 'SC-12'],
        'NIST SP 800-57 recommends shorter certificate validity periods with automatic rotation to minimize risk.'
      );
    }

    if (!identity.trustAnchorsPEM || identity.trustAnchorsPEM.length === 0) {
      this.addFinding(
        'High',
        'Trust Chain',
        'No trust anchors configured for the identity system',
        'Configure proper trust anchors to validate service identities',
        'identity.trustAnchorsPEM',
        ['IA-5', 'SC-12'],
        'NIST SP 800-57 requires proper trust anchors for certificate validation. Without configured trust anchors, the system cannot verify service identities.'
      );
    }
  }

  private checkProxyConfig(config: LinkerdConfig): void {
    const proxy = config.proxy || {};

    if (proxy.privileged === true) {
      this.addFinding(
        'High',
        'Proxy Security',
        'Proxies are configured to run in privileged mode',
        'Avoid running proxies with privileged access unless absolutely necessary',
        'proxy.privileged',
        ['CM-7', 'AC-3', 'AC-6'],
        'NIST SP 800-53 Rev. 5 emphasizes the principle of least privilege. Running proxies in privileged mode grants them unnecessary permissions.',
        { path: 'proxy.privileged', action: 'set', value: false }
      );
    }

    if (proxy.image && proxy.image.includes(':latest')) {
      this.addFinding(
        'Medium',
        'Image Security',
        'Using :latest tag for proxy image instead of a specific version',
        'Pin to specific proxy image versions for stability and security',
        'proxy.image',
        ['CM-2', 'CM-6'],
        'NIST SP 800-53 Rev. 5 requires establishing baseline configurations. Using the :latest tag can result in unexpected proxy updates.'
      );
    }

    if (!proxy.outboundConnectTimeout) {
      this.addFinding(
        'Low',
        'Proxy Configuration',
        'No outbound connection timeout configured',
        'Set reasonable timeout values to limit the impact of connectivity issues',
        'proxy.outboundConnectTimeout',
        ['SI-4', 'SC-5', 'SC-6'],
        'NIST SP 800-53 Rev. 5 recommends configurations that limit the impact of potential denial of service conditions.'
      );
    }

    // Check resource limits
    if (!proxy.resources || !proxy.resources.cpu || !proxy.resources.memory) {
      this.addFinding(
        'Medium',
        'Resource Management',
        'Resource limits not fully configured for proxies',
        'Set appropriate CPU and memory limits for all proxies',
        'proxy.resources',
        ['SC-6', 'CM-2', 'CM-6'],
        'NIST SP 800-53 Rev. 5 (SC-6) requires resource availability protection. Without defined resource limits, proxies may consume excessive resources.'
      );
    }
  }

  private checkPolicy(config: LinkerdConfig): void {
    const policy = config.policy || {};

    if (!policy.enabled) {
      this.addFinding(
        'High',
        'Authorization',
        'Policy enforcement is not enabled',
        'Enable policy enforcement to control service-to-service communication',
        'policy.enabled',
        ['AC-3', 'AC-4', 'CM-7'],
        'NIST SP 800-204B recommends implementing authorization policies to control service-to-service communication.',
        { path: 'policy.enabled', action: 'set', value: true }
      );
    }

    if (policy.enabled && !policy.defaultDeny) {
      this.addFinding(
        'Medium',
        'Authorization',
        'Default allow policy is in effect',
        'Configure a default deny policy and explicitly allow required traffic',
        'policy.defaultDeny',
        ['AC-3', 'CM-7', 'AC-4'],
        'NIST SP 800-204A recommends a deny-by-default approach aligned with zero trust architecture principles.',
        { path: 'policy.defaultDeny', action: 'set', value: true }
      );
    }

    if (
      policy.enabled &&
      policy.serverPolicies &&
      policy.serverPolicies.length === 0
    ) {
      this.addFinding(
        'Medium',
        'Authorization',
        'No server policies defined despite policy enforcement being enabled',
        'Define specific server policies to control which clients can access each service',
        'policy.serverPolicies',
        ['AC-3', 'AC-4', 'AC-5', 'CM-7'],
        'NIST SP 800-53 Rev. 5 requires implementing access controls that restrict which resources can be accessed.'
      );
    }

    // Check for policy consistency
    if (
      policy.enabled &&
      policy.serverPolicies &&
      policy.serverPolicies.length > 0
    ) {
      // Check for overly permissive policies
      const permissivePolicies = policy.serverPolicies.filter(
        (p) =>
          p.clients && p.clients.some((c) => !c.namespace || c.namespace === '*')
      );

      if (permissivePolicies.length > 0) {
        this.addFinding(
          'Medium',
          'Authorization',
          'Overly permissive server policies detected',
          'Avoid wildcard namespace selectors in policy definitions',
          'policy.serverPolicies[].clients[].namespace',
          ['AC-3', 'AC-6', 'CM-7'],
          'NIST SP 800-53 Rev. 5 (AC-6) requires implementing the principle of least privilege. Policies with wildcard namespace selectors allow access from any namespace.'
        );
      }
    }
  }

  private checkAuthenticationPolicy(config: LinkerdConfig): void {
    const authn = config.authentication || {};

    if (!authn.enabled) {
      this.addFinding(
        'Critical',
        'Authentication',
        'Authentication policy enforcement is not enabled',
        'Enable authentication to verify service identities',
        'authentication.enabled',
        ['IA-2', 'IA-5', 'SC-8'],
        'NIST SP 800-204A emphasizes the importance of strong authentication between services.',
        { path: 'authentication.enabled', action: 'set', value: true }
      );
    }

    if (authn.enabled && authn.mode !== 'strict') {
      this.addFinding(
        'High',
        'Authentication',
        'Authentication mode is not set to strict',
        'Use strict authentication mode to require authentication for all traffic',
        'authentication.mode',
        ['IA-2', 'SC-8', 'CM-6'],
        'NIST SP 800-204B emphasizes that authentication policies should be strictly enforced. Non-strict modes allow unauthenticated traffic.',
        { path: 'authentication.mode', action: 'set', value: 'strict' }
      );
    }
  }

  private checkTracing(config: LinkerdConfig): void {
    const tracing = config.tracing || {};

    if (!tracing.enabled) {
      this.addFinding(
        'Medium',
        'Observability',
        'Distributed tracing is not enabled',
        'Enable tracing for better security monitoring and incident response',
        'tracing.enabled',
        ['AU-2', 'AU-3', 'SI-4'],
        'NIST SP 800-53 Rev. 5 requires monitoring information systems to detect and analyze attacks. Distributed tracing provides valuable data for security monitoring.'
      );
    }

    if (tracing.enabled && !tracing.sampling) {
      this.addFinding(
        'Low',
        'Observability',
        'Tracing sampling rate not configured',
        'Configure sampling rate to balance observability with performance',
        'tracing.sampling',
        ['AU-2', 'CM-6', 'AU-12'],
        'NIST SP 800-53 Rev. 5 recommends configuring auditing to capture sufficient data while minimizing operational impact.'
      );
    }

    // Check collector configuration
    if (tracing.enabled && (!tracing.collector || !tracing.collector.service)) {
      this.addFinding(
        'Medium',
        'Observability',
        'Tracing collector service not configured',
        'Configure a tracing collector service to capture distributed traces',
        'tracing.collector.service',
        ['AU-3', 'AU-12', 'SI-4'],
        'NIST SP 800-53 Rev. 5 (AU-3) requires that audit records contain information to establish what events occurred. Without a properly configured tracing collector, trace data will not be captured.'
      );
    }
  }

  private checkMetrics(config: LinkerdConfig): void {
    const metrics = config.metrics || {};

    if (!metrics.enabled) {
      this.addFinding(
        'Medium',
        'Observability',
        'Metrics collection is not enabled',
        'Enable metrics for monitoring and detecting security anomalies',
        'metrics.enabled',
        ['SI-4', 'AU-2', 'AU-12'],
        'NIST SP 800-53 Rev. 5 requires monitoring information systems to detect attacks. Metrics provide critical data for detecting anomalies.'
      );
    }

    if (metrics.enabled && (!metrics.prometheus || !metrics.prometheus.enabled)) {
      this.addFinding(
        'Low',
        'Observability',
        'Prometheus metrics endpoint not enabled',
        'Enable Prometheus metrics for integration with security monitoring systems',
        'metrics.prometheus.enabled',
        ['SI-4', 'AU-2', 'AU-6'],
        'NIST SP 800-53 Rev. 5 recommends monitoring capabilities that can integrate with enterprise security monitoring.'
      );
    }

    // Check metrics retention
    if (
      metrics.enabled &&
      (!metrics.retention || parseInt(metrics.retention) < 4)
    ) {
      const retentionTime = metrics.retention ? metrics.retention : 'not configured';
      this.addFinding(
        'Low',
        'Observability',
        `Metrics retention period (${retentionTime}) may be insufficient for security analysis`,
        'Configure metrics retention period of at least 24h for security analysis purposes',
        'metrics.retention',
        ['AU-4', 'AU-11', 'SI-4'],
        'NIST SP 800-53 Rev. 5 (AU-11) requires organizations to retain audit records for a specific period.'
      );
    }
  }

  private checkDestinationRules(config: LinkerdConfig): void {
    const destinationRules = config.destinationRules || [];

    // Check for destination rules without TLS settings
    const rulesWithoutTLS = destinationRules.filter(
      (rule) => !rule.tls || !rule.tls.mode
    );
    if (rulesWithoutTLS.length > 0) {
      this.addFinding(
        'Medium',
        'Traffic Security',
        `${rulesWithoutTLS.length} destination rules found without TLS configuration`,
        'Configure TLS settings for all destination rules',
        'destinationRules[].tls',
        ['SC-8', 'CM-6', 'SC-13'],
        'NIST SP 800-204B emphasizes the importance of protecting data in transit. Destination rules without TLS settings may allow unencrypted traffic.'
      );
    }

    // Check for rules using plaintext mode
    const plaintextRules = destinationRules.filter(
      (rule) => rule.tls && rule.tls.mode === 'DISABLE'
    );
    if (plaintextRules.length > 0) {
      this.addFinding(
        'High',
        'Traffic Security',
        `${plaintextRules.length} destination rules explicitly disable TLS`,
        'Avoid disabling TLS in destination rules',
        'destinationRules[].tls.mode',
        ['SC-8', 'SC-13', 'CM-7', 'SC-23'],
        'NIST SP 800-53 Rev. 5 (SC-8) requires the protection of transmission confidentiality and integrity. Explicitly disabling TLS creates gaps in the security posture.'
      );
    }

    // Check for rules with system namespaces that should be protected
    const systemNamespaceRules = destinationRules.filter(
      (rule) =>
        rule.host &&
        (rule.host.includes('kube-system') ||
          rule.host.includes('istio-system') ||
          rule.host.includes('linkerd-') ||
          rule.host.includes('consul-')) &&
        (!rule.tls || rule.tls.mode === 'DISABLE')
    );

    if (systemNamespaceRules.length > 0) {
      this.addFinding(
        'Critical',
        'System Security',
        `${systemNamespaceRules.length} destination rules disable or omit TLS for system namespaces`,
        'Always enforce TLS for system namespaces to protect critical control plane services',
        'destinationRules[].host',
        ['SC-8', 'AC-3', 'SC-23', 'CM-7'],
        'NIST SP 800-53 Rev. 5 (AC-3) requires the enforcement of approved authorizations for access to system services. System namespaces contain critical control plane components.'
      );
    }
  }
}
