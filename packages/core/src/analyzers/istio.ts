import { BaseSecurityAnalyzer } from './base.js';
import type { Finding, IstioConfig } from '../types.js';

/**
 * Security analyzer for Istio service mesh configurations
 */
export class IstioSecurityAnalyzer extends BaseSecurityAnalyzer {
  analyze(config: unknown): Finding[] {
    this.reset();

    const istioConfig = config as IstioConfig;

    // Analyze overall structure
    if (!istioConfig) {
      this.addFinding(
        'Critical',
        'File Format',
        'Invalid or empty configuration file',
        'Provide a valid Istio MeshConfig'
      );
      return this.getFindings();
    }

    // Check if it's a valid Istio resource
    if (!istioConfig.kind || !istioConfig.apiVersion) {
      this.addFinding(
        'Critical',
        'Resource Type',
        'File is not a valid Kubernetes resource',
        'Ensure the file has apiVersion and kind fields'
      );
      return this.getFindings();
    }

    // Check MeshConfig type
    if (istioConfig.kind !== 'MeshConfig') {
      this.addFinding(
        'Critical',
        'Resource Type',
        `Expected MeshConfig but found ${istioConfig.kind}`,
        'Use a valid Istio MeshConfig resource'
      );
      return this.getFindings();
    }

    // Run security checks
    this.checkMTLS(istioConfig);
    this.checkRootCertificates(istioConfig);
    this.checkPeerAuthentication(istioConfig);
    this.checkProxyConfig(istioConfig);
    this.checkSDS(istioConfig);
    this.checkTrustDomain(istioConfig);
    this.checkAuthorizationPolicies(istioConfig);
    this.checkTelemetry(istioConfig);
    this.checkRBAC(istioConfig);
    this.checkOutboundTrafficPolicy(istioConfig);

    return this.getFindings();
  }

  private checkMTLS(config: IstioConfig): void {
    // Check if mTLS is enabled
    if (!config.meshMTLS || !config.meshMTLS.enabled) {
      this.addFinding(
        'High',
        'mTLS',
        'Mesh-wide mTLS is not enabled',
        'Enable mesh-wide mTLS for service-to-service communication security',
        'meshMTLS.enabled',
        ['SC-8', 'SC-13', 'IA-5', 'SC-23'],
        'NIST SP 800-204B recommends implementing mutual TLS for service-to-service communications. Without mTLS, traffic between services may be intercepted or tampered with, leading to unauthorized access or data exfiltration. According to NIST, "implementations must ensure protection of data in transit through the use of encryption techniques" and "credentials used for service identity should be automatically rotated frequently."',
        { path: 'meshMTLS.enabled', action: 'set', value: true }
      );
    }

    // Check mTLS mode (STRICT is most secure)
    if (config.meshMTLS && config.meshMTLS.mode !== 'STRICT') {
      this.addFinding(
        'Medium',
        'mTLS',
        `mTLS mode is set to ${config.meshMTLS.mode || 'PERMISSIVE'} instead of STRICT`,
        'Use STRICT mode for mTLS to ensure all traffic is encrypted',
        'meshMTLS.mode',
        ['SC-8', 'CM-6', 'CM-7'],
        'NIST SP 800-204A states that permissive mode should only be used during transition periods. NIST recommends enforcing strict mTLS mode to ensure all service-to-service communication is encrypted and authenticated. Running in permissive mode allows unencrypted traffic to flow within the mesh, potentially exposing sensitive data and allowing for man-in-the-middle attacks.',
        { path: 'meshMTLS.mode', action: 'set', value: 'STRICT' }
      );
    }
  }

  private checkRootCertificates(config: IstioConfig): void {
    const ca = config.ca || {};

    if (!ca.provider || ca.provider === 'istiod') {
      this.addFinding(
        'Medium',
        'Certificate Authority',
        'Using default istiod CA instead of a custom CA',
        'Consider using a production-grade external CA for production environments',
        'ca.provider',
        ['SC-12', 'IA-5', 'SC-13'],
        'NIST SP 800-204B recommends using a robust certificate authority infrastructure for production environments. According to NIST SP 800-57, "cryptographic keys require protection throughout their lifecycle." The default istiod CA may lack the security controls and processes required for high-security environments, including regular key rotation, hardware security modules (HSMs), and formal certificate lifecycle management expected in production deployments.'
      );
    }

    if (!ca.certValidityDuration) {
      this.addFinding(
        'Low',
        'Certificate Validity',
        'Certificate validity duration not specified',
        'Set appropriate cert validity periods based on your security policies',
        'ca.certValidityDuration',
        ['IA-5', 'SC-12'],
        'NIST SP 800-57 ("Recommendation for Key Management") specifies that certificates should have appropriate validity periods that balance security with operational overhead. Not specifying certificate validity durations may result in default values that are either too short (causing operational disruptions) or too long (increasing the risk of compromise). NIST recommends explicitly defining certificate lifetimes as part of a comprehensive key management policy.'
      );
    } else if (parseInt(ca.certValidityDuration) > 8760) {
      // More than a year
      this.addFinding(
        'Medium',
        'Certificate Validity',
        'Long certificate validity period detected',
        'Consider shorter certificate validity periods (e.g., 90 days) for better security',
        'ca.certValidityDuration',
        ['IA-5', 'SC-12'],
        'NIST SP 800-204B suggests frequent rotation of certificates for service mesh identities. According to NIST SP 800-57, "the longer a key is in use, the greater the potential for key compromise." Certificates with validity periods longer than one year provide attackers with an extended window of opportunity if keys are compromised. NIST recommends shorter validity periods with automatic rotation to minimize risk while maintaining operational continuity.'
      );
    }
  }

  private checkPeerAuthentication(config: IstioConfig): void {
    if (!config.peerAuthentication || !config.peerAuthentication.mode) {
      this.addFinding(
        'High',
        'Authentication',
        'No default peer authentication policy defined',
        'Define a default peer authentication policy with strict mTLS',
        'peerAuthentication',
        ['IA-2', 'SC-8', 'SC-23', 'AC-17'],
        'NIST SP 800-204A emphasizes the importance of strong authentication between services. NIST SP 800-204B specifically states: "A service mesh should enforce authentication of peer microservices... to ensure that only legitimate services are communicating within the mesh." Without a default peer authentication policy, services may not properly authenticate each other, allowing potential impersonation attacks and unauthorized access to sensitive information.'
      );
    } else if (config.peerAuthentication.mode !== 'STRICT') {
      this.addFinding(
        'Medium',
        'Authentication',
        `Peer authentication mode is set to ${config.peerAuthentication.mode} instead of STRICT`,
        'Use STRICT mode for peer authentication to ensure all traffic is authenticated',
        'peerAuthentication.mode',
        ['IA-2', 'SC-8', 'CM-6', 'AC-3'],
        'NIST SP 800-204A recommends using strict authentication policies in service mesh implementations. According to NIST, "all network communication should require mutually authenticated TLS." Non-strict modes allow for unauthenticated traffic, which creates security vulnerabilities and inconsistent policy enforcement across the mesh. NIST SP 800-204B specifically notes that permissive mode should only be used temporarily during migration periods.',
        { path: 'peerAuthentication.mode', action: 'set', value: 'STRICT' }
      );
    }
  }

  private checkProxyConfig(config: IstioConfig): void {
    const proxyConfig = config.defaultConfig || {};

    // Check privileged mode
    if (proxyConfig.privileged === true) {
      this.addFinding(
        'High',
        'Proxy Configuration',
        'Proxies are running in privileged mode',
        'Avoid running proxies in privileged mode unless absolutely necessary',
        'defaultConfig.privileged',
        ['CM-7', 'AC-6'],
        'NIST SP 800-53 Rev. 5 emphasizes the principle of least privilege. Running proxies in privileged mode grants them unnecessary permissions that could be exploited if the proxy is compromised.',
        { path: 'defaultConfig.privileged', action: 'set', value: false }
      );
    }

    // Check proxy image version
    if (proxyConfig.image && proxyConfig.image.includes(':')) {
      const version = proxyConfig.image.split(':')[1];
      if (version === 'latest' || version === 'master') {
        this.addFinding(
          'Medium',
          'Proxy Configuration',
          `Using non-specific proxy image version: ${version}`,
          'Use specific, pinned versions of proxy images',
          'defaultConfig.image',
          ['CM-2', 'CM-6'],
          'NIST SP 800-53 Rev. 5 requires establishing baseline configurations. Using non-specific image tags can result in unexpected updates that may introduce security issues.'
        );
      }
    }

    // Check if holdApplicationUntilProxyStarts is set
    if (proxyConfig.holdApplicationUntilProxyStarts !== true) {
      this.addFinding(
        'Medium',
        'Proxy Configuration',
        'Applications may start before proxy initialization is complete',
        'Set holdApplicationUntilProxyStarts to true to prevent traffic leaks',
        'defaultConfig.holdApplicationUntilProxyStarts',
        ['CM-7', 'SC-7', 'AC-4', 'SC-8'],
        'NIST SP 800-53 Rev. 5 (CM-7) requires implementing the principle of least functionality. According to NIST SP 800-204B, a service mesh must ensure that all traffic is intercepted by the proxy. When applications start before the proxy is ready, traffic can bypass the mesh controls, creating a potential security gap. This violates traffic flow enforcement (AC-4) and boundary protection (SC-7) requirements, as unencrypted traffic might leave the pod without proper controls or encryption.',
        {
          path: 'defaultConfig.holdApplicationUntilProxyStarts',
          action: 'set',
          value: true,
        }
      );
    }
  }

  private checkSDS(config: IstioConfig): void {
    const proxyConfig = config.defaultConfig || {};

    if (!proxyConfig.sds || !proxyConfig.sds.enabled) {
      this.addFinding(
        'Medium',
        'Secret Discovery Service',
        'SDS is not enabled for certificate management',
        'Enable SDS for secure certificate distribution and rotation',
        'defaultConfig.sds.enabled',
        ['SC-12', 'IA-5', 'SC-8', 'SC-13'],
        'NIST SP 800-53 Rev. 5 (SC-12) requires proper cryptographic key establishment and management. The Secret Discovery Service (SDS) is a critical component for secure certificate distribution in service meshes. Without SDS, certificate handling is less secure and requires manual management. NIST SP 800-57 specifies that cryptographic materials should be securely provisioned and rotated. SDS enables automatic certificate distribution and rotation, minimizing exposure of sensitive key material and simplifying compliance with authenticator management requirements (IA-5).',
        { path: 'defaultConfig.sds.enabled', action: 'set', value: true }
      );
    }
  }

  private checkTrustDomain(config: IstioConfig): void {
    if (!config.trustDomain) {
      this.addFinding(
        'Medium',
        'Trust Domain',
        'Trust domain not explicitly configured',
        'Set a specific trust domain for your mesh to isolate identities',
        'trustDomain',
        ['IA-2', 'IA-5', 'AC-3', 'SC-16'],
        'NIST SP 800-53 Rev. 5 (IA-2) requires proper identification of system users and processes. In service meshes, the trust domain is foundational for service identity and authentication. According to NIST SP 800-204B, service mesh implementations must establish trust boundaries. Without an explicitly configured trust domain, services may not be properly isolated, potentially allowing identity spoofing across different security contexts. NIST SP 800-204A emphasizes that service identities must be bound to specific security domains, which requires explicit trust domain configuration.'
      );
    } else if (config.trustDomain === 'cluster.local') {
      this.addFinding(
        'Low',
        'Trust Domain',
        'Using default trust domain (cluster.local)',
        'Consider setting a custom trust domain specific to your organization',
        'trustDomain',
        ['IA-2', 'IA-5', 'AC-16'],
        'NIST SP 800-53 Rev. 5 (AC-16) requires implementing security attributes for information and resources. Using the default trust domain (cluster.local) rather than a customized domain specific to your organization reduces the ability to uniquely identify and isolate your mesh. NIST SP 800-204B recommends using organization-specific trust domains to prevent potential identity conflicts when interacting with external meshes and to establish clear security boundaries between different organizational domains.'
      );
    }
  }

  private checkAuthorizationPolicies(config: IstioConfig): void {
    if (
      !config.defaultAuthorizationPolicy ||
      config.defaultAuthorizationPolicy.action !== 'DENY'
    ) {
      this.addFinding(
        'High',
        'Authorization',
        'No default deny policy is configured at mesh level',
        'Configure a default DENY policy and explicitly allow required traffic',
        'defaultAuthorizationPolicy',
        ['AC-3', 'AC-4', 'CM-7'],
        'NIST SP 800-204B explicitly recommends implementing authorization policies to control service-to-service communication. According to NIST, "authorization policies provide a more secure deployment by limiting which services can communicate with each other." Without a default deny policy, any authenticated service can access any other service in the mesh, violating the principle of least privilege.'
      );
    }
  }

  private checkTelemetry(config: IstioConfig): void {
    const telemetry = config.telemetry || {};

    if (!telemetry.enabled) {
      this.addFinding(
        'Medium',
        'Telemetry',
        'Telemetry collection is disabled',
        'Enable telemetry for security monitoring and incident detection',
        'telemetry.enabled',
        ['AU-2', 'AU-12', 'SI-4', 'IR-4', 'IR-5'],
        'NIST SP 800-53 Rev. 5 (SI-4) requires information system monitoring capabilities. According to NIST SP 800-204B, telemetry data is essential for detecting anomalies and security incidents within service meshes. Without telemetry collection, security teams lack visibility into service behavior, traffic patterns, and potential security violations. NIST SP 800-53 Rev. 5 (IR-4 and IR-5) emphasize the importance of incident monitoring and tracking, which relies on telemetry data to identify and respond to security incidents in complex microservices environments.',
        { path: 'telemetry.enabled', action: 'set', value: true }
      );
    }

    if (!telemetry.accessLogging || !telemetry.accessLogging.enabled) {
      this.addFinding(
        'Medium',
        'Access Logging',
        'Access logging is not enabled',
        'Enable access logging for security auditing and forensics',
        'telemetry.accessLogging.enabled',
        ['AU-3', 'AU-12', 'AU-14', 'SI-4'],
        'NIST SP 800-53 Rev. 5 (AU-3) requires the system to generate audit records containing specific information about events. Access logging in service meshes is critical for capturing details about all service-to-service communications, including source and destination identities, request paths, and response codes. NIST SP 800-204A recommends capturing detailed logs for all service interactions. Without access logging, organizations cannot perform effective security analysis, forensic investigations, or demonstrate compliance with regulatory requirements that mandate audit trails of system access and activity.',
        { path: 'telemetry.accessLogging.enabled', action: 'set', value: true }
      );
    }
  }

  private checkRBAC(config: IstioConfig): void {
    if (!config.rbac || config.rbac.mode !== 'ON') {
      this.addFinding(
        'Critical',
        'RBAC',
        'RBAC enforcement is not enabled',
        'Enable RBAC to control service-to-service authorization',
        'rbac.mode',
        ['AC-3', 'AC-4', 'CM-7'],
        'NIST SP 800-204B explicitly recommends implementing authorization policies to control service-to-service communication. According to NIST, "authorization policies provide a more secure deployment by limiting which services can communicate with each other." Without RBAC, any authenticated service can access any other service in the mesh, violating the principle of least privilege. NIST SP 800-204A emphasizes that "authorization policies protect services against unauthorized access even from other services within the mesh."',
        { path: 'rbac.mode', action: 'set', value: 'ON' }
      );
    }
  }

  private checkOutboundTrafficPolicy(config: IstioConfig): void {
    const outboundTrafficPolicy = config.outboundTrafficPolicy || {};

    if (outboundTrafficPolicy.mode !== 'REGISTRY_ONLY') {
      this.addFinding(
        'High',
        'Traffic Policy',
        'Outbound traffic to external services is allowed by default',
        'Set outboundTrafficPolicy.mode to REGISTRY_ONLY to restrict external access',
        'outboundTrafficPolicy.mode',
        ['AC-4', 'SC-7', 'CM-7', 'CA-3'],
        'NIST SP 800-204B emphasizes the importance of controlling traffic flow in and out of the service mesh. According to NIST SP 800-207 (Zero Trust Architecture), "all resource access should be determined by policy" and "access to resources is granted on a per-session basis." Allowing unrestricted outbound traffic creates potential data exfiltration pathways and expands the attack surface by permitting connections to unauthorized external endpoints. This violates the principle of least functionality outlined in NIST SP 800-53 Rev. 5.',
        { path: 'outboundTrafficPolicy.mode', action: 'set', value: 'REGISTRY_ONLY' }
      );
    }
  }
}
