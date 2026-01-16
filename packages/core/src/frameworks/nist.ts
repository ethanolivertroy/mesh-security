import type { NistControl } from '../types.js';

/**
 * NIST 800-53 Rev 5 Controls relevant to service mesh security
 */
export const NIST_CONTROLS: Record<string, NistControl> = {
  'AC-3': {
    id: 'AC-3',
    title: 'Access Enforcement',
    description:
      'The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.',
  },
  'AC-4': {
    id: 'AC-4',
    title: 'Information Flow Enforcement',
    description:
      'The information system enforces approved authorizations for controlling the flow of information within the system and between connected systems based on applicable information flow control policies.',
  },
  'AC-6': {
    id: 'AC-6',
    title: 'Least Privilege',
    description:
      'The organization employs the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions.',
  },
  'AC-16': {
    id: 'AC-16',
    title: 'Security Attributes',
    description:
      'The organization provides the means to associate types of information with specific security attributes.',
  },
  'AC-17': {
    id: 'AC-17',
    title: 'Remote Access',
    description:
      'The organization establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed.',
  },
  'AU-2': {
    id: 'AU-2',
    title: 'Audit Events',
    description:
      'The information system generates audit records containing information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.',
  },
  'AU-3': {
    id: 'AU-3',
    title: 'Content of Audit Records',
    description:
      'The information system generates audit records containing information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.',
  },
  'AU-4': {
    id: 'AU-4',
    title: 'Audit Storage Capacity',
    description:
      'The organization allocates audit record storage capacity in accordance with audit record storage requirements.',
  },
  'AU-6': {
    id: 'AU-6',
    title: 'Audit Review, Analysis, and Reporting',
    description:
      'The organization reviews and analyzes information system audit records for indications of inappropriate or unusual activity.',
  },
  'AU-11': {
    id: 'AU-11',
    title: 'Audit Record Retention',
    description:
      'The organization retains audit records for a specified period to provide support for after-the-fact investigations of security incidents.',
  },
  'AU-12': {
    id: 'AU-12',
    title: 'Audit Generation',
    description:
      'The information system provides audit record generation capability for the auditable events defined in AU-2 a. at all information system components where audit capability is deployed.',
  },
  'AU-14': {
    id: 'AU-14',
    title: 'Session Audit',
    description:
      'The information system provides the capability for authorized users to select a user session to capture/record or view/hear.',
  },
  'CA-3': {
    id: 'CA-3',
    title: 'System Interconnections',
    description:
      'The organization authorizes connections from the information system to other information systems through the use of Interconnection Security Agreements and monitors the system connections on an ongoing basis.',
  },
  'CM-2': {
    id: 'CM-2',
    title: 'Baseline Configuration',
    description:
      'The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system.',
  },
  'CM-6': {
    id: 'CM-6',
    title: 'Configuration Settings',
    description:
      'The organization establishes and documents configuration settings for information technology products employed within the information system that reflect the most restrictive mode consistent with operational requirements.',
  },
  'CM-7': {
    id: 'CM-7',
    title: 'Least Functionality',
    description:
      'The organization configures the information system to provide only essential capabilities and specifically prohibits or restricts the use of functions, ports, protocols, and/or services as defined in the security plan.',
  },
  'IA-2': {
    id: 'IA-2',
    title: 'Identification and Authentication',
    description:
      'The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).',
  },
  'IA-5': {
    id: 'IA-5',
    title: 'Authenticator Management',
    description:
      'The organization manages information system authenticators by establishing and implementing administrative procedures for initial authenticator distribution, for lost/compromised, or damaged authenticators, and for revoking authenticators.',
  },
  'IR-4': {
    id: 'IR-4',
    title: 'Incident Handling',
    description:
      'The organization implements an incident handling capability for security incidents that includes preparation, detection and analysis, containment, eradication, and recovery.',
  },
  'IR-5': {
    id: 'IR-5',
    title: 'Incident Monitoring',
    description:
      'The organization tracks and documents information system security incidents.',
  },
  'SC-5': {
    id: 'SC-5',
    title: 'Denial of Service Protection',
    description:
      'The information system protects against or limits the effects of denial of service attacks.',
  },
  'SC-6': {
    id: 'SC-6',
    title: 'Resource Availability',
    description:
      'The information system protects the availability of resources by allocating resources according to priority and quota.',
  },
  'SC-7': {
    id: 'SC-7',
    title: 'Boundary Protection',
    description:
      'The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system and implements subnetworks for publicly accessible system components that are physically or logically separated from internal organizational networks.',
  },
  'SC-8': {
    id: 'SC-8',
    title: 'Transmission Confidentiality and Integrity',
    description:
      'The information system protects the confidentiality and integrity of transmitted information.',
  },
  'SC-12': {
    id: 'SC-12',
    title: 'Cryptographic Key Establishment and Management',
    description:
      'The organization establishes and manages cryptographic keys for required cryptography employed within the information system in accordance with requirements for key generation, distribution, storage, access, and destruction.',
  },
  'SC-13': {
    id: 'SC-13',
    title: 'Cryptographic Protection',
    description:
      'The information system implements cryptographic uses and type of cryptography required for each use in accordance with applicable laws, executive orders, directives, policies, regulations, and standards.',
  },
  'SC-16': {
    id: 'SC-16',
    title: 'Transmission of Security Attributes',
    description:
      'The information system associates security attributes with information exchanged between information systems and between system components.',
  },
  'SC-23': {
    id: 'SC-23',
    title: 'Session Authenticity',
    description:
      'The information system protects the authenticity of communications sessions.',
  },
  'SI-4': {
    id: 'SI-4',
    title: 'Information System Monitoring',
    description:
      'The organization monitors the information system to detect attacks and indicators of potential attacks, unauthorized local, network, and remote connections.',
  },
};

/**
 * Get NIST control by ID
 */
export function getNistControl(id: string): NistControl | undefined {
  return NIST_CONTROLS[id];
}

/**
 * Get multiple NIST controls by IDs
 */
export function getNistControls(ids: string[]): NistControl[] {
  return ids
    .map((id) => NIST_CONTROLS[id])
    .filter((control): control is NistControl => control !== undefined);
}
