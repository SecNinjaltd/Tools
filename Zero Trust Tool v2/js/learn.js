// Microsoft Learn overview pages for products named in the chapters, so every mention can link to the real docs.
import { escapeHtml } from './ui.js';

export const PRODUCTS = {
  'Microsoft Entra ID': 'https://learn.microsoft.com/entra/fundamentals/whatis',
  'Conditional Access': 'https://learn.microsoft.com/entra/identity/conditional-access/overview',
  'Entra ID Protection': 'https://learn.microsoft.com/entra/id-protection/overview-identity-protection',
  'Privileged Identity Management': 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure',
  'Access reviews': 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview',
  'Authentication strengths': 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths',
  'Passkeys': 'https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2',
  'Named locations': 'https://learn.microsoft.com/entra/identity/conditional-access/concept-assignment-network',
  'Session controls': 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-session',
  'Entra roles': 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference',
  'Defender for Identity': 'https://learn.microsoft.com/defender-for-identity/what-is',
  'Microsoft Intune': 'https://learn.microsoft.com/intune/fundamentals/what-is-intune',
  'Intune device compliance': 'https://learn.microsoft.com/intune/protect/device-compliance-get-started',
  'Endpoint Privilege Management': 'https://learn.microsoft.com/intune/epm/overview',
  'Windows LAPS': 'https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords',
  'Defender for Endpoint': 'https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint',
  'Defender for Business': 'https://learn.microsoft.com/defender-business/mdb-overview',
  'Defender Vulnerability Management': 'https://learn.microsoft.com/defender-vulnerability-management/defender-vulnerability-management',
  'Defender for Cloud Apps': 'https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps',
  'Conditional Access app control': 'https://learn.microsoft.com/defender-cloud-apps/proxy-intro-aad',
  'Defender for Office 365': 'https://learn.microsoft.com/defender-office-365/mdo-about',
  'Attack simulation training': 'https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started',
  'Purview sensitivity labels': 'https://learn.microsoft.com/purview/sensitivity-labels',
  'Purview data loss prevention': 'https://learn.microsoft.com/purview/dlp-learn-about-dlp',
  'Purview Insider Risk Management': 'https://learn.microsoft.com/purview/insider-risk-management',
  'Purview Data Security Posture Management': 'https://learn.microsoft.com/purview/data-security-posture-management-learn-about',
  'Defender for Cloud': 'https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction',
  'Azure Policy': 'https://learn.microsoft.com/azure/governance/policy/overview',
  'Azure Arc': 'https://learn.microsoft.com/azure/azure-arc/overview',
  'Entra Private Access': 'https://learn.microsoft.com/entra/global-secure-access/concept-private-access',
  'Entra Internet Access': 'https://learn.microsoft.com/entra/global-secure-access/concept-internet-access',
  'Azure Firewall': 'https://learn.microsoft.com/azure/firewall/overview',
  'Defender XDR': 'https://learn.microsoft.com/defender-xdr/microsoft-365-defender',
  'Automatic attack disruption': 'https://learn.microsoft.com/defender-xdr/automatic-attack-disruption',
  'Microsoft Sentinel': 'https://learn.microsoft.com/azure/sentinel/overview',
  'Security Copilot': 'https://learn.microsoft.com/copilot/security/microsoft-security-copilot',
  'Security Exposure Management': 'https://learn.microsoft.com/security-exposure-management/microsoft-security-exposure-management'
};

// A product name as a small chip that opens its Microsoft Learn page. Unknown names render as a plain chip.
export function productChip(name) {
  const url = PRODUCTS[name];
  return url
    ? `<a class="tag-chip learn" href="${url}" target="_blank" rel="noopener">${escapeHtml(name)} <span aria-hidden="true">↗</span><span class="sr-only"> (Microsoft Learn, opens in a new tab)</span></a>`
    : `<span class="tag-chip">${escapeHtml(name)}</span>`;
}

// A "Read more on Microsoft Learn" link for a URL.
export function learnLink(url, label = 'Read more on Microsoft Learn') {
  return url ? `<a class="learn-link" href="${url}" target="_blank" rel="noopener">${escapeHtml(label)} <span aria-hidden="true">↗</span><span class="sr-only"> (opens in a new tab)</span></a>` : '';
}
