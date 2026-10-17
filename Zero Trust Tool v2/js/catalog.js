// Microsoft controls used across chapters 5, 6 and 7. `needs` lists capability keys from js/licences.js,
// `learn` is the Microsoft Learn overview page and `note` is an extra licensing hint shown in chapter 6.

export const PILLARS = {
  identity: { name: 'Identity', icon: '👤' },
  endpoints: { name: 'Endpoints', icon: '💻' },
  apps: { name: 'Applications', icon: '☁️' },
  data: { name: 'Data', icon: '📄' },
  infrastructure: { name: 'Infrastructure', icon: '🏗️' },
  network: { name: 'Network', icon: '🌐' },
  visibility: { name: 'Security operations', icon: '📡' }
};

export const CONTROLS = {
  mfa: {
    name: 'MFA for everyone', pillar: 'identity', product: 'Entra Conditional Access',
    plain: 'Every sign-in needs a second proof, like an app prompt.', needs: ['entraP1'],
    note: 'Every plan gets basic MFA free through security defaults; Conditional Access lets you tailor it'
  },
  passkeys: {
    name: 'Passkeys (phishing-resistant sign-in)', pillar: 'identity', product: 'Entra authentication strength',
    plain: 'A private key that is never sent to any website signs each sign-in, and only for the real Microsoft address, so a fake page has nothing to steal or relay.', needs: ['entraP1'],
    note: 'Registering passkeys is free in every Entra ID edition; requiring them needs Entra ID P1'
  },
  compliant: {
    name: 'Require a healthy, managed device', pillar: 'endpoints', product: 'Conditional Access + Intune',
    plain: 'Only laptops and phones that Intune has checked can open company apps.', needs: ['entraP1', 'intune']
  },
  risk: {
    name: 'Risk-based sign-in policies', pillar: 'identity', product: 'Entra ID Protection',
    plain: 'Unusual sign-ins, and accounts with leaked passwords, are challenged or blocked automatically.', needs: ['idProtection']
  },
  pim: {
    name: 'Just-in-time admin (PIM)', pillar: 'identity', product: 'Entra Privileged Identity Management',
    plain: 'Admin rights are switched on for a short time, with approval, then switched off again.', needs: ['idGovernance']
  },
  reviews: {
    name: 'Regular access reviews', pillar: 'identity', product: 'Entra ID access reviews',
    plain: 'Managers confirm who still needs access, and leftover access is removed.', needs: ['idGovernance']
  },
  edr: {
    name: 'Endpoint detection and response', pillar: 'endpoints', product: 'Defender for Endpoint / Defender for Business',
    plain: 'Spots malware behaviour on a device and can isolate the device automatically.', needs: ['edr']
  },
  asr: {
    name: 'Attack surface reduction rules', pillar: 'endpoints', product: 'Defender for Endpoint',
    plain: 'Blocks common attacker tricks, like Office files launching scripts or ransomware encrypting folders.', needs: ['endpointProtection']
  },
  safelinks: {
    name: 'Safe Links and Safe Attachments', pillar: 'apps', product: 'Defender for Office 365',
    plain: 'Checks links and attachments when they are opened, and blocks known-bad ones.', needs: ['mdoP1']
  },
  cloudapps: {
    name: 'Discover and control cloud apps', pillar: 'apps', product: 'Defender for Cloud Apps',
    plain: 'Shows which cloud apps staff use and can limit risky sessions, like downloads on personal devices.', needs: ['mdca']
  },
  labels: {
    name: 'Sensitivity labels', pillar: 'data', product: 'Purview Information Protection',
    plain: 'Marks files as confidential and, if you choose, encrypts them so the protection travels with the file.', needs: ['labels']
  },
  dlp: {
    name: 'Data loss prevention for email and files', pillar: 'data', product: 'Purview DLP',
    plain: 'Stops sensitive data like card numbers being emailed or shared outside the company.', needs: ['dlp']
  },
  endpointdlp: {
    name: 'Endpoint DLP', pillar: 'data', product: 'Purview Endpoint DLP',
    plain: 'Stops sensitive files being copied to USB sticks, personal cloud storage or AI websites.', needs: ['endpointDlp'],
    note: 'On Business Premium, ask your partner about the Purview Suite for Business Premium'
  },
  private: {
    name: 'Replace the VPN with Private Access', pillar: 'network', product: 'Entra Private Access',
    plain: 'People reach one approved app at a time instead of the whole network.', needs: ['privateAccess']
  },
  internet: {
    name: 'Secure web access', pillar: 'network', product: 'Entra Internet Access',
    plain: 'Filters risky websites and applies sign-in checks to internet traffic.', needs: ['internetAccess']
  },
  cspm: {
    name: 'Cloud security posture', pillar: 'infrastructure', product: 'Defender for Cloud',
    plain: 'Finds misconfigured cloud resources, like storage left open to the internet.', needs: ['defenderCloud'],
    paygNote: 'Basic checks are free in Azure; the full Defender CSPM plan is billed by usage'
  },
  xdr: {
    name: 'Automatic attack disruption', pillar: 'visibility', product: 'Defender XDR / Defender for Business',
    plain: 'Links signals from email, identity and devices, and can contain a hijacked account and device in minutes.', needs: ['disruption']
  },
  sentinel: {
    name: 'Security monitoring (SIEM)', pillar: 'visibility', product: 'Microsoft Sentinel',
    plain: 'Collects logs from everywhere so a security team can spot and investigate attacks.', needs: ['sentinel'],
    paygNote: 'Billed by the data you send it; E5 includes a free data allowance'
  },
  mdi: {
    name: 'Spot attacks on your user directory', pillar: 'identity', product: 'Defender for Identity',
    plain: 'Watches domain controllers and identity systems for signs that an attacker is stealing passwords or moving between accounts.', needs: ['mdi']
  },
  tokenprotection: {
    name: 'Stop stolen sign-in tokens being reused', pillar: 'identity', product: 'Conditional Access token protection',
    plain: 'Ties a sign-in session to the Windows device it was issued on, so a token copied by malware is useless on another machine.', needs: ['entraP1']
  },
  epm: {
    name: 'Remove everyday admin rights', pillar: 'endpoints', product: 'Intune Endpoint Privilege Management',
    plain: 'Staff work as standard users, and only approved tasks, like installing a trusted app, run with admin rights.', needs: ['epm']
  },
  laps: {
    name: 'Unique local admin passwords', pillar: 'endpoints', product: 'Windows LAPS with Intune',
    plain: 'Gives every Windows device its own local admin password, changes it regularly and stores it safely in Entra ID.', needs: ['intune'],
    note: 'Windows LAPS itself is free; Intune makes it easy to roll out to every device'
  },
  vulnmgmt: {
    name: 'Find and fix weak software', pillar: 'endpoints', product: 'Defender Vulnerability Management',
    plain: 'Lists the software on every device, flags known weaknesses and missing updates, and ranks what to fix first.', needs: ['edr'],
    note: 'Core capabilities only; premium features are a separate add-on'
  },
  attacksim: {
    name: 'Phishing practice for staff', pillar: 'apps', product: 'Defender for Office 365 attack simulation training',
    plain: 'Sends safe, realistic fake phishing emails and gives short training to anyone who clicks.', needs: ['mdoP2']
  },
  insiderrisk: {
    name: 'Spot risky data handling', pillar: 'data', product: 'Purview Insider Risk Management',
    plain: 'Looks for warning signs, like someone downloading lots of files before leaving, and alerts a reviewer while keeping names hidden by default.', needs: ['insiderRisk']
  },
  compliantnetwork: {
    name: 'Only allow sign-ins through your secure network', pillar: 'network', product: 'Global Secure Access compliant network check',
    plain: 'Company apps only open when the device connects through your Global Secure Access client, so a stolen token can\'t be used from elsewhere.', needs: ['entraP1']
  },
  exposure: {
    name: 'See your weak spots and attack paths', pillar: 'visibility', product: 'Microsoft Security Exposure Management',
    plain: 'Brings security findings into one view and shows how an attacker could chain weaknesses together to reach important systems.', needs: ['exposureMgmt']
  },
  securitycopilot: {
    name: 'AI help for security tasks', pillar: 'visibility', product: 'Microsoft Security Copilot',
    plain: 'An AI assistant and agents inside Defender, Entra, Intune and Purview that summarise incidents, triage phishing reports and suggest fixes.', needs: ['securityCopilot'],
    note: 'Other plans can buy Security Compute Units, paid for by use', ai: true
  },
  // Securing the use of AI. Copilot only sees what the signed-in user can already reach, so these sit on top of the controls above.
  copilotoversharing: {
    name: 'Stop Copilot finding overshared files', pillar: 'data', product: 'SharePoint Advanced Management', ai: true,
    plain: 'Reports on overshared SharePoint sites and can hide sensitive sites from Copilot and search, so Copilot only surfaces what people should see.', needs: ['copilot'],
    note: 'Turns on when at least one Copilot licence is assigned, or with the SharePoint Advanced Management Plan 1 add-on'
  },
  copilotdlp: {
    name: 'Stop Copilot using sensitive files', pillar: 'data', product: 'Purview DLP for Copilot', ai: true,
    plain: 'A data loss prevention policy stops Copilot from summarising files and emails with chosen sensitivity labels.', needs: ['copilot', 'copilotDlp'],
    note: 'Blocking sensitive details typed into prompts works for every Copilot user'
  },
  aiposture: {
    name: 'See how AI is used with your data', pillar: 'data', product: 'Purview DSPM for AI', ai: true,
    plain: 'Shows which AI apps people use, flags sensitive data in prompts and offers one-click policies to protect it.', needs: ['dspmAi'],
    note: 'E3 gets a basic view; watching third-party AI apps is billed pay as you go'
  },
  shadowai: {
    name: 'Block risky AI apps', pillar: 'apps', product: 'Defender for Cloud Apps', ai: true,
    plain: 'Finds the generative AI apps staff use, scores their risk and blocks the ones you unsanction.', needs: ['mdca'],
    note: 'Blocking happens on devices onboarded to Defender for Endpoint'
  },
  agentaccess: {
    name: 'Conditional Access for AI agents', pillar: 'identity', product: 'Microsoft Entra Agent ID', ai: true,
    plain: 'Gives each AI agent its own identity and checks it with Conditional Access, blocking risky agents just like risky users.', needs: ['entraP1', 'agent365']
  }
};

// Microsoft Learn overview page for each control.
const LEARN = {
  mfa: 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength',
  passkeys: 'https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2',
  compliant: 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance',
  risk: 'https://learn.microsoft.com/entra/id-protection/overview-identity-protection',
  pim: 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure',
  reviews: 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview',
  edr: 'https://learn.microsoft.com/defender-endpoint/overview-endpoint-detection-response',
  asr: 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-overview',
  safelinks: 'https://learn.microsoft.com/defender-office-365/safe-links-about',
  cloudapps: 'https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps',
  labels: 'https://learn.microsoft.com/purview/sensitivity-labels',
  dlp: 'https://learn.microsoft.com/purview/dlp-learn-about-dlp',
  endpointdlp: 'https://learn.microsoft.com/purview/endpoint-dlp-learn-about',
  private: 'https://learn.microsoft.com/entra/global-secure-access/concept-private-access',
  internet: 'https://learn.microsoft.com/entra/global-secure-access/concept-internet-access',
  cspm: 'https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management',
  xdr: 'https://learn.microsoft.com/defender-xdr/automatic-attack-disruption',
  sentinel: 'https://learn.microsoft.com/azure/sentinel/overview',
  mdi: 'https://learn.microsoft.com/defender-for-identity/what-is',
  tokenprotection: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection',
  epm: 'https://learn.microsoft.com/intune/epm/overview',
  laps: 'https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords',
  vulnmgmt: 'https://learn.microsoft.com/defender-vulnerability-management/defender-vulnerability-management',
  attacksim: 'https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started',
  insiderrisk: 'https://learn.microsoft.com/purview/insider-risk-management',
  compliantnetwork: 'https://learn.microsoft.com/entra/global-secure-access/how-to-compliant-network',
  exposure: 'https://learn.microsoft.com/security-exposure-management/microsoft-security-exposure-management',
  securitycopilot: 'https://learn.microsoft.com/copilot/security/microsoft-security-copilot',
  copilotoversharing: 'https://learn.microsoft.com/microsoft-365/copilot/get-ready-copilot-sharepoint-advanced-management',
  copilotdlp: 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about',
  aiposture: 'https://learn.microsoft.com/purview/dspm-for-ai',
  shadowai: 'https://learn.microsoft.com/microsoft-365/copilot/manage-generative-ai-apps',
  agentaccess: 'https://learn.microsoft.com/entra/identity/conditional-access/agent-id'
};
Object.entries(LEARN).forEach(([id, url]) => { CONTROLS[id].learn = url; });

// Small tag marking AI and Copilot controls wherever a control is listed.
export function aiTag(c) {
  return c.ai ? '<span class="ai-tag" title="AI and Copilot security">✨ AI</span>' : '';
}
