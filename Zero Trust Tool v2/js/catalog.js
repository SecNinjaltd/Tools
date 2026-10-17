// Microsoft controls used across chapters 5, 6 and 7. `needs` lists capability keys from js/licences.js.

export const PILLARS = {
  identity: { name: 'Identity', icon: '👤' },
  endpoints: { name: 'Endpoints', icon: '💻' },
  apps: { name: 'Applications', icon: '☁️' },
  data: { name: 'Data', icon: '📄' },
  infrastructure: { name: 'Infrastructure', icon: '🏗️' },
  network: { name: 'Network', icon: '🌐' },
  visibility: { name: 'Visibility & automation', icon: '📡' }
};

export const CONTROLS = {
  mfa: {
    name: 'MFA for everyone', pillar: 'identity', product: 'Entra Conditional Access',
    plain: 'Every sign-in needs a second proof, like an app prompt.', needs: ['entraP1']
  },
  passkeys: {
    name: 'Passkeys (phishing-resistant sign-in)', pillar: 'identity', product: 'Entra authentication strength',
    plain: 'A passkey only works on the real Microsoft sign-in page, so fake pages get nothing useful.', needs: ['entraP1']
  },
  compliant: {
    name: 'Require a healthy, managed device', pillar: 'endpoints', product: 'Conditional Access + Intune',
    plain: 'Only laptops and phones that Intune has checked can open company apps.', needs: ['entraP1', 'intune']
  },
  risk: {
    name: 'Risk-based sign-in policies', pillar: 'identity', product: 'Entra ID Protection',
    plain: 'Unusual or leaked-password sign-ins are challenged or blocked automatically.', needs: ['entraP2']
  },
  pim: {
    name: 'Just-in-time admin (PIM)', pillar: 'identity', product: 'Entra Privileged Identity Management',
    plain: 'Admin rights are switched on for a short time, with approval, then switched off again.', needs: ['entraP2']
  },
  reviews: {
    name: 'Regular access reviews', pillar: 'identity', product: 'Entra ID Governance',
    plain: 'Managers confirm who still needs access, and leftover access is removed.', needs: ['entraP2']
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
    plain: 'Marks files as confidential and keeps them encrypted wherever they go.', needs: ['labels']
  },
  dlp: {
    name: 'Data loss prevention for email and files', pillar: 'data', product: 'Purview DLP',
    plain: 'Stops sensitive data like card numbers being emailed or shared outside the company.', needs: ['dlp']
  },
  endpointdlp: {
    name: 'Endpoint DLP', pillar: 'data', product: 'Purview Endpoint DLP',
    plain: 'Stops sensitive files being copied to USB sticks, personal cloud storage or AI websites.', needs: ['endpointDlp']
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
    plain: 'Finds misconfigured cloud resources, like storage left open to the internet.', needs: ['defenderCloud']
  },
  xdr: {
    name: 'Automatic attack disruption', pillar: 'visibility', product: 'Defender XDR',
    plain: 'Links signals from email, identity and devices, and can disable a hijacked account in minutes.', needs: ['xdrFull']
  },
  sentinel: {
    name: 'Security monitoring (SIEM)', pillar: 'visibility', product: 'Microsoft Sentinel',
    plain: 'Collects logs from everywhere so a security team can spot and investigate attacks.', needs: ['sentinel']
  }
};
