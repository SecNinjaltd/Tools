// What each Microsoft 365 plan and add-on includes, for the capabilities used in js/catalog.js.
// Checked against Microsoft Learn service descriptions in October 2026. Licensing changes often:
// always confirm with Microsoft or your partner before buying.
import { CONTROLS } from './catalog.js';

export const CHECKED = 'October 2026';

export const CAPABILITIES = {
  entraP1: 'Microsoft Entra ID P1',
  // Entra ID P2 is split in two because the Entra ID Governance add-on gives PIM and access reviews but not ID Protection.
  idProtection: 'Microsoft Entra ID Protection (Entra ID P2)',
  idGovernance: 'Privileged Identity Management and access reviews (Entra ID P2 or ID Governance)',
  intune: 'Microsoft Intune Plan 1',
  epm: 'Intune Endpoint Privilege Management',
  edr: 'Endpoint detection and response (Defender for Business or Defender for Endpoint P2)',
  endpointProtection: 'Defender for Endpoint P1 or Defender for Business',
  mdoP1: 'Defender for Office 365 Plan 1',
  mdoP2: 'Defender for Office 365 Plan 2',
  mdi: 'Microsoft Defender for Identity',
  mdca: 'Defender for Cloud Apps',
  labels: 'Purview sensitivity labels',
  dlp: 'Purview DLP for email and files',
  endpointDlp: 'Purview Endpoint DLP',
  insiderRisk: 'Purview Insider Risk Management',
  privateAccess: 'Entra Private Access',
  internetAccess: 'Entra Internet Access',
  xdrFull: 'Full Defender XDR (Defender for Endpoint P2, Office 365 P2, Identity and Cloud Apps)',
  // Built into Defender for Business (device and user containment) and Defender XDR (cross-product).
  disruption: 'Automatic attack disruption (Defender for Business or Defender XDR)',
  exposureMgmt: 'Microsoft Security Exposure Management',
  securityCopilot: 'Microsoft Security Copilot (included Security Compute Units)',
  defenderCloud: 'Defender for Cloud (Foundational CSPM free; Defender CSPM billed by Azure usage)',
  sentinel: 'Microsoft Sentinel (Azure, pay as you go)'
};

// Billed by Azure usage rather than per user, whatever the plan.
export const PAYG = new Set(['defenderCloud', 'sentinel']);

const P2 = ['idProtection', 'idGovernance'];
const BP = ['entraP1', 'intune', 'edr', 'endpointProtection', 'mdoP1', 'labels', 'dlp', 'disruption', 'exposureMgmt'];
const E3 = ['entraP1', 'intune', 'endpointProtection', 'mdoP1', 'labels', 'dlp'];
const E5 = [...E3, ...P2, 'edr', 'mdoP2', 'mdi', 'mdca', 'endpointDlp', 'insiderRisk', 'xdrFull', 'disruption', 'epm', 'exposureMgmt', 'securityCopilot'];

export const PLANS = {
  basic: {
    name: 'Microsoft 365 Business Basic', short: 'Business Basic', family: 'Business', who: 'Up to 300 users · web and mobile apps',
    includes: [],
    addons: ['entraP1Standalone', 'entraP2Standalone', 'defenderBusiness']
  },
  standard: {
    name: 'Microsoft 365 Business Standard', short: 'Business Standard', family: 'Business', who: 'Up to 300 users · desktop apps',
    includes: [],
    addons: ['entraP1Standalone', 'entraP2Standalone', 'defenderBusiness']
  },
  bp: {
    name: 'Microsoft 365 Business Premium', short: 'Business Premium', family: 'Business', who: 'Up to 300 users · full security',
    includes: BP,
    addons: ['defenderSuiteBP', 'entraSuite', 'idGovernance', 'privateAccess', 'internetAccess', 'intuneSuite']
  },
  f3: {
    name: 'Microsoft 365 F3', short: 'F3', family: 'Frontline', who: 'Frontline staff on shared or mobile devices',
    includes: ['entraP1', 'intune', 'labels'],
    addons: ['entraP2Standalone', 'entraSuite', 'idGovernance', 'privateAccess', 'internetAccess', 'intuneSuite']
  },
  e3: {
    name: 'Microsoft 365 E3', short: 'E3', family: 'Enterprise', who: 'Enterprise, any size',
    includes: E3,
    addons: ['defenderSuite', 'purviewSuite', 'entraSuite', 'idGovernance', 'privateAccess', 'internetAccess', 'intuneSuite', 'mdeP2']
  },
  e5: {
    name: 'Microsoft 365 E5', short: 'E5', family: 'Enterprise', who: 'Enterprise, any size · full security',
    includes: E5,
    addons: ['entraSuite', 'privateAccess', 'internetAccess']
  },
  e7: {
    name: 'Microsoft 365 E7', short: 'E7', family: 'Enterprise', who: 'E5 plus Copilot, Entra Suite and Agent 365',
    includes: [...E5, 'privateAccess', 'internetAccess'],
    addons: []
  }
};

export const ADDONS = {
  entraP1Standalone: { name: 'Microsoft Entra ID P1', includes: ['entraP1'] },
  entraP2Standalone: { name: 'Microsoft Entra ID P2', includes: ['entraP1', ...P2] },
  defenderBusiness: { name: 'Microsoft Defender for Business', includes: ['edr', 'endpointProtection', 'disruption', 'exposureMgmt'] },
  defenderSuiteBP: {
    name: 'Defender Suite for Business Premium',
    includes: [...P2, 'edr', 'endpointProtection', 'mdoP1', 'mdoP2', 'mdi', 'mdca', 'xdrFull', 'disruption', 'exposureMgmt']
  },
  defenderSuite: {
    name: 'Microsoft Defender Suite (formerly E5 Security)',
    includes: [...P2, 'edr', 'endpointProtection', 'mdoP1', 'mdoP2', 'mdi', 'mdca', 'xdrFull', 'disruption', 'exposureMgmt']
  },
  purviewSuite: {
    name: 'Microsoft Purview Suite (formerly E5 Compliance)',
    includes: ['labels', 'dlp', 'endpointDlp', 'insiderRisk', 'mdca']
  },
  // Doesn't include the P2 licence itself, but bundles ID Protection and ID Governance, which cover the
  // P2 identity controls used here. Requires Entra ID P1. Also included in Microsoft 365 E7.
  entraSuite: {
    name: 'Microsoft Entra Suite',
    includes: [...P2, 'privateAccess', 'internetAccess']
  },
  idGovernance: { name: 'Microsoft Entra ID Governance', includes: ['idGovernance'] },
  privateAccess: { name: 'Entra Private Access', includes: ['privateAccess'] },
  internetAccess: { name: 'Entra Internet Access', includes: ['internetAccess'] },
  intuneSuite: { name: 'Intune Suite (or Endpoint Privilege Management)', includes: ['epm'] },
  mdeP2: { name: 'Defender for Endpoint P2', includes: ['edr', 'endpointProtection', 'disruption'] }
};

export const SOURCES = [
  ['Microsoft Defender service description', 'https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-defender-service-description'],
  ['Defender for Office 365 service description', 'https://learn.microsoft.com/office365/servicedescriptions/office-365-advanced-threat-protection-service-description'],
  ['Defender for Business attack disruption', 'https://learn.microsoft.com/defender-business/mdb-attack-disruption'],
  ['Microsoft 365 for business security overview', 'https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/m365b-security-overview'],
  ['Microsoft Purview service description', 'https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description'],
  ['Microsoft Entra licensing', 'https://learn.microsoft.com/entra/fundamentals/licensing'],
  ['Entra ID Governance licensing', 'https://learn.microsoft.com/entra/id-governance/licensing-fundamentals'],
  ['Defender Suite for Business Premium', 'https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/add-defender-suite-business-premium'],
  ['Global Secure Access licensing', 'https://learn.microsoft.com/entra/global-secure-access/overview-what-is-global-secure-access'],
  ['Intune licensing changes 2026', 'https://learn.microsoft.com/intune/fundamentals/planning-guide'],
  ['Microsoft 365 E7 overview', 'https://learn.microsoft.com/microsoft-365/copilot/microsoft-365-copilot-license-feature-overview'],
  ['Security Copilot in E5 and E7', 'https://learn.microsoft.com/copilot/security/security-copilot-inclusion'],
  ['Exposure Management licensing', 'https://learn.microsoft.com/security-exposure-management/integration-licensing'],
  ['Defender for Cloud posture management', 'https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management'],
  ['Microsoft Sentinel billing', 'https://learn.microsoft.com/azure/sentinel/billing']
];

// Saved choices, checked against the current data in case a plan or add-on was renamed.
export function savedPlan(store) {
  const p = store.get('plan', 'bp');
  return PLANS[p] ? p : 'bp';
}
export function savedAddons(store, planId) {
  const a = store.get('addons', []);
  return Array.isArray(a) ? a.filter((x) => ADDONS[x] && PLANS[planId].addons.includes(x)) : [];
}

// How a control is covered by a plan plus chosen add-ons.
// Returns { status: 'included' | 'addon' | 'payg' | 'missing', missing: [capability keys], via: [add-on names] }
export function coverage(controlId, planId, addonIds = []) {
  const plan = PLANS[planId];
  const needs = CONTROLS[controlId].needs;
  if (needs.every((n) => PAYG.has(n))) return { status: 'payg', missing: [], via: [] };
  const via = new Set();
  const missing = [];
  needs.forEach((n) => {
    if (plan.includes.includes(n)) return;
    const addon = addonIds.find((a) => plan.addons.includes(a) && ADDONS[a].includes.includes(n));
    if (addon) via.add(ADDONS[addon].name); else missing.push(n);
  });
  if (missing.length) return { status: 'missing', missing, via: [...via] };
  return { status: via.size ? 'addon' : 'included', missing: [], via: [...via] };
}

// Which available add-ons would cover the missing capabilities.
export function addonsThatCover(controlId, planId) {
  const plan = PLANS[planId];
  return plan.addons.filter((a) => coverage(controlId, planId, [a]).status === 'addon').map((a) => ADDONS[a].name);
}

// Plans that include a control outright, for when no add-on on the current plan covers it.
export function plansThatInclude(controlId) {
  return Object.keys(PLANS).filter((p) => coverage(controlId, p, []).status === 'included').map((p) => PLANS[p].short);
}

// One short line saying how to get a control that the current plan doesn't cover.
export function howToGet(controlId, planId) {
  const opts = addonsThatCover(controlId, planId);
  if (opts.length) return `Available with ${opts.join(' or ')}`;
  const plans = plansThatInclude(controlId);
  if (plans.length) return `Included in ${plans.join(', ')}`;
  return `Needs ${CONTROLS[controlId].needs.map((n) => CAPABILITIES[n]).join(', ')}`;
}
