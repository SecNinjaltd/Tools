// What each Microsoft 365 plan and add-on includes, for the capabilities used in js/catalog.js.
// Checked against Microsoft Learn service descriptions in October 2026. Licensing changes often:
// always confirm with Microsoft or your partner before buying.
import { CONTROLS } from './catalog.js';

export const CHECKED = 'October 2026';

export const CAPABILITIES = {
  entraP1: 'Microsoft Entra ID P1',
  entraP2: 'Microsoft Entra ID P2',
  intune: 'Microsoft Intune Plan 1',
  edr: 'Endpoint detection and response (Defender for Business or Defender for Endpoint P2)',
  endpointProtection: 'Defender for Endpoint P1 or Defender for Business',
  mdoP1: 'Defender for Office 365 Plan 1',
  mdca: 'Defender for Cloud Apps',
  labels: 'Purview sensitivity labels',
  dlp: 'Purview DLP for email and files',
  endpointDlp: 'Purview Endpoint DLP',
  privateAccess: 'Entra Private Access',
  internetAccess: 'Entra Internet Access',
  xdrFull: 'Full Defender XDR (Defender for Endpoint P2, Office 365 P2, Identity and Cloud Apps)',
  defenderCloud: 'Defender for Cloud (Azure, pay as you go)',
  sentinel: 'Microsoft Sentinel (Azure, pay as you go)'
};

// Billed by Azure usage rather than per user, whatever the plan.
export const PAYG = new Set(['defenderCloud', 'sentinel']);

export const PLANS = {
  bp: {
    name: 'Microsoft 365 Business Premium', short: 'Business Premium', who: 'Up to 300 users',
    includes: ['entraP1', 'intune', 'edr', 'endpointProtection', 'mdoP1', 'labels', 'dlp'],
    addons: ['defenderSuiteBP', 'entraSuite']
  },
  e3: {
    name: 'Microsoft 365 E3', short: 'E3', who: 'Enterprise, any size',
    includes: ['entraP1', 'intune', 'endpointProtection', 'mdoP1', 'labels', 'dlp'],
    addons: ['defenderSuite', 'entraSuite']
  },
  e5: {
    name: 'Microsoft 365 E5', short: 'E5', who: 'Enterprise, any size',
    includes: ['entraP1', 'entraP2', 'intune', 'edr', 'endpointProtection', 'mdoP1', 'mdca', 'labels', 'dlp', 'endpointDlp', 'xdrFull'],
    addons: ['entraSuite']
  }
};

export const ADDONS = {
  defenderSuiteBP: {
    name: 'Defender Suite for Business Premium',
    includes: ['entraP2', 'edr', 'endpointProtection', 'mdoP1', 'mdca', 'xdrFull']
  },
  defenderSuite: {
    name: 'Microsoft Defender Suite (formerly E5 Security)',
    includes: ['entraP2', 'edr', 'endpointProtection', 'mdoP1', 'mdca', 'xdrFull']
  },
  entraSuite: {
    name: 'Microsoft Entra Suite',
    includes: ['entraP2', 'privateAccess', 'internetAccess']
  }
};

export const SOURCES = [
  ['Microsoft Defender service description', 'https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-defender-service-description'],
  ['Microsoft Purview service description', 'https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description'],
  ['Microsoft Entra licensing', 'https://learn.microsoft.com/entra/fundamentals/licensing'],
  ['Defender Suite for Business Premium', 'https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/add-defender-suite-business-premium'],
  ['Global Secure Access licensing', 'https://learn.microsoft.com/entra/global-secure-access/overview-what-is-global-secure-access'],
  ['Microsoft Sentinel billing', 'https://learn.microsoft.com/azure/sentinel/billing']
];

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
