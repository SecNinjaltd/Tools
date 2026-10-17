// Course content. Kept apart from the UI code so wording can change without touching behaviour.

export const CHAPTERS = [
  {
    id: 'castle',
    n: 1,
    title: 'The castle and the moat',
    blurb: 'Watch one phishing email take over a "trusted" network, then replay it with zero trust.',
    minutes: 4,
    ready: true
  },
  {
    id: 'principles',
    n: 2,
    title: 'Three principles, one story',
    blurb: 'Switch on each principle in turn and see where the attacker gets stopped.',
    minutes: 4,
    ready: true
  },
  {
    id: 'pillars',
    n: 3,
    title: 'Meet the six pillars',
    blurb: 'Identity, endpoints, apps, data, infrastructure and network, in plain English.',
    minutes: 5,
    ready: true
  },
  {
    id: 'signin',
    n: 4,
    title: 'Signals and decisions',
    blurb: 'Play with a sign-in and watch Conditional Access decide: allow, ask for more, or block.',
    minutes: 5,
    ready: true
  },
  {
    id: 'missions',
    n: 5,
    title: 'Stop the attack',
    blurb: 'Drag Microsoft controls onto the step of the attack they break.',
    minutes: 6,
    ready: true
  },
  {
    id: 'licences',
    n: 6,
    title: 'What do I already own?',
    blurb: 'Pick your Microsoft 365 plan and see what you can switch on today.',
    minutes: 4,
    ready: true
  },
  {
    id: 'roadmap',
    n: 7,
    title: 'Build your roadmap',
    blurb: 'Plan your target state, see what it covers and export a one-page plan.',
    minutes: 8,
    ready: true
  }
];

// Plain-English definitions used by every [[term]] in chapter copy.
export const GLOSSARY = {
  'zero trust': 'A security approach that never trusts a request just because of where it comes from. Every access is checked, every time.',
  'perimeter': 'The edge of the company network, usually guarded by a firewall. Old security models trusted everything inside it.',
  'firewall': 'A gatekeeper that filters network traffic coming in and out. It cannot see what a trusted insider does.',
  'phishing': 'A fake email or message that tricks someone into clicking a link, opening a file or typing their password.',
  'lateral movement': 'When an attacker who has got in moves from one computer or system to the next.',
  'mfa': 'Multi-factor authentication: proving it is you with something extra, like an app prompt or a passkey, not just a password.',
  'passkey': 'A phishing-resistant sign-in. Your device holds a private key that never leaves it, unlocked with your face, fingerprint or PIN. It signs a one-time challenge, and only for the real website address it was made for, so there is no password to steal and nothing a fake site can reuse.',
  'conditional access': 'Microsoft Entra\'s policy engine. It looks at who, what device, where and how risky, then decides to allow, ask for more, or block.',
  'compliant device': 'A laptop or phone that Microsoft Intune has checked meets your rules: encrypted, up to date, protected by antivirus.',
  'intune': 'Microsoft Intune manages and checks company devices, so access decisions can trust (or distrust) the device.',
  'sign-in risk': 'Microsoft Entra ID Protection\'s estimate that a sign-in is not really the user, based on things like leaked passwords or impossible travel.',
  'least privilege': 'Giving people only the access they need, only for as long as they need it.',
  'assume breach': 'Designing as if an attacker is already inside, so one compromise cannot spread everywhere.',
  'verify explicitly': 'Checking every request using all the signals you have: identity, device, location, app and risk.',
  'entra id p1': 'Microsoft Entra ID P1 licence. Unlocks Conditional Access. Included in Microsoft 365 Business Premium, E3 and E5.',
  'entra id p2': 'Microsoft Entra ID P2 licence. Adds risk-based policies (ID Protection) and Privileged Identity Management. Included in Microsoft 365 E5.',
  'session controls': 'Letting someone in but limiting what they can do, for example view email in the browser but not download attachments.'
};
