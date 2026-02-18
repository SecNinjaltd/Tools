const { useState, useEffect } = React;


const COLORS = {
  bg: "#090e1a",
  surface: "#0d1526",
  surfaceAlt: "#111d35",
  border: "#1e3a5f",
  accent: "#3b82f6",
  accentBright: "#60a5fa",
  success: "#10b981",
  warning: "#f59e0b",
  danger: "#ef4444",
  text: "#e2e8f0",
  textMuted: "#64748b",
  textDim: "#94a3b8",
};

const CONTROL_COLORS = {
  phish_mfa: "#a855f7",
  mfa: "#3b82f6",
  legacy_auth: "#f97316",
  compliant_device: "#10b981",
  hybrid_join: "#059669",
  app_protection: "#14b8a6",
  approved_client: "#0d9488",
  named_locations: "#eab308",
  sign_in_risk: "#ef4444",
  user_risk: "#ec4899",
  session_controls: "#6366f1",
  terms_of_use: "#8b5cf6",
  block_unknown_platforms: "#dc2626",
  require_password_change: "#f97316",
};

const ZERO_TRUST_PRINCIPLES = {
  verify: { label: "Verify Explicitly", color: "#3b82f6", icon: "🔍" },
  least: { label: "Least Privilege Access", color: "#8b5cf6", icon: "🔒" },
  breach: { label: "Assume Breach", color: "#ef4444", icon: "🛡️" },
};

const MITRE_TECHNIQUES = {
  'T1078': { 
    name: 'Valid Accounts', 
    tactic: 'Initial Access', 
    severity: 'High',
    desc: 'Adversaries use legitimate credentials to gain initial access, persistence, or privilege escalation.',
  },
  'T1110': { 
    name: 'Brute Force', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'Attackers attempt to guess passwords or use credential stuffing to gain access.',
  },
  'T1528': { 
    name: 'Steal Application Access Token', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'Adversaries steal OAuth tokens to access cloud services without needing passwords.',
  },
  'T1539': { 
    name: 'Steal Web Session Cookie', 
    tactic: 'Credential Access', 
    severity: 'Medium',
    desc: 'Attackers steal session cookies to hijack authenticated sessions.',
  },
  'T1556': { 
    name: 'Modify Authentication Process', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'Adversaries modify authentication mechanisms to bypass controls.',
  },
  'T1621': { 
    name: 'MFA Request Generation', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'MFA fatigue attacks - flooding users with push notifications until they approve.',
  },
  'T1098': { 
    name: 'Account Manipulation', 
    tactic: 'Persistence', 
    severity: 'Medium',
    desc: 'Attackers modify account settings to maintain access or escalate privileges.',
  },
  'T1484': { 
    name: 'Domain Policy Modification', 
    tactic: 'Defense Evasion', 
    severity: 'Medium',
    desc: 'Adversaries modify domain policies to evade defenses or maintain access.',
  },
  'T1557': { 
    name: 'Adversary-in-the-Middle', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'Man-in-the-middle attacks to intercept credentials or session tokens (AiTM).',
  },
  'T1606': { 
    name: 'Forge Web Credentials', 
    tactic: 'Credential Access', 
    severity: 'High',
    desc: 'Attackers forge authentication tokens or cookies to bypass authentication.',
  },
  'T1133': { 
    name: 'External Remote Services', 
    tactic: 'Persistence', 
    severity: 'Medium',
    desc: 'Using external remote services like VPNs or legacy protocols for persistence.',
  },
  'T1199': { 
    name: 'Trusted Relationship', 
    tactic: 'Initial Access', 
    severity: 'Medium',
    desc: 'Exploiting trust relationships with third parties or partners.',
  },
};

const IDENTITY_TYPES = [
  { id: "user", label: "Standard User", icon: "👤", desc: "Regular employees, contractors", baseRisk: 45 },
  { id: "admin", label: "Administrator", icon: "⚙️", desc: "Global admin, privileged roles", baseRisk: 85 },
  { id: "guest", label: "Guest / External", icon: "🌐", desc: "B2B collaborators, partners", baseRisk: 70 },
  { id: "workload", label: "Workload Identity", icon: "🤖", desc: "Service principals, managed identities", baseRisk: 60 },
];

const ACCESS_TARGETS = [
  { id: "all_apps", label: "All Cloud Apps", icon: "☁️", desc: "Broadest coverage", riskMultiplier: 1.6 },
  { id: "admin_portals", label: "Microsoft Admin Portals", icon: "🏛️", desc: "Azure, Entra, Intune", riskMultiplier: 1.9 },
  { id: "office365", label: "Microsoft 365", icon: "📧", desc: "Exchange, SharePoint, Teams", riskMultiplier: 1.3 },
  { id: "specific", label: "Specific Applications", icon: "🎯", desc: "Target individual apps", riskMultiplier: 1.0 },
];

const POLICY_CONTROLS = [
  {
    id: "phish_mfa",
    label: "Phishing-Resistant MFA",
    category: "authentication",
    baseRiskReduction: 35,
    ztPrinciples: ["verify"],
    defenseLayer: "Identity",
    desc: "FIDO2 security keys or Windows Hello for Business",
    why: "Cryptographically bound to origin - cannot be phished, relayed, or replayed. Blocks AiTM attacks completely.",
    mitreBlocked: ['T1621', 'T1110', 'T1557', 'T1078', 'T1606'],
    bestPractice: "Mandatory for all administrator accounts. Consider hardware tokens for high-value users.",
  },
  {
    id: "mfa",
    label: "Require MFA",
    category: "authentication",
    baseRiskReduction: 25,
    ztPrinciples: ["verify"],
    defenseLayer: "Identity",
    desc: "Multi-factor authentication (any method)",
    why: "Blocks 99.9% of automated attacks even with stolen passwords.",
    mitreBlocked: ['T1110', 'T1078'],
    bestPractice: "Minimum baseline for all users. Upgrade to phishing-resistant for admins.",
  },
  {
    id: "legacy_auth",
    label: "Block Legacy Authentication",
    category: "authentication",
    baseRiskReduction: 22,
    ztPrinciples: ["verify"],
    defenseLayer: "Network",
    desc: "Block IMAP, POP3, SMTP Auth, older protocols",
    why: "Legacy protocols bypass MFA. 99% of password spray attacks use legacy auth.",
    mitreBlocked: ['T1110', 'T1078', 'T1133'],
    bestPractice: "Block for all users. No legitimate need for legacy auth in modern environments.",
  },
  {
    id: "compliant_device",
    label: "Require Compliant Device",
    category: "device",
    baseRiskReduction: 20,
    ztPrinciples: ["verify", "breach"],
    defenseLayer: "Device",
    desc: "Intune-enrolled, policy-compliant devices only",
    why: "Ensures endpoint security baselines, encryption, and patch compliance before access.",
    mitreBlocked: ['T1078', 'T1528', 'T1539'],
    bestPractice: "Required for accessing sensitive data. Provide enrollment grace period for new devices.",
  },
  {
    id: "hybrid_join",
    label: "Hybrid Azure AD Joined Device",
    category: "device",
    baseRiskReduction: 15,
    ztPrinciples: ["verify"],
    defenseLayer: "Device",
    desc: "Corporate-managed devices joined to AD and Azure AD",
    why: "Ensures corporate device control and management.",
    mitreBlocked: ['T1078', 'T1199'],
    bestPractice: "Use for hybrid environments. Prefer compliant device check for pure cloud.",
  },
  {
    id: "app_protection",
    label: "Require App Protection Policy",
    category: "device",
    baseRiskReduction: 18,
    ztPrinciples: ["breach", "least"],
    defenseLayer: "Application",
    desc: "Mobile app management policies for BYOD",
    why: "Prevents data leakage on unmanaged mobile devices. Copy/paste controls, encryption.",
    mitreBlocked: ['T1528', 'T1539'],
    bestPractice: "Essential for BYOD scenarios. Combine with compliant device for corporate devices.",
  },
  {
    id: "approved_client",
    label: "Require Approved Client App",
    category: "device",
    baseRiskReduction: 12,
    ztPrinciples: ["least"],
    defenseLayer: "Application",
    desc: "Only allow Microsoft approved mobile apps",
    why: "Prevents browser-based access on mobile that bypasses app protection.",
    mitreBlocked: ['T1528'],
    bestPractice: "Use with app protection policies for complete mobile security.",
  },
  {
    id: "named_locations",
    label: "Require Trusted Locations",
    category: "location",
    baseRiskReduction: 15,
    ztPrinciples: ["verify"],
    defenseLayer: "Network",
    desc: "Only allow access from known IP ranges",
    why: "Reduces attack surface by limiting access geography. Blocks impossible travel scenarios.",
    mitreBlocked: ['T1078', 'T1199'],
    bestPractice: "Define corporate offices + VPN ranges. Allow MFA step-up from untrusted locations.",
  },
  {
    id: "sign_in_risk",
    label: "Block High Sign-In Risk",
    category: "risk",
    baseRiskReduction: 25,
    ztPrinciples: ["breach"],
    defenseLayer: "Identity",
    desc: "Azure AD Identity Protection sign-in risk signals",
    why: "ML-based detection of anomalous sign-ins, leaked credentials, atypical travel.",
    mitreBlocked: ['T1078', 'T1110', 'T1557', 'T1606'],
    bestPractice: "Block high risk, require MFA for medium risk. Essential for admins.",
  },
  {
    id: "user_risk",
    label: "Block High User Risk",
    category: "risk",
    baseRiskReduction: 20,
    ztPrinciples: ["breach"],
    defenseLayer: "Identity",
    desc: "Azure AD Identity Protection user risk signals",
    why: "Detects compromised accounts based on leaked credentials, behavioral anomalies.",
    mitreBlocked: ['T1078', 'T1098', 'T1556'],
    bestPractice: "Require password change for high risk users. Block access until remediated.",
  },
  {
    id: "session_controls",
    label: "Session Management",
    category: "session",
    baseRiskReduction: 10,
    ztPrinciples: ["breach", "least"],
    defenseLayer: "Application",
    desc: "Session timeouts and sign-in frequency controls",
    why: "Limits session hijacking window. Forces periodic re-authentication.",
    mitreBlocked: ['T1539', 'T1528'],
    bestPractice: "4-hour timeout for standard users, 1-hour for admins.",
  },
  {
    id: "terms_of_use",
    label: "Require Terms of Use Acceptance",
    category: "compliance",
    baseRiskReduction: 5,
    ztPrinciples: ["verify"],
    defenseLayer: "Application",
    desc: "Force acceptance of usage policies",
    why: "Legal/compliance requirement. User acknowledgment of acceptable use.",
    mitreBlocked: [],
    bestPractice: "Use for guest users and contractors. Annual re-acceptance.",
  },
  {
    id: "block_unknown_platforms",
    label: "Block Unknown Platforms",
    category: "device",
    baseRiskReduction: 10,
    ztPrinciples: ["verify"],
    defenseLayer: "Device",
    desc: "Block unrecognized device platforms",
    why: "Prevents access from unusual or spoofed platforms.",
    mitreBlocked: ['T1078'],
    bestPractice: "Useful for highly controlled environments.",
  },
  {
    id: "require_password_change",
    label: "Require Password Change",
    category: "authentication",
    baseRiskReduction: 15,
    ztPrinciples: ["verify"],
    defenseLayer: "Identity",
    desc: "Force password reset on risky sign-in",
    why: "Ensures compromised credentials are rotated immediately.",
    mitreBlocked: ['T1078', 'T1110'],
    bestPractice: "Combine with user risk policies. Use for detected compromises.",
  },
];

const DEFENSE_IN_DEPTH_LAYERS = [
  { layer: "Perimeter", example: "Network firewalls, WAF", color: "#ef4444" },
  { layer: "Network", example: "Named locations, geo-blocking", color: "#f97316" },
  { layer: "Identity", example: "MFA, phishing-resistant auth", color: "#eab308" },
  { layer: "Device", example: "Compliant devices, app protection", color: "#10b981" },
  { layer: "Application", example: "App controls, session limits", color: "#3b82f6" },
  { layer: "Data", example: "Encryption, DLP policies", color: "#8b5cf6" },
];

const ZERO_TRUST_MATURITY = {
  traditional: {
    level: "Traditional",
    color: COLORS.danger,
    desc: "Perimeter-based security, limited identity verification",
  },
  advanced: {
    level: "Advanced",
    color: COLORS.warning,
    desc: "Some cloud-based controls, basic MFA",
  },
  optimal: {
    level: "Optimal",
    color: COLORS.success,
    desc: "Full Zero Trust implementation with phishing-resistant MFA",
  },
};

const BEST_PRACTICES = [
  {
    id: "breakglass",
    title: "Break-Glass Accounts",
    icon: "🚨",
    desc: "Maintain 2+ emergency access accounts excluded from ALL Conditional Access policies",
    why: "Prevents complete lockout if policies misconfigure. Critical for disaster recovery.",
    steps: [
      "Create 2 cloud-only global admin accounts (not synced from AD)",
      "Use 25+ character random passwords stored in secure physical safe",
      "Exclude from ALL CA policies including MFA",
      "Monitor with dedicated alerts - any use triggers investigation",
      "Rotate passwords quarterly",
      "Document in security runbook",
    ],
    critical: true,
    msReference: "Microsoft Zero Trust Deployment Guide - Emergency Access",
  },
  {
    id: "report_only",
    title: "Report-Only Mode Testing",
    icon: "📊",
    desc: "Always test new policies in report-only mode first",
    why: "Identifies potential lockout scenarios before enforcement. See who would be impacted.",
    steps: [
      "Create policy in 'Report-only' state",
      "Monitor sign-in logs for 7-14 days",
      "Review 'What If' tool results for different scenarios",
      "Check for unexpected user/app combinations",
      "Only enable after validation",
    ],
    critical: true,
    msReference: "Microsoft Conditional Access Deployment Best Practices",
  },
  {
    id: "named_locations",
    title: "Named Locations Configuration",
    icon: "📍",
    desc: "Define trusted locations for geo-fencing policies",
    why: "Enables location-based access controls and blocks access from unexpected regions.",
    steps: [
      "Add corporate office IP ranges",
      "Include VPN exit points",
      "Add approved remote work locations (home IPs for executives)",
      "Mark trusted locations for MFA bypass (only for low-risk scenarios)",
      "Block known high-risk countries (match your threat intelligence)",
      "Use 'Trusted' flag carefully - limits its security benefit",
    ],
    critical: false,
    msReference: "Zero Trust Principle: Verify Explicitly - Network Controls",
  },
  {
    id: "policy_exclusions",
    title: "Exclusion Groups Best Practices",
    icon: "👥",
    desc: "Manage policy exceptions safely",
    why: "Exclusions create security gaps. Must be tightly controlled and audited.",
    steps: [
      "Use groups for exclusions (never individual users)",
      "Name clearly: 'CA-Exclusion-[PolicyName]-[Reason]'",
      "Require approval workflow for adding members",
      "Review quarterly - remove when no longer needed",
      "Alert on membership changes",
      "Document business justification for each exclusion",
      "Prefer time-limited exceptions where possible",
    ],
    critical: false,
    msReference: "Microsoft Conditional Access Framework - Exception Management",
  },
  {
    id: "admin_protection",
    title: "Administrator Protection Strategy",
    icon: "🛡️",
    desc: "Separate policies for privileged accounts",
    why: "Admin accounts are highest-value targets. Require strictest controls.",
    steps: [
      "Phishing-resistant MFA mandatory (no exceptions)",
      "Require compliant devices only",
      "1-hour session lifetime maximum",
      "Block legacy authentication entirely",
      "Restrict to trusted locations only",
      "Separate admin accounts from daily-use accounts",
      "Consider Privileged Access Workstations (PAWs)",
    ],
    critical: true,
    msReference: "Zero Trust - Least Privilege & Microsoft Privileged Access Strategy",
  },
  {
    id: "monitoring",
    title: "Policy Monitoring & Alerts",
    icon: "🔔",
    desc: "Continuous monitoring of policy effectiveness",
    why: "Policies must be monitored for gaps, failures, and abuse attempts.",
    steps: [
      "Monitor sign-in logs for policy failures/successes",
      "Alert on break-glass account usage",
      "Track policy exclusion group changes",
      "Review risk detections (Identity Protection)",
      "Monitor for policy conflicts or gaps",
      "Weekly review of blocked sign-ins",
      "Quarterly policy effectiveness audit",
    ],
    critical: false,
    msReference: "Zero Trust - Assume Breach & Continuous Verification",
  },
];

const Btn = ({ label, onClick, disabled, danger, secondary, small }) => (
  <button
    onClick={onClick}
    disabled={disabled}
    style={{
      background: disabled ? COLORS.surfaceAlt : danger ? `${COLORS.danger}18` : secondary ? `${COLORS.textMuted}18` : `${COLORS.accent}18`,
      border: `1px solid ${disabled ? COLORS.border : danger ? `${COLORS.danger}50` : secondary ? `${COLORS.textMuted}50` : `${COLORS.accent}50`}`,
      color: disabled ? COLORS.textMuted : danger ? COLORS.danger : secondary ? COLORS.textDim : COLORS.accentBright,
      padding: small ? "6px 12px" : "9px 18px",
      borderRadius: 8,
      cursor: disabled ? "not-allowed" : "pointer",
      fontSize: small ? 9 : 10,
      fontWeight: 700,
      letterSpacing: "0.1em",
      fontFamily: "inherit",
      transition: "all 0.15s",
      opacity: disabled ? 0.5 : 1,
    }}
  >
    {label}
  </button>
);

const RiskMeter = ({ score, size = 80 }) => {
  const getColor = () => {
    if (score < 25) return COLORS.success;
    if (score < 50) return COLORS.warning;
    return COLORS.danger;
  };
  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={size/2 - 8} fill="none" stroke={COLORS.border} strokeWidth="6" />
        <circle cx={size/2} cy={size/2} r={size/2 - 8} fill="none" stroke={getColor()} strokeWidth="6"
          strokeDasharray={`${2 * Math.PI * (size/2 - 8)}`}
          strokeDashoffset={`${2 * Math.PI * (size/2 - 8) * (1 - score / 100)}`}
          style={{ transition: "stroke-dashoffset 0.5s" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <div style={{ fontSize: size * 0.25, fontWeight: 700, color: getColor() }}>{score}</div>
        <div style={{ fontSize: size * 0.1, color: COLORS.textMuted }}>RISK</div>
      </div>
    </div>
  );
};

export default function ThreatFirstCABuilder() {
  const [identity, setIdentity] = useState(null);
  const [target, setTarget] = useState(null);
  const [selectedThreats, setSelectedThreats] = useState([]);
  const [highlightedControls, setHighlightedControls] = useState(new Set());
  const [draggedThreat, setDraggedThreat] = useState(null);
  const [analysisView, setAnalysisView] = useState('overview');
  const [pulseControls, setPulseControls] = useState(true);
  const [showBestPractices, setShowBestPractices] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setPulseControls(prev => !prev);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Calculate which controls are needed based on selected threats
  useEffect(() => {
    const needed = new Set();
    selectedThreats.forEach(threatId => {
      POLICY_CONTROLS.forEach(control => {
        if (control.mitreBlocked.includes(threatId)) {
          needed.add(control.id);
        }
      });
    });
    setHighlightedControls(needed);
  }, [selectedThreats]);

  const handleDropThreat = (threatId) => {
    if (!selectedThreats.includes(threatId)) {
      setSelectedThreats([...selectedThreats, threatId]);
    }
    setDraggedThreat(null);
  };

  const removeThreat = (threatId) => {
    setSelectedThreats(selectedThreats.filter(id => id !== threatId));
  };

  const handleReset = () => {
    setIdentity(null);
    setTarget(null);
    setSelectedThreats([]);
    setHighlightedControls(new Set());
    setShowBestPractices(false);
  };

  const canStartBuilding = identity && target;

  // Calculate base risk from identity type + access target combination
  const getBaseRisk = () => {
    if (!identity || !target) return 100;
    const identityData = IDENTITY_TYPES.find(i => i.id === identity);
    const targetData = ACCESS_TARGETS.find(t => t.id === target);
    const combinedRisk = Math.min(95, Math.round(identityData.baseRisk * targetData.riskMultiplier));
    return combinedRisk;
  };

  // Calculate risk reduction from controls
  const calculateRiskReduction = () => {
    let total = 0;
    highlightedControls.forEach(controlId => {
      const control = POLICY_CONTROLS.find(c => c.id === controlId);
      if (control) {
        total += control.baseRiskReduction;
      }
    });
    return Math.min(total, 90);
  };

  const baseRisk = getBaseRisk();
  const riskReduction = calculateRiskReduction();
  const finalRisk = Math.max(5, baseRisk - riskReduction);

  // Calculate coverage metrics
  const getControlsForThreats = () => {
    const controlMap = {};
    selectedThreats.forEach(threatId => {
      POLICY_CONTROLS.forEach(control => {
        if (control.mitreBlocked.includes(threatId)) {
          if (!controlMap[control.id]) {
            controlMap[control.id] = {
              control,
              threats: []
            };
          }
          controlMap[control.id].threats.push(threatId);
        }
      });
    });
    return Object.values(controlMap).sort((a, b) => b.threats.length - a.threats.length);
  };

  const controlsNeeded = getControlsForThreats();

  // Zero Trust maturity calculation
  const calculateMaturity = () => {
    const controls = highlightedControls;
    if (controls.has('phish_mfa') && controls.has('compliant_device') && controls.size >= 6) {
      return 'optimal';
    } else if (controls.has('mfa') && controls.size >= 3) {
      return 'advanced';
    }
    return 'traditional';
  };

  const maturityLevel = calculateMaturity();

  // Defense layer coverage
  const getLayerCoverage = () => {
    const coverage = {};
    highlightedControls.forEach(controlId => {
      const control = POLICY_CONTROLS.find(c => c.id === controlId);
      if (control) {
        const layer = control.defenseLayer;
        coverage[layer] = (coverage[layer] || 0) + 1;
      }
    });
    return coverage;
  };

  const layerCoverage = getLayerCoverage();

  // Zero Trust principles coverage
  const getZTPrincipleCoverage = () => {
    const coverage = {};
    Object.keys(ZERO_TRUST_PRINCIPLES).forEach(key => {
      coverage[key] = [];
    });
    
    highlightedControls.forEach(controlId => {
      const control = POLICY_CONTROLS.find(c => c.id === controlId);
      if (control) {
        control.ztPrinciples.forEach(principle => {
          coverage[principle].push(control);
        });
      }
    });
    return coverage;
  };

  const ztCoverage = getZTPrincipleCoverage();

  // All threats coverage for matrix view
  const allThreats = Object.keys(MITRE_TECHNIQUES);
  const coveredThreats = new Set();
  highlightedControls.forEach(controlId => {
    const control = POLICY_CONTROLS.find(c => c.id === controlId);
    if (control) {
      control.mitreBlocked.forEach(t => coveredThreats.add(t));
    }
  });

  const coveragePercent = allThreats.length > 0 ? Math.round((coveredThreats.size / allThreats.length) * 100) : 0;

  return (
    <div style={{
      minHeight: "100vh",
      background: `linear-gradient(135deg, ${COLORS.bg} 0%, #0a1128 100%)`,
      padding: 24,
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      color: COLORS.text,
    }}>
      <div style={{ maxWidth: 1800, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontSize: 26, fontWeight: 800, marginBottom: 6 }}>
              🛡️ Threat-First CA Policy Builder
            </div>
            <div style={{ fontSize: 12, color: COLORS.textMuted }}>
              Drag threats to see required controls • Real-time MITRE ATT&CK analysis
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn label="📚 BEST PRACTICES" onClick={() => setShowBestPractices(!showBestPractices)} secondary small />
            <Btn label="↺ RESET" onClick={handleReset} danger small />
          </div>
        </div>

        {/* Best Practices Modal */}
        {showBestPractices && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
            <div style={{ background: COLORS.surface, borderRadius: 16, maxWidth: 900, maxHeight: "90vh", overflow: "auto", border: `2px solid ${COLORS.border}` }}>
              <div style={{ position: "sticky", top: 0, background: COLORS.surface, padding: 24, borderBottom: `1px solid ${COLORS.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ fontSize: 18, fontWeight: 700 }}>Microsoft Best Practices & Guidance</div>
                <button onClick={() => setShowBestPractices(false)} style={{ background: "none", border: "none", color: COLORS.text, fontSize: 24, cursor: "pointer" }}>×</button>
              </div>
              <div style={{ padding: 24 }}>
                {BEST_PRACTICES.map(bp => (
                  <div key={bp.id} style={{ background: COLORS.surfaceAlt, borderRadius: 12, padding: 20, marginBottom: 16, border: `1px solid ${bp.critical ? COLORS.danger : COLORS.border}` }}>
                    <div style={{ display: "flex", alignItems: "start", gap: 12, marginBottom: 12 }}>
                      <div style={{ fontSize: 32 }}>{bp.icon}</div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                          <div style={{ fontSize: 16, fontWeight: 700 }}>{bp.title}</div>
                          {bp.critical && (
                            <span style={{ fontSize: 9, padding: "2px 8px", background: `${COLORS.danger}20`, color: COLORS.danger, borderRadius: 4, fontWeight: 700 }}>CRITICAL</span>
                          )}
                        </div>
                        <div style={{ fontSize: 11, color: COLORS.textMuted, marginBottom: 8 }}>{bp.desc}</div>
                        <div style={{ fontSize: 10, color: COLORS.textDim, fontStyle: "italic", marginBottom: 8 }}>Why: {bp.why}</div>
                        <div style={{ fontSize: 9, color: COLORS.accentBright, padding: "4px 8px", background: `${COLORS.accent}10`, borderRadius: 4, display: "inline-block" }}>
                          📚 {bp.msReference}
                        </div>
                      </div>
                    </div>
                    <div style={{ background: COLORS.surface, borderRadius: 8, padding: 14 }}>
                      <div style={{ fontSize: 9, letterSpacing: "0.1em", color: COLORS.textMuted, marginBottom: 8 }}>IMPLEMENTATION STEPS:</div>
                      {bp.steps.map((step, idx) => (
                        <div key={idx} style={{ fontSize: 10, color: COLORS.textDim, marginBottom: 6, display: "flex", gap: 8 }}>
                          <span style={{ color: COLORS.accent, fontWeight: 700 }}>{idx + 1}.</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Step 1: Identity & Access Selection */}
        <div style={{ 
          background: COLORS.surface, 
          borderRadius: 16, 
          padding: 24,
          border: `1px solid ${COLORS.border}`,
          marginBottom: 24
        }}>
          <div style={{ fontSize: 11, letterSpacing: "0.1em", color: COLORS.textMuted, marginBottom: 16, fontWeight: 700 }}>
            STEP 1: DEFINE POLICY SCOPE
          </div>
          
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
            {/* Identity Selection */}
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, color: COLORS.text }}>
                Select Identity Type
              </div>
              <div style={{ display: "grid", gap: 12 }}>
                {IDENTITY_TYPES.map(id => (
                  <button
                    key={id.id}
                    onClick={() => setIdentity(id.id)}
                    style={{
                      padding: 16,
                      background: identity === id.id ? `${COLORS.accent}20` : COLORS.surfaceAlt,
                      border: `2px solid ${identity === id.id ? COLORS.accent : COLORS.border}`,
                      borderRadius: 12,
                      color: COLORS.text,
                      cursor: "pointer",
                      textAlign: "left",
                      fontFamily: "inherit",
                      transition: "all 0.2s",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                      <span style={{ fontSize: 24 }}>{id.icon}</span>
                      <div style={{ fontSize: 14, fontWeight: 700 }}>{id.label}</div>
                    </div>
                    <div style={{ fontSize: 11, color: COLORS.textMuted }}>{id.desc}</div>
                    <div style={{ fontSize: 10, color: COLORS.danger, marginTop: 8, fontWeight: 600 }}>
                      Base Risk: {id.baseRisk}%
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Access Target Selection */}
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, color: COLORS.text }}>
                Select Access Scope
              </div>
              <div style={{ display: "grid", gap: 12 }}>
                {ACCESS_TARGETS.map(tgt => {
                  const combinedRisk = identity ? Math.min(95, Math.round(
                    IDENTITY_TYPES.find(i => i.id === identity).baseRisk * tgt.riskMultiplier
                  )) : null;
                  
                  return (
                    <button
                      key={tgt.id}
                      onClick={() => setTarget(tgt.id)}
                      style={{
                        padding: 16,
                        background: target === tgt.id ? `${COLORS.accent}20` : COLORS.surfaceAlt,
                        border: `2px solid ${target === tgt.id ? COLORS.accent : COLORS.border}`,
                        borderRadius: 12,
                        color: COLORS.text,
                        cursor: "pointer",
                        textAlign: "left",
                        fontFamily: "inherit",
                        transition: "all 0.2s",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                        <span style={{ fontSize: 24 }}>{tgt.icon}</span>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 14, fontWeight: 700 }}>{tgt.label}</div>
                        </div>
                        {combinedRisk && (
                          <div style={{
                            padding: "4px 10px",
                            background: combinedRisk > 75 ? `${COLORS.danger}20` : combinedRisk > 50 ? `${COLORS.warning}20` : `${COLORS.success}20`,
                            border: `1px solid ${combinedRisk > 75 ? COLORS.danger : combinedRisk > 50 ? COLORS.warning : COLORS.success}`,
                            borderRadius: 6,
                            fontSize: 11,
                            fontWeight: 700,
                            color: combinedRisk > 75 ? COLORS.danger : combinedRisk > 50 ? COLORS.warning : COLORS.success
                          }}>
                            {combinedRisk}% RISK
                          </div>
                        )}
                      </div>
                      <div style={{ fontSize: 11, color: COLORS.textMuted }}>{tgt.desc}</div>
                      {identity && (
                        <div style={{ fontSize: 9, color: COLORS.textDim, marginTop: 6, fontStyle: "italic" }}>
                          {tgt.riskMultiplier}x risk multiplier
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Comprehensive Threat Coverage Analysis */}
        {canStartBuilding && (
          <div style={{
            background: COLORS.surface,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 16,
            padding: 24,
            marginBottom: 24
          }}>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, letterSpacing: "0.1em", color: COLORS.textMuted, fontWeight: 700, marginBottom: 8 }}>
                COMPREHENSIVE THREAT COVERAGE ANALYSIS
              </div>
              
              {/* View Tabs */}
              <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
                {[
                  { id: 'overview', label: '📊 Overview', icon: '📊' },
                  { id: 'matrix', label: '🎯 MITRE Matrix', icon: '🎯' },
                  { id: 'zerotrust', label: '🔍 Zero Trust', icon: '🔍' },
                  { id: 'defense', label: '🛡️ Defense Layers', icon: '🛡️' }
                ].map(view => (
                  <button
                    key={view.id}
                    onClick={() => setAnalysisView(view.id)}
                    style={{
                      padding: "8px 16px",
                      background: analysisView === view.id ? `${COLORS.accent}20` : COLORS.surfaceAlt,
                      border: `1px solid ${analysisView === view.id ? COLORS.accent : COLORS.border}`,
                      borderRadius: 8,
                      color: analysisView === view.id ? COLORS.accent : COLORS.textMuted,
                      cursor: "pointer",
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "inherit",
                      transition: "all 0.2s"
                    }}
                  >
                    {view.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Overview View */}
            {analysisView === 'overview' && (
              <div>
                {selectedThreats.length > 0 ? (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
                      <div style={{
                        padding: 20,
                        background: `${COLORS.danger}10`,
                        border: `2px solid ${COLORS.danger}`,
                        borderRadius: 12
                      }}>
                        <div style={{ fontSize: 9, color: COLORS.danger, marginBottom: 8, letterSpacing: "0.1em" }}>
                          THREATS SELECTED
                        </div>
                        <div style={{ fontSize: 32, fontWeight: 900, color: COLORS.danger }}>
                          {selectedThreats.length}
                        </div>
                      </div>
                      
                      <div style={{
                        padding: 20,
                        background: `${COLORS.success}10`,
                        border: `2px solid ${COLORS.success}`,
                        borderRadius: 12
                      }}>
                        <div style={{ fontSize: 9, color: COLORS.success, marginBottom: 8, letterSpacing: "0.1em" }}>
                          CONTROLS NEEDED
                        </div>
                        <div style={{ fontSize: 32, fontWeight: 900, color: COLORS.success }}>
                          {highlightedControls.size}
                        </div>
                      </div>
                      
                      <div style={{
                        padding: 20,
                        background: `${ZERO_TRUST_MATURITY[maturityLevel].color}10`,
                        border: `2px solid ${ZERO_TRUST_MATURITY[maturityLevel].color}`,
                        borderRadius: 12
                      }}>
                        <div style={{ fontSize: 9, color: ZERO_TRUST_MATURITY[maturityLevel].color, marginBottom: 8, letterSpacing: "0.1em" }}>
                          MATURITY LEVEL
                        </div>
                        <div style={{ fontSize: 18, fontWeight: 900, color: ZERO_TRUST_MATURITY[maturityLevel].color }}>
                          {ZERO_TRUST_MATURITY[maturityLevel].level}
                        </div>
                      </div>
                    </div>

                    <div style={{
                      padding: 20,
                      background: `${COLORS.accent}10`,
                      border: `1px solid ${COLORS.accent}40`,
                      borderRadius: 12
                    }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: COLORS.accentBright, marginBottom: 12 }}>
                        💡 Defense Strategy Summary
                      </div>
                      <div style={{ fontSize: 11, color: COLORS.text, lineHeight: 1.6 }}>
                        To defend against the {selectedThreats.length} selected threat{selectedThreats.length !== 1 ? 's' : ''}, 
                        you need to implement {highlightedControls.size} conditional access control{highlightedControls.size !== 1 ? 's' : ''}. 
                        This configuration will achieve <strong>{ZERO_TRUST_MATURITY[maturityLevel].level}</strong> Zero Trust maturity 
                        and provide coverage across {Object.keys(layerCoverage).length} defense layer{Object.keys(layerCoverage).length !== 1 ? 's' : ''}.
                      </div>
                    </div>
                  </>
                ) : (
                  <div style={{
                    padding: 40,
                    textAlign: "center",
                    color: COLORS.textMuted,
                    fontSize: 12,
                    fontStyle: "italic"
                  }}>
                    Select threats below to see comprehensive coverage analysis
                  </div>
                )}
              </div>
            )}

            {/* MITRE Matrix View */}
            {analysisView === 'matrix' && (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright }}>
                    📊 MITRE ATT&CK Technique Coverage Matrix
                  </div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 12 }}>
                    Green = Will be mitigated by recommended controls, Red = Not addressed by current threat selection
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 10 }}>
                  {allThreats.map(threatId => {
                    const threat = MITRE_TECHNIQUES[threatId];
                    const isSelected = selectedThreats.includes(threatId);
                    const isCovered = coveredThreats.has(threatId);
                    const coveringControls = POLICY_CONTROLS.filter(c => 
                      highlightedControls.has(c.id) && c.mitreBlocked.includes(threatId)
                    );
                    
                    return (
                      <div
                        key={threatId}
                        style={{
                          background: isCovered ? `${COLORS.success}08` : `${COLORS.danger}08`,
                          border: `2px solid ${isSelected ? COLORS.accentBright : isCovered ? `${COLORS.success}40` : `${COLORS.danger}40`}`,
                          borderRadius: 8,
                          padding: 12,
                          transition: "all 0.2s",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <span style={{ 
                              fontFamily: "monospace", 
                              fontWeight: 700, 
                              fontSize: 9, 
                              color: COLORS.textMuted, 
                              background: COLORS.surfaceAlt, 
                              padding: "2px 6px", 
                              borderRadius: 3 
                            }}>
                              {threatId}
                            </span>
                            <span style={{ 
                              fontSize: 8, 
                              padding: "2px 6px", 
                              borderRadius: 3, 
                              background: threat.severity === 'High' ? `${COLORS.danger}20` : `${COLORS.warning}20`, 
                              color: threat.severity === 'High' ? COLORS.danger : COLORS.warning, 
                              fontWeight: 700 
                            }}>
                              {threat.severity}
                            </span>
                          </div>
                          <span style={{ fontSize: 18, lineHeight: 1 }}>
                            {isCovered ? "✓" : "✗"}
                          </span>
                        </div>
                        
                        <div style={{ fontWeight: 700, fontSize: 11, marginBottom: 4, color: COLORS.text }}>
                          {threat.name}
                        </div>
                        
                        <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>
                          {threat.tactic}
                        </div>
                        
                        <div style={{ fontSize: 8, color: COLORS.textDim, fontStyle: "italic", marginBottom: 8 }}>
                          {threat.desc}
                        </div>
                        
                        {isSelected && (
                          <div style={{
                            fontSize: 8,
                            padding: "4px 8px",
                            background: `${COLORS.accentBright}20`,
                            color: COLORS.accentBright,
                            borderRadius: 4,
                            marginBottom: 8,
                            fontWeight: 700
                          }}>
                            🎯 SELECTED FOR DEFENSE
                          </div>
                        )}
                        
                        {isCovered && coveringControls.length > 0 && (
                          <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` }}>
                            <div style={{ fontSize: 9, color: COLORS.success, fontWeight: 700, marginBottom: 6 }}>
                              ✓ MITIGATED BY:
                            </div>
                            {coveringControls.map(c => (
                              <div 
                                key={c.id} 
                                style={{ 
                                  fontSize: 9, 
                                  color: COLORS.textDim, 
                                  marginBottom: 4, 
                                  paddingLeft: 8, 
                                  borderLeft: `2px solid ${CONTROL_COLORS[c.id] || COLORS.success}` 
                                }}
                              >
                                • {c.label}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Zero Trust View */}
            {analysisView === 'zerotrust' && (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright }}>
                    🔍 Zero Trust Maturity Assessment
                  </div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 12 }}>
                    Based on Microsoft Zero Trust deployment framework and CISA Zero Trust Maturity Model
                  </div>
                </div>

                {/* Current Maturity Level */}
                <div style={{ 
                  background: COLORS.surfaceAlt, 
                  borderRadius: 12, 
                  padding: 20, 
                  marginBottom: 16, 
                  border: `2px solid ${ZERO_TRUST_MATURITY[maturityLevel].color}` 
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                    <div style={{ fontSize: 48 }}>🏆</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 4, letterSpacing: "0.1em" }}>
                        CURRENT MATURITY LEVEL
                      </div>
                      <div style={{ 
                        fontSize: 20, 
                        fontWeight: 700, 
                        color: ZERO_TRUST_MATURITY[maturityLevel].color, 
                        marginBottom: 6 
                      }}>
                        {ZERO_TRUST_MATURITY[maturityLevel].level}
                      </div>
                      <div style={{ fontSize: 10, color: COLORS.textDim }}>
                        {ZERO_TRUST_MATURITY[maturityLevel].desc}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Zero Trust Principles Coverage */}
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, marginBottom: 12, color: COLORS.text }}>
                    Microsoft Zero Trust Principles Coverage
                  </div>
                  <div style={{ display: "grid", gap: 12 }}>
                    {Object.entries(ZERO_TRUST_PRINCIPLES).map(([key, principle]) => {
                      const controls = ztCoverage[key] || [];
                      const coveragePercent = Math.min(100, (controls.length / 3) * 100);
                      
                      return (
                        <div 
                          key={key} 
                          style={{ 
                            background: COLORS.surfaceAlt, 
                            borderRadius: 8, 
                            padding: 16, 
                            border: `1px solid ${principle.color}30` 
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
                            <div style={{ fontSize: 24 }}>{principle.icon}</div>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: 11, fontWeight: 700, color: principle.color, marginBottom: 4 }}>
                                {principle.label}
                              </div>
                              <div style={{ 
                                height: 6, 
                                background: COLORS.border, 
                                borderRadius: 3, 
                                overflow: "hidden" 
                              }}>
                                <div style={{ 
                                  height: "100%", 
                                  width: `${coveragePercent}%`, 
                                  background: principle.color, 
                                  transition: "width 0.5s" 
                                }} />
                              </div>
                            </div>
                            <div style={{ fontSize: 12, fontWeight: 700, color: principle.color }}>
                              {controls.length} control{controls.length !== 1 ? 's' : ''}
                            </div>
                          </div>
                          {controls.length > 0 && (
                            <div style={{ paddingLeft: 36 }}>
                              {controls.map(c => (
                                <div key={c.id} style={{ fontSize: 9, color: COLORS.textDim, marginBottom: 2 }}>
                                  • {c.label}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Maturity Recommendations */}
                {maturityLevel !== 'optimal' && selectedThreats.length > 0 && (
                  <div style={{ 
                    background: `${COLORS.accentBright}10`, 
                    border: `1px solid ${COLORS.accentBright}40`, 
                    borderRadius: 8, 
                    padding: 14 
                  }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.accentBright, marginBottom: 8 }}>
                      📈 Path to Optimal Zero Trust Maturity
                    </div>
                    <div style={{ fontSize: 9, color: COLORS.textDim, marginBottom: 8 }}>
                      To achieve Optimal maturity level, consider adding these threats to your defense strategy:
                    </div>
                    <div style={{ fontSize: 9, color: COLORS.text }}>
                      {!highlightedControls.has('phish_mfa') && (
                        <div style={{ marginBottom: 4 }}>
                          • Add threats that require Phishing-resistant MFA (T1621, T1557, T1606)
                        </div>
                      )}
                      {!highlightedControls.has('compliant_device') && (
                        <div style={{ marginBottom: 4 }}>
                          • Add threats that require Device compliance (T1528, T1539)
                        </div>
                      )}
                      {highlightedControls.size < 6 && (
                        <div style={{ marginBottom: 4 }}>
                          • Select more threats to implement additional layered controls for defense in depth
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Defense in Depth View */}
            {analysisView === 'defense' && (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright }}>
                    🛡️ Defense in Depth Layer Analysis
                  </div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 12 }}>
                    Microsoft security framework: Multiple layers of protection ensure no single point of failure
                  </div>
                </div>

                {/* Layer Visualization */}
                <div style={{ position: "relative", marginBottom: 24 }}>
                  {DEFENSE_IN_DEPTH_LAYERS.map((layer, idx) => {
                    const controlCount = layerCoverage[layer.layer] || 0;
                    const isActive = controlCount > 0;
                    const size = 60 + (idx * 30);
                    
                    return (
                      <div
                        key={layer.layer}
                        style={{
                          position: idx === 0 ? "relative" : "absolute",
                          left: "50%",
                          top: idx === 0 ? 0 : `${idx * 40}px`,
                          transform: "translateX(-50%)",
                          width: `${size}%`,
                          height: 80,
                          background: isActive ? `${layer.color}15` : `${COLORS.border}10`,
                          border: `2px solid ${isActive ? layer.color : COLORS.border}`,
                          borderRadius: 12,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          zIndex: DEFENSE_IN_DEPTH_LAYERS.length - idx,
                          transition: "all 0.3s",
                        }}
                      >
                        <div style={{ textAlign: "center" }}>
                          <div style={{ 
                            fontSize: 11, 
                            fontWeight: 700, 
                            color: isActive ? layer.color : COLORS.textMuted, 
                            marginBottom: 2 
                          }}>
                            {layer.layer}
                          </div>
                          <div style={{ fontSize: 8, color: COLORS.textDim }}>
                            {layer.example}
                          </div>
                          {isActive && (
                            <div style={{ fontSize: 8, color: layer.color, marginTop: 4, fontWeight: 700 }}>
                              {controlCount} control{controlCount > 1 ? 's' : ''} active
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div style={{ marginTop: `${DEFENSE_IN_DEPTH_LAYERS.length * 40 + 100}px` }}>
                  {/* Layer Details */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                    {DEFENSE_IN_DEPTH_LAYERS.map(layer => {
                      const controlCount = layerCoverage[layer.layer] || 0;
                      const isActive = controlCount > 0;
                      
                      return (
                        <div 
                          key={layer.layer} 
                          style={{ 
                            background: COLORS.surfaceAlt, 
                            borderRadius: 8, 
                            padding: 14, 
                            border: `1px solid ${isActive ? layer.color : COLORS.border}` 
                          }}
                        >
                          <div style={{ 
                            display: "flex", 
                            alignItems: "center", 
                            justifyContent: "space-between", 
                            marginBottom: 8 
                          }}>
                            <div style={{ 
                              fontSize: 11, 
                              fontWeight: 700, 
                              color: isActive ? layer.color : COLORS.textMuted 
                            }}>
                              {layer.layer} Layer
                            </div>
                            {isActive ? (
                              <span style={{ fontSize: 16, color: layer.color }}>✓</span>
                            ) : (
                              <span style={{ fontSize: 16, color: COLORS.textMuted }}>○</span>
                            )}
                          </div>
                          <div style={{ fontSize: 9, color: COLORS.textDim, marginBottom: 8 }}>
                            {layer.example}
                          </div>
                          <div style={{ 
                            fontSize: 9, 
                            color: isActive ? COLORS.success : COLORS.warning, 
                            fontWeight: 700 
                          }}>
                            {isActive 
                              ? `${controlCount} control${controlCount > 1 ? 's' : ''} protecting this layer` 
                              : 'Not covered by current threat selection'}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Defense in Depth Best Practice */}
                  <div style={{ 
                    marginTop: 16, 
                    background: `${COLORS.accentBright}10`, 
                    border: `1px solid ${COLORS.accentBright}40`, 
                    borderRadius: 8, 
                    padding: 14 
                  }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.accentBright, marginBottom: 6 }}>
                      📚 Microsoft Defense in Depth Principle
                    </div>
                    <div style={{ fontSize: 9, color: COLORS.textDim }}>
                      Defense in Depth is a layered approach to security. If one layer is compromised, subsequent 
                      layers provide continued protection. Microsoft recommends implementing controls across ALL 
                      layers - from network perimeter to data encryption - to ensure comprehensive security posture. 
                      Each layer reduces the attack surface and provides additional opportunities to detect and prevent threats.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Main Builder Area with Sidebar */}
        {canStartBuilding && (
          <div style={{ display: "grid", gridTemplateColumns: "400px 1fr 320px", gap: 24, marginBottom: 24 }}>
            {/* Left: Threat Palette */}
            <div style={{
              background: COLORS.surface,
              borderRadius: 16,
              padding: 20,
              border: `1px solid ${COLORS.border}`,
              height: "fit-content",
              maxHeight: "calc(100vh - 400px)",
              overflowY: "auto"
            }}>
              <div style={{ fontSize: 11, letterSpacing: "0.1em", color: COLORS.textMuted, marginBottom: 16, fontWeight: 700 }}>
                MITRE ATT&CK THREATS
              </div>
              <div style={{ fontSize: 10, color: COLORS.textDim, marginBottom: 16 }}>
                Drag threats to the drop zone to see which controls protect against them
              </div>

              {Object.entries(MITRE_TECHNIQUES).map(([threatId, threat]) => {
                const isSelected = selectedThreats.includes(threatId);
                
                return (
                  <div
                    key={threatId}
                    draggable={!isSelected}
                    onDragStart={(e) => {
                      if (!isSelected) {
                        setDraggedThreat(threatId);
                        e.dataTransfer.effectAllowed = "move";
                      }
                    }}
                    onDragEnd={() => setDraggedThreat(null)}
                    style={{
                      padding: 12,
                      marginBottom: 10,
                      background: isSelected ? `${COLORS.textMuted}20` : `${COLORS.danger}10`,
                      border: `2px solid ${isSelected ? COLORS.textMuted : COLORS.danger}`,
                      borderRadius: 8,
                      cursor: isSelected ? "not-allowed" : "grab",
                      opacity: isSelected ? 0.4 : 1,
                      transition: "all 0.2s"
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 6 }}>
                      <div style={{
                        fontSize: 9,
                        fontFamily: "monospace",
                        fontWeight: 700,
                        color: isSelected ? COLORS.textMuted : COLORS.danger,
                        background: COLORS.surfaceAlt,
                        padding: "2px 6px",
                        borderRadius: 3
                      }}>
                        {threatId}
                      </div>
                      <div style={{
                        fontSize: 8,
                        padding: "2px 6px",
                        borderRadius: 3,
                        background: threat.severity === 'High' ? `${COLORS.danger}30` : `${COLORS.warning}30`,
                        color: threat.severity === 'High' ? COLORS.danger : COLORS.warning,
                        fontWeight: 700
                      }}>
                        {threat.severity}
                      </div>
                    </div>
                    
                    <div style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: isSelected ? COLORS.textMuted : COLORS.text,
                      marginBottom: 4
                    }}>
                      {threat.name}
                    </div>
                    
                    <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>
                      {threat.tactic}
                    </div>
                    
                    {!isSelected && (
                      <div style={{ fontSize: 8, color: COLORS.textDim, fontStyle: "italic" }}>
                        {threat.desc}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Center: Drop Zone & Required Controls */}
            <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
              {/* Threat Drop Zone */}
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (draggedThreat) {
                    handleDropThreat(draggedThreat);
                  }
                }}
                style={{
                  background: draggedThreat ? `${COLORS.danger}10` : COLORS.surface,
                  border: `2px dashed ${draggedThreat ? COLORS.danger : COLORS.border}`,
                  borderRadius: 16,
                  padding: 32,
                  minHeight: 200,
                  transition: "all 0.3s"
                }}
              >
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, letterSpacing: "0.1em", color: COLORS.textMuted, fontWeight: 700 }}>
                    THREATS TO DEFEND AGAINST
                  </div>
                  <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 4 }}>
                    Drop threats here to build your defense strategy
                  </div>
                </div>

                {selectedThreats.length === 0 ? (
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    minHeight: 120,
                    color: COLORS.textMuted,
                    fontSize: 14,
                    fontStyle: "italic"
                  }}>
                    {draggedThreat ? "Drop threat here" : "No threats selected yet"}
                  </div>
                ) : (
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12 }}>
                    {selectedThreats.map(threatId => {
                      const threat = MITRE_TECHNIQUES[threatId];
                      return (
                        <div
                          key={threatId}
                          style={{
                            background: `${COLORS.danger}15`,
                            border: `2px solid ${COLORS.danger}`,
                            borderRadius: 12,
                            padding: 12,
                            position: "relative"
                          }}
                        >
                          <button
                            onClick={() => removeThreat(threatId)}
                            style={{
                              position: "absolute",
                              top: 8,
                              right: 8,
                              background: COLORS.danger,
                              border: "none",
                              borderRadius: "50%",
                              width: 20,
                              height: 20,
                              color: "white",
                              cursor: "pointer",
                              fontSize: 12,
                              fontWeight: 700,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center"
                            }}
                          >
                            ×
                          </button>
                          
                          <div style={{
                            fontSize: 9,
                            fontFamily: "monospace",
                            fontWeight: 700,
                            color: COLORS.danger,
                            marginBottom: 6
                          }}>
                            {threatId}
                          </div>
                          
                          <div style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: COLORS.text,
                            marginBottom: 4
                          }}>
                            {threat.name}
                          </div>
                          
                          <div style={{ fontSize: 9, color: COLORS.textMuted }}>
                            {threat.tactic}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Required Controls Panel */}
              {selectedThreats.length > 0 && (
                <div style={{
                  background: COLORS.surface,
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 16,
                  padding: 24
                }}>
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ fontSize: 11, letterSpacing: "0.1em", color: COLORS.textMuted, fontWeight: 700 }}>
                      RECOMMENDED CONTROLS
                    </div>
                    <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 4 }}>
                      These controls will mitigate the threats you've selected
                    </div>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {controlsNeeded.map(({ control, threats }) => {
                      const color = CONTROL_COLORS[control.id] || COLORS.accent;
                      const shouldPulse = pulseControls && threats.length > 0;
                      
                      return (
                        <div
                          key={control.id}
                          style={{
                            background: COLORS.surfaceAlt,
                            border: `2px solid ${color}`,
                            borderRadius: 12,
                            padding: 16,
                            transform: shouldPulse ? "scale(1.02)" : "scale(1)",
                            boxShadow: shouldPulse ? `0 0 20px ${color}40` : "none",
                            transition: "all 0.3s ease"
                          }}
                        >
                          <div style={{ display: "flex", gap: 12 }}>
                            <div style={{
                              width: 4,
                              background: `linear-gradient(180deg, ${color}, ${color}80)`,
                              borderRadius: 2,
                              flexShrink: 0
                            }} />
                            
                            <div style={{ flex: 1 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: 8 }}>
                                <div>
                                  <div style={{ fontSize: 13, fontWeight: 700, color: color, marginBottom: 4 }}>
                                    {control.label}
                                  </div>
                                  <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 6 }}>
                                    {control.desc}
                                  </div>
                                  <div style={{ fontSize: 9, color: COLORS.textDim, fontStyle: "italic" }}>
                                    {control.why}
                                  </div>
                                </div>
                                
                                <div style={{
                                  padding: "6px 12px",
                                  background: `${COLORS.success}20`,
                                  border: `1px solid ${COLORS.success}`,
                                  borderRadius: 6,
                                  fontSize: 10,
                                  fontWeight: 700,
                                  color: COLORS.success,
                                  whiteSpace: "nowrap"
                                }}>
                                  -{control.baseRiskReduction}% RISK
                                </div>
                              </div>

                              <div style={{ marginBottom: 8 }}>
                                <div style={{ fontSize: 9, color: COLORS.success, marginBottom: 4, fontWeight: 700 }}>
                                  MITIGATES {threats.length} SELECTED THREAT{threats.length !== 1 ? 'S' : ''}:
                                </div>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                                  {threats.map(threatId => (
                                    <span
                                      key={threatId}
                                      style={{
                                        fontSize: 8,
                                        padding: "3px 6px",
                                        borderRadius: 4,
                                        background: `${COLORS.success}20`,
                                        color: COLORS.success,
                                        fontFamily: "monospace",
                                        fontWeight: 600
                                      }}
                                    >
                                      {threatId}
                                    </span>
                                  ))}
                                </div>
                              </div>

                              <div style={{
                                fontSize: 9,
                                padding: 10,
                                background: `${COLORS.accent}08`,
                                borderRadius: 6,
                                border: `1px solid ${COLORS.accent}20`,
                                color: COLORS.accentBright
                              }}>
                                💡 <strong>Best Practice:</strong> {control.bestPractice}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Right Sidebar: Real-Time Analytics */}
            <div style={{ position: "sticky", top: 24, height: "fit-content" }}>
              {/* Risk Score */}
              <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>REAL-TIME RISK ANALYSIS</div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-around", marginBottom: 14 }}>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, marginBottom: 6 }}>BASELINE</div>
                    <RiskMeter score={baseRisk} size={70} />
                  </div>
                  <div style={{ fontSize: 18, color: COLORS.accentBright }}>→</div>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, marginBottom: 6 }}>CURRENT</div>
                    <RiskMeter score={finalRisk} size={70} />
                  </div>
                </div>
                <div style={{ textAlign: "center", padding: "8px", background: `${COLORS.success}10`, borderRadius: 6, border: `1px solid ${COLORS.success}30` }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.success }}>
                    ↓ {riskReduction} POINTS REDUCED
                  </div>
                </div>
              </div>

              {/* MITRE Coverage */}
              <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 12 }}>MITRE ATT&CK COVERAGE</div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontSize: 9, color: COLORS.textMuted }}>TECHNIQUES MITIGATED</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: COLORS.success }}>{coveredThreats.size}/{allThreats.length}</span>
                  </div>
                  <div style={{ height: 6, background: COLORS.border, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${coveragePercent}%`, background: `linear-gradient(90deg, ${COLORS.success}, ${COLORS.accentBright})`, transition: "width 0.5s" }} />
                  </div>
                  <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.success, marginTop: 4, textAlign: "center" }}>{coveragePercent}%</div>
                </div>

                {/* Coverage by Severity */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  {['High', 'Medium'].map(severity => {
                    const total = Object.values(MITRE_TECHNIQUES).filter(t => t.severity === severity).length;
                    const coveredCount = Object.entries(MITRE_TECHNIQUES)
                      .filter(([id, t]) => t.severity === severity && coveredThreats.has(id))
                      .length;
                    return (
                      <div key={severity} style={{ background: COLORS.surfaceAlt, borderRadius: 6, padding: 8 }}>
                        <div style={{ fontSize: 8, color: COLORS.textMuted, marginBottom: 4 }}>{severity.toUpperCase()}</div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: coveredCount === total ? COLORS.success : COLORS.warning }}>
                          {coveredCount}/{total}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Active Controls */}
              <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 10 }}>
                  ACTIVE CONTROLS ({highlightedControls.size})
                </div>
                {highlightedControls.size === 0 ? (
                  <div style={{ fontSize: 10, color: COLORS.textMuted, textAlign: "center", padding: 16 }}>No controls selected</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {Array.from(highlightedControls).map(id => {
                      const c = POLICY_CONTROLS.find(p => p.id === id);
                      const col = CONTROL_COLORS[id] || COLORS.accent;
                      return (
                        <div key={id} style={{ fontSize: 9, color: col, display: "flex", alignItems: "center", gap: 6 }}>
                          <div style={{ width: 4, height: 4, borderRadius: "50%", background: col }} />
                          <span>{c?.label}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Uncovered Threats */}
              {coveredThreats.size < allThreats.length && selectedThreats.length > 0 && (
                <div style={{ background: `${COLORS.danger}08`, border: `1px solid ${COLORS.danger}30`, borderRadius: 12, padding: 14 }}>
                  <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.danger, marginBottom: 8 }}>⚠ GAPS IDENTIFIED</div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 8 }}>
                    {allThreats.length - coveredThreats.size} techniques not mitigated
                  </div>
                  <div style={{ fontSize: 8, color: COLORS.textDim }}>
                    {Object.entries(MITRE_TECHNIQUES)
                      .filter(([id]) => !coveredThreats.has(id))
                      .slice(0, 3)
                      .map(([id, t]) => (
                        <div key={id} style={{ marginBottom: 2 }}>• {id}: {t.name}</div>
                      ))}
                    {allThreats.length - coveredThreats.size > 3 && (
                      <div style={{ marginTop: 4, fontSize: 8, color: COLORS.textMuted }}>
                        +{allThreats.length - coveredThreats.size - 3} more...
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}


      </div>
    </div>
  );
}
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<ThreatFirstCABuilder />);
