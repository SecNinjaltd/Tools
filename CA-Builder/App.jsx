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
  app_protection: "#14b8a6",
  named_locations: "#eab308",
  sign_in_risk: "#ef4444",
  user_risk: "#ec4899",
  session_controls: "#6366f1",
};

const ZERO_TRUST_PRINCIPLES = {
  verify: { label: "Verify Explicitly", color: "#3b82f6", icon: "🔍" },
  least: { label: "Least Privilege", color: "#8b5cf6", icon: "🔒" },
  breach: { label: "Assume Breach", color: "#ef4444", icon: "🛡️" },
};

// MITRE ATT&CK techniques relevant to identity/access
const MITRE_TECHNIQUES = {
  'T1078': { name: 'Valid Accounts', tactic: 'Initial Access', desc: 'Adversaries may obtain and abuse credentials of existing accounts' },
  'T1110': { name: 'Brute Force', tactic: 'Credential Access', desc: 'Adversaries may use brute force techniques to gain access to accounts' },
  'T1528': { name: 'Steal Application Access Token', tactic: 'Credential Access', desc: 'Adversaries may steal application access tokens as a means of acquiring credentials' },
  'T1539': { name: 'Steal Web Session Cookie', tactic: 'Credential Access', desc: 'Adversaries may steal web application or service session cookies' },
  'T1556': { name: 'Modify Authentication Process', tactic: 'Credential Access', desc: 'Adversaries may modify authentication mechanisms to access user credentials' },
  'T1621': { name: 'MFA Request Generation', tactic: 'Credential Access', desc: 'Adversaries may attempt to bypass MFA through push bombing or fatigue attacks' },
  'T1098': { name: 'Account Manipulation', tactic: 'Persistence', desc: 'Adversaries may manipulate accounts to maintain access to systems' },
  'T1484': { name: 'Domain Policy Modification', tactic: 'Defense Evasion', desc: 'Adversaries may modify domain policies to evade defenses' },
  'T1557': { name: 'Adversary-in-the-Middle', tactic: 'Credential Access', desc: 'Adversaries may position themselves between communications to steal credentials' },
  'T1606': { name: 'Forge Web Credentials', tactic: 'Credential Access', desc: 'Adversaries may forge credential materials to gain unauthorized access' },
};

const IDENTITY_TYPES = [
  { id: "user", label: "Standard User", icon: "👤", desc: "Regular employees, contractors, or guests", baseRisk: 45 },
  { id: "admin", label: "Administrator", icon: "⚙️", desc: "Global admin, security admin, privileged roles", baseRisk: 85 },
  { id: "guest", label: "Guest / External", icon: "🌐", desc: "B2B collaborators, partner accounts", baseRisk: 70 },
  { id: "workload", label: "Workload Identity", icon: "🤖", desc: "Service principals, managed identities", baseRisk: 60 },
];

const ACCESS_TARGETS = [
  { id: "all_apps", label: "All Cloud Apps", icon: "☁️", desc: "Broadest coverage — all Microsoft and connected apps" },
  { id: "admin_portals", label: "Microsoft Admin Portals", icon: "🏛️", desc: "Azure Portal, Entra, Intune, Security Center" },
  { id: "office365", label: "Microsoft 365", icon: "📧", desc: "Exchange, SharePoint, Teams, OneDrive" },
  { id: "specific", label: "Specific Applications", icon: "🎯", desc: "Target individual registered apps by name" },
];

const POLICY_CONTROLS = [
  {
    id: "phish_mfa", label: "Require Phishing-Resistant MFA", category: "authentication", riskReduction: 35,
    ztPrinciples: ["verify"],
    desc: "Enforce FIDO2 security keys or Windows Hello — cryptographically bound to origin",
    why: "Traditional MFA can be bypassed via real-time phishing proxies (e.g. Evilginx2) and MFA fatigue attacks. Phishing-resistant MFA cryptographically binds authentication to the exact origin domain.",
    attacksBlocked: ["Phishing", "MFA fatigue", "Adversary-in-the-middle", "Real-time phishing proxy"],
    mitreBlocked: ['T1621', 'T1110', 'T1557', 'T1078'],
    warnings: ["Requires FIDO2 hardware security keys or Windows Hello for Business"],
    note: "Supersedes standard MFA — enabling this is the gold standard",
  },
  {
    id: "mfa", label: "Require MFA", category: "authentication", riskReduction: 25,
    ztPrinciples: ["verify"],
    desc: "Require multi-factor authentication at every sign-in",
    why: "MFA blocks 99.9% of automated account compromise attacks — even if credentials are stolen.",
    attacksBlocked: ["Credential stuffing", "Password spray", "Brute force"],
    mitreBlocked: ['T1110', 'T1078'],
    warnings: [], note: null,
  },
  {
    id: "legacy_auth", label: "Block Legacy Authentication", category: "authentication", riskReduction: 22,
    ztPrinciples: ["verify"],
    desc: "Block protocols that don't support MFA (IMAP, POP3, SMTP Auth)",
    why: "Over 99% of password spray attacks use legacy authentication — blocking it is non-negotiable.",
    attacksBlocked: ["Password spray via legacy protocols", "Brute force"],
    mitreBlocked: ['T1110', 'T1078'],
    warnings: ["Check for legacy mail clients before enabling"],
    note: null,
  },
  {
    id: "compliant_device", label: "Require Compliant Device", category: "device", riskReduction: 20,
    ztPrinciples: ["verify", "breach"],
    desc: "Only allow access from Intune-enrolled, compliant devices",
    why: "Unmanaged devices are a major attack surface. Ensures endpoint security baselines are met.",
    attacksBlocked: ["Unmanaged device compromise", "Lateral movement", "Token theft from BYOD"],
    mitreBlocked: ['T1078', 'T1528', 'T1539'],
    warnings: ["Ensure users have enrolled devices before enabling"],
    note: null,
  },
  {
    id: "app_protection", label: "Require App Protection Policy", category: "device", riskReduction: 8,
    ztPrinciples: ["least", "breach"],
    desc: "Require Intune App Protection Policies on mobile devices",
    why: "Ensures corporate data is containerised and can be wiped independently of the device.",
    attacksBlocked: ["Data leakage from mobile", "Lost/stolen device exposure"],
    mitreBlocked: ['T1539'],
    warnings: [], note: null,
  },
  {
    id: "named_locations", label: "Restrict to Trusted Locations", category: "location", riskReduction: 15,
    ztPrinciples: ["verify"],
    desc: "Limit or flag access from outside known corporate IP ranges",
    why: "Geo-fencing reduces the blast radius of compromised credentials.",
    attacksBlocked: ["Off-network attacks", "Impossible travel scenarios"],
    mitreBlocked: ['T1078'],
    warnings: ["Remote workers need their home IPs or VPN included"],
    note: null,
  },
  {
    id: "sign_in_risk", label: "Block Risky Sign-ins", category: "risk", riskReduction: 18,
    ztPrinciples: ["verify", "breach"],
    desc: "Leverage Entra ID Protection to block high-risk sign-ins automatically",
    why: "Real-time ML models detect anomalous sign-in patterns — leaked credentials, unfamiliar locations.",
    attacksBlocked: ["Leaked credentials", "Malicious IPs", "Token replay", "Impossible travel"],
    mitreBlocked: ['T1078', 'T1528', 'T1606'],
    warnings: ["Requires Entra ID P2 licence"],
    note: null,
  },
  {
    id: "user_risk", label: "Require Password Change on User Risk", category: "risk", riskReduction: 12,
    ztPrinciples: ["breach"],
    desc: "Force secure password reset when account is flagged as compromised",
    why: "When credentials appear in breach dumps, force immediate remediation.",
    attacksBlocked: ["Compromised credentials in the wild"],
    mitreBlocked: ['T1078', 'T1098'],
    warnings: ["Requires Entra ID P2 licence"],
    note: null,
  },
  {
    id: "session_controls", label: "Session Controls & Token Lifetime", category: "session", riskReduction: 10,
    ztPrinciples: ["least", "breach"],
    desc: "Limit session duration, disable persistent browser sessions",
    why: "Short-lived tokens reduce the window for token replay and session hijacking attacks.",
    attacksBlocked: ["Token replay", "Session hijacking", "Persistent session abuse"],
    mitreBlocked: ['T1528', 'T1539'],
    warnings: [], note: null,
  },
];

const Btn = ({ label, onClick, disabled, danger, secondary }) => (
  <button
    onClick={onClick}
    disabled={disabled}
    style={{
      background: disabled ? COLORS.surfaceAlt : danger ? `${COLORS.danger}18` : secondary ? `${COLORS.textMuted}18` : `${COLORS.accent}18`,
      border: `1px solid ${disabled ? COLORS.border : danger ? `${COLORS.danger}50` : secondary ? `${COLORS.textMuted}50` : `${COLORS.accent}50`}`,
      color: disabled ? COLORS.textMuted : danger ? COLORS.danger : secondary ? COLORS.textDim : COLORS.accentBright,
      padding: "9px 18px",
      borderRadius: 8,
      cursor: disabled ? "not-allowed" : "pointer",
      fontSize: 10,
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

const RiskMeter = ({ score }) => {
  const getColor = () => {
    if (score < 25) return COLORS.success;
    if (score < 50) return COLORS.warning;
    return COLORS.danger;
  };
  return (
    <div style={{ position: "relative", width: 80, height: 80 }}>
      <svg width="80" height="80" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="40" cy="40" r="32" fill="none" stroke={COLORS.border} strokeWidth="6" />
        <circle cx="40" cy="40" r="32" fill="none" stroke={getColor()} strokeWidth="6"
          strokeDasharray={`${2 * Math.PI * 32}`}
          strokeDashoffset={`${2 * Math.PI * 32 * (1 - score / 100)}`}
          style={{ transition: "stroke-dashoffset 1s" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, fontWeight: 700, color: getColor() }}>
        {score}
      </div>
    </div>
  );
};

const ThreatCoverageMap = ({ controls }) => {
  const allMitre = new Set();
  const coveredMitre = new Set();
  
  Object.values(MITRE_TECHNIQUES).forEach((_, idx) => {
    const id = Object.keys(MITRE_TECHNIQUES)[idx];
    allMitre.add(id);
  });
  
  controls.forEach(controlId => {
    const ctrl = POLICY_CONTROLS.find(c => c.id === controlId);
    if (ctrl?.mitreBlocked) {
      ctrl.mitreBlocked.forEach(m => coveredMitre.add(m));
    }
  });

  const coverage = Math.round((coveredMitre.size / allMitre.size) * 100);

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ flex: 1, height: 8, background: COLORS.border, borderRadius: 4, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${coverage}%`, background: `linear-gradient(90deg, ${COLORS.success}, ${COLORS.accentBright})`, transition: "width 1s" }} />
        </div>
        <div style={{ fontSize: 13, fontWeight: 700, color: COLORS.success }}>{coverage}% MITRE Coverage</div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 8 }}>
        {Object.entries(MITRE_TECHNIQUES).map(([id, tech]) => {
          const covered = coveredMitre.has(id);
          const coveringControls = POLICY_CONTROLS.filter(c => controls.includes(c.id) && c.mitreBlocked?.includes(id));
          
          return (
            <div key={id} style={{
              background: covered ? `${COLORS.success}08` : `${COLORS.danger}08`,
              border: `1px solid ${covered ? `${COLORS.success}30` : `${COLORS.danger}30`}`,
              borderRadius: 8,
              padding: 10,
              fontSize: 10,
            }}>
              <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 9, color: COLORS.textMuted }}>{id}</span>
                <span style={{ fontSize: 14 }}>{covered ? "✓" : "✗"}</span>
              </div>
              <div style={{ fontWeight: 700, fontSize: 11, marginBottom: 4, color: COLORS.text }}>{tech.name}</div>
              <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>{tech.tactic}</div>
              {covered && coveringControls.length > 0 && (
                <div style={{ fontSize: 9, color: COLORS.success, marginTop: 6, paddingTop: 6, borderTop: `1px solid ${COLORS.border}` }}>
                  Mitigated by: {coveringControls.map(c => c.label).join(", ")}
                </div>
              )}
            </div>
          );
        })}
      </div>
      
      {coveredMitre.size < allMitre.size && (
        <div style={{ marginTop: 16, background: `${COLORS.warning}10`, border: `1px solid ${COLORS.warning}40`, borderRadius: 8, padding: 12 }}>
          <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.warning, marginBottom: 6 }}>⚠ IDENTIFIED GAPS</div>
          <div style={{ fontSize: 10, color: COLORS.textDim }}>
            {allMitre.size - coveredMitre.size} MITRE techniques not covered. Consider adding additional controls.
          </div>
        </div>
      )}
    </div>
  );
};

const DefenseLayersVisualization = ({ controls, identity }) => {
  const baseRisk = IDENTITY_TYPES.find(i => i.id === identity)?.baseRisk || 50;
  let currentRisk = baseRisk;
  
  const layers = controls.map(controlId => {
    const ctrl = POLICY_CONTROLS.find(c => c.id === controlId);
    const layerRisk = Math.max(0, currentRisk - ctrl.riskReduction);
    const layer = {
      control: ctrl,
      startRisk: currentRisk,
      endRisk: layerRisk,
      reduction: ctrl.riskReduction,
    };
    currentRisk = layerRisk;
    return layer;
  });

  return (
    <div style={{ background: COLORS.surfaceAlt, borderRadius: 12, padding: 20, border: `1px solid ${COLORS.border}` }}>
      <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>DEFENSE IN DEPTH LAYERS</div>
      
      <div style={{ display: "flex", alignItems: "center", marginBottom: 20, gap: 12 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>BASELINE</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: COLORS.danger }}>{baseRisk}</div>
        </div>
        
        {layers.map((layer, idx) => (
          <div key={layer.control.id} style={{ flex: 1, display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ fontSize: 20, color: COLORS.accentBright }}>→</div>
            <div style={{ 
              flex: 1,
              background: `${CONTROL_COLORS[layer.control.id] || COLORS.accent}15`,
              border: `1px solid ${CONTROL_COLORS[layer.control.id] || COLORS.accent}40`,
              borderRadius: 8,
              padding: 10,
            }}>
              <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 2 }}>LAYER {idx + 1}</div>
              <div style={{ fontSize: 10, fontWeight: 700, color: CONTROL_COLORS[layer.control.id] || COLORS.accent, marginBottom: 4 }}>
                {layer.control.label}
              </div>
              <div style={{ fontSize: 10, color: COLORS.success }}>-{layer.reduction}%</div>
            </div>
          </div>
        ))}
        
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>FINAL</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: COLORS.success }}>{currentRisk}</div>
        </div>
      </div>
      
      <div style={{ fontSize: 9, color: COLORS.textMuted, textAlign: "center", marginTop: 12 }}>
        Total Risk Reduction: <span style={{ color: COLORS.success, fontWeight: 700 }}>{baseRisk - currentRisk} points</span>
      </div>
    </div>
  );
};

function ConditionalAccessBuilder() {
  const [step, setStep] = useState(0);
  const [identity, setIdentity] = useState(null);
  const [target, setTarget] = useState(null);
  const [selectedControls, setSelectedControls] = useState([]);
  const [showMitreDetail, setShowMitreDetail] = useState(null);

  const phishMfaActive = selectedControls.includes("phish_mfa");
  const standardMfaActive = selectedControls.includes("mfa") && !phishMfaActive;

  const handleReset = () => {
    setStep(0);
    setIdentity(null);
    setTarget(null);
    setSelectedControls([]);
    setShowMitreDetail(null);
  };

  const toggleControl = (id) => {
    if (id === "phish_mfa" && selectedControls.includes("mfa")) {
      setSelectedControls(prev => [...prev.filter(c => c !== "mfa"), id]);
    } else if (id === "mfa" && selectedControls.includes("phish_mfa")) {
      setSelectedControls(prev => [...prev.filter(c => c !== "phish_mfa"), id]);
    } else if (selectedControls.includes(id)) {
      setSelectedControls(prev => prev.filter(c => c !== id));
    } else {
      setSelectedControls(prev => [...prev, id]);
    }
  };

  const riskScore = () => {
    let base = IDENTITY_TYPES.find(i => i.id === identity)?.baseRisk || 50;
    selectedControls.forEach(id => {
      const c = POLICY_CONTROLS.find(p => p.id === id);
      base = Math.max(0, base - (c?.riskReduction || 0));
    });
    return base;
  };

  const warnings = POLICY_CONTROLS.filter(c => selectedControls.includes(c.id) && c.warnings.length > 0);

  return (
    <div style={{
      minHeight: "100vh",
      background: COLORS.bg,
      color: COLORS.text,
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      padding: 24,
    }}>
      <div style={{ maxWidth: 1400, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontSize: 26, fontWeight: 800, marginBottom: 6 }}>
              🛡️ Entra ID Conditional Access Policy Builder
            </div>
            <div style={{ fontSize: 12, color: COLORS.textMuted }}>
              Zero Trust-aligned policy design with MITRE ATT&CK threat mapping
            </div>
          </div>
          <Btn label="↺ RESET" onClick={handleReset} danger />
        </div>

        {/* Progress */}
        {step < 3 && (
          <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 18 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              {["1. IDENTITY", "2. ACCESS SCOPE", "3. CONTROLS", "4. REVIEW"].map((label, idx) => (
                <div key={idx} style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
                  <div style={{
                    width: 28,
                    height: 28,
                    borderRadius: "50%",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 11,
                    fontWeight: 700,
                    background: step > idx ? COLORS.success : step === idx ? COLORS.accent : COLORS.surfaceAlt,
                    color: step >= idx ? "#fff" : COLORS.textMuted,
                    border: `2px solid ${step > idx ? COLORS.success : step === idx ? COLORS.accent : COLORS.border}`,
                  }}>
                    {step > idx ? "✓" : idx + 1}
                  </div>
                  <div style={{ fontSize: 10, fontWeight: 600, color: step >= idx ? COLORS.text : COLORS.textMuted }}>
                    {label}
                  </div>
                  {idx < 3 && <div style={{ flex: 1, height: 2, background: step > idx ? COLORS.success : COLORS.border, borderRadius: 1 }} />}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 0: Identity */}
        {step === 0 && (
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Select Identity Type</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14 }}>
              {IDENTITY_TYPES.map(i => (
                <div
                  key={i.id}
                  onClick={() => { setIdentity(i.id); setStep(1); }}
                  style={{
                    background: identity === i.id ? COLORS.surfaceAlt : COLORS.surface,
                    border: `1px solid ${identity === i.id ? COLORS.accent : COLORS.border}`,
                    borderRadius: 12,
                    padding: 20,
                    cursor: "pointer",
                    transition: "all 0.15s",
                  }}
                >
                  <div style={{ fontSize: 32, marginBottom: 10 }}>{i.icon}</div>
                  <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{i.label}</div>
                  <div style={{ fontSize: 11, color: COLORS.textMuted, marginBottom: 12 }}>{i.desc}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 9, color: COLORS.textMuted }}>BASE RISK:</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: i.baseRisk > 70 ? COLORS.danger : i.baseRisk > 50 ? COLORS.warning : COLORS.success }}>
                      {i.baseRisk}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 1: Access Target */}
        {step === 1 && (
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Select Access Scope</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14 }}>
              {ACCESS_TARGETS.map(t => (
                <div
                  key={t.id}
                  onClick={() => { setTarget(t.id); setStep(2); }}
                  style={{
                    background: target === t.id ? COLORS.surfaceAlt : COLORS.surface,
                    border: `1px solid ${target === t.id ? COLORS.accent : COLORS.border}`,
                    borderRadius: 12,
                    padding: 20,
                    cursor: "pointer",
                    transition: "all 0.15s",
                  }}
                >
                  <div style={{ fontSize: 32, marginBottom: 10 }}>{t.icon}</div>
                  <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t.label}</div>
                  <div style={{ fontSize: 11, color: COLORS.textMuted }}>{t.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 16 }}>
              <Btn label="← BACK" onClick={() => setStep(0)} secondary />
            </div>
          </div>
        )}

        {/* Step 2: Controls */}
        {step === 2 && (
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Configure Security Controls</div>
            
            {/* Phishing-resistant MFA callout */}
            {identity === "admin" && !phishMfaActive && (
              <div style={{ background: `${COLORS.warning}10`, border: `1px solid ${COLORS.warning}40`, borderRadius: 12, padding: 14, marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.warning, marginBottom: 4 }}>
                  ⚠ CRITICAL RECOMMENDATION FOR ADMINISTRATORS
                </div>
                <div style={{ fontSize: 10, color: COLORS.textDim }}>
                  Phishing-resistant MFA is mandatory for all admin accounts. Standard MFA can be bypassed by sophisticated adversaries.
                </div>
              </div>
            )}

            <div style={{ display: "grid", gap: 10, marginBottom: 16 }}>
              {POLICY_CONTROLS.map(c => {
                const isSelected = selectedControls.includes(c.id);
                const col = CONTROL_COLORS[c.id] || COLORS.accent;
                const isDisabled = (c.id === "mfa" && phishMfaActive) || (c.id === "phish_mfa" && standardMfaActive);

                return (
                  <div
                    key={c.id}
                    onClick={() => !isDisabled && toggleControl(c.id)}
                    style={{
                      background: isSelected ? `${col}08` : COLORS.surface,
                      border: `1px solid ${isSelected ? `${col}50` : COLORS.border}`,
                      borderRadius: 10,
                      padding: 16,
                      cursor: isDisabled ? "not-allowed" : "pointer",
                      opacity: isDisabled ? 0.5 : 1,
                      transition: "all 0.15s",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "start", gap: 12 }}>
                      <div style={{
                        width: 18,
                        height: 18,
                        borderRadius: 4,
                        border: `2px solid ${isSelected ? col : COLORS.border}`,
                        background: isSelected ? col : "transparent",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                        marginTop: 2,
                      }}>
                        {isSelected && <span style={{ fontSize: 11, color: "#fff" }}>✓</span>}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                          <div style={{ fontSize: 13, fontWeight: 700, color: isSelected ? col : COLORS.text }}>
                            {c.label}
                          </div>
                          <div style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4, background: `${COLORS.success}20`, color: COLORS.success }}>
                            -{c.riskReduction}% RISK
                          </div>
                        </div>
                        <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 8 }}>{c.desc}</div>
                        <div style={{ fontSize: 9, color: COLORS.textDim, marginBottom: 8, fontStyle: "italic" }}>
                          Why it matters: {c.why}
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 6 }}>
                          {c.mitreBlocked.map(m => (
                            <span key={m} style={{ fontSize: 8, padding: "2px 6px", borderRadius: 3, background: `${COLORS.danger}15`, color: COLORS.danger, fontFamily: "monospace", fontWeight: 600 }}>
                              {m}
                            </span>
                          ))}
                        </div>
                        {c.note && (
                          <div style={{ fontSize: 9, color: COLORS.accentBright, marginTop: 6, padding: 8, background: `${COLORS.accent}10`, borderRadius: 6 }}>
                            💡 {c.note}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <Btn label="← BACK" onClick={() => setStep(1)} secondary />
              <Btn label="REVIEW POLICY →" onClick={() => setStep(3)} disabled={selectedControls.length === 0} />
            </div>
          </div>
        )}

        {/* Step 3: Review */}
        {step === 3 && (
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Policy Review & Threat Analysis</div>

            {/* Risk reduction summary */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>POLICY SUMMARY</div>
                <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 2 }}>IDENTITY</div>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10 }}>
                  {IDENTITY_TYPES.find(i => i.id === identity)?.icon} {IDENTITY_TYPES.find(i => i.id === identity)?.label}
                </div>
                <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 2 }}>TARGET</div>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10 }}>
                  {ACCESS_TARGETS.find(t => t.id === target)?.icon} {ACCESS_TARGETS.find(t => t.id === target)?.label}
                </div>
                <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>CONTROLS ({selectedControls.length})</div>
                {selectedControls.map(id => {
                  const c = POLICY_CONTROLS.find(p => p.id === id);
                  const col = CONTROL_COLORS[id] || COLORS.success;
                  return (
                    <div key={id} style={{ fontSize: 11, color: col, display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                      <div style={{ width: 6, height: 6, borderRadius: 1, background: col }} />✓ {c?.label}
                    </div>
                  );
                })}
              </div>
              <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>RISK REDUCTION</div>
                <div style={{ display: "flex", justifyContent: "space-around", alignItems: "center" }}>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>WITHOUT</div>
                    <RiskMeter score={IDENTITY_TYPES.find(i => i.id === identity)?.baseRisk || 50} />
                  </div>
                  <div style={{ fontSize: 22, color: COLORS.success }}>→</div>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 9, color: COLORS.textMuted, marginBottom: 6 }}>WITH POLICY</div>
                    <RiskMeter score={riskScore()} />
                  </div>
                </div>
                <div style={{ marginTop: 14, textAlign: "center" }}>
                  <div style={{ display: "inline-block", fontSize: 11, fontWeight: 700, padding: "5px 12px", borderRadius: 6, background: `${COLORS.success}15`, color: COLORS.success, border: `1px solid ${COLORS.success}40` }}>
                    ↓ {(IDENTITY_TYPES.find(i => i.id === identity)?.baseRisk || 50) - riskScore()} POINTS REDUCED
                  </div>
                </div>
              </div>
            </div>

            {/* Defense layers visualization */}
            <div style={{ marginBottom: 14 }}>
              <DefenseLayersVisualization controls={selectedControls} identity={identity} />
            </div>

            {/* MITRE ATT&CK Coverage */}
            <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 20, marginBottom: 14 }}>
              <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>MITRE ATT&CK THREAT COVERAGE</div>
              <ThreatCoverageMap controls={selectedControls} />
            </div>

            {/* Zero Trust Coverage */}
            <div style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 }}>
              <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 }}>ZERO TRUST PRINCIPLE COVERAGE</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
                {Object.entries(ZERO_TRUST_PRINCIPLES).map(([key, p]) => {
                  const n = POLICY_CONTROLS.filter(c => selectedControls.includes(c.id) && c.ztPrinciples.includes(key)).length;
                  return (
                    <div key={key} style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: 11, border: `1px solid ${p.color}30` }}>
                      <div style={{ fontSize: 16, marginBottom: 5 }}>{p.icon}</div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: p.color, marginBottom: 7 }}>{p.label}</div>
                      <div style={{ height: 4, background: COLORS.border, borderRadius: 2, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${Math.min(100, (n / 3) * 100)}%`, background: p.color, borderRadius: 2, transition: "width 0.8s" }} />
                      </div>
                      <div style={{ fontSize: 9, color: COLORS.textMuted, marginTop: 3 }}>{n} controls</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Warnings */}
            {warnings.length > 0 && (
              <div style={{ background: `${COLORS.warning}10`, border: `1px solid ${COLORS.warning}40`, borderRadius: 12, padding: 14, marginBottom: 14 }}>
                <div style={{ fontSize: 9, letterSpacing: "0.15em", color: COLORS.warning, marginBottom: 8 }}>⚠ CONFIGURATION WARNINGS</div>
                {warnings.map(ctrl => ctrl.warnings.map((w, i) => (
                  <div key={`${ctrl.id}-${i}`} style={{ fontSize: 11, color: COLORS.warning, marginBottom: 3, display: "flex", gap: 7 }}>
                    <span>•</span><span><strong>{ctrl.label}:</strong> {w}</span>
                  </div>
                )))}
              </div>
            )}

            <div style={{ marginTop: 16, display: "flex", justifyContent: "space-between" }}>
              <Btn label="← BACK TO CONTROLS" onClick={() => setStep(2)} secondary />
              <Btn label="↺ START NEW POLICY" onClick={handleReset} danger />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
