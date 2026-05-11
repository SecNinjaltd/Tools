var CAPolicyBuilderBundle = (() => {
  // CA Policy Builder/App.jsx
  var { useState, useEffect } = React;
  var LIGHT_COLORS = {
    bg: "#ffffff",
    surface: "#ffffff",
    surfaceAlt: "#f3eee8",
    border: "#ded4c8",
    accent: "#e8610a",
    accentBright: "#c44e00",
    success: "#00a96e",
    warning: "#f2aa00",
    danger: "#e1063a",
    text: "#201c18",
    textMuted: "#867d74",
    textDim: "#5f5751"
  };
  var DARK_COLORS = {
    bg: "#141414",
    surface: "#1d1d1d",
    surfaceAlt: "#232323",
    border: "#302d2a",
    accent: "#e8610a",
    accentBright: "#ff8748",
    success: "#3fd392",
    warning: "#f0c030",
    danger: "#ff5c66",
    text: "#f5f2ee",
    textMuted: "#a59a8d",
    textDim: "#cfc6bc"
  };
  var COLORS = { ...LIGHT_COLORS };
  function getStoredTheme() {
    try {
      const prefs = JSON.parse(localStorage.getItem("xdr_ui_prefs") || "{}");
      return prefs.theme === "dark-mode" || prefs.theme === "cyber-mode" ? "dark-mode" : "light";
    } catch (_err) {
      return "light";
    }
  }
  function applyBuilderTheme(theme) {
    Object.assign(COLORS, theme === "dark-mode" ? DARK_COLORS : LIGHT_COLORS);
  }
  applyBuilderTheme(getStoredTheme());
  var CONTROL_COLORS = {
    phish_mfa: "#6f675f",
    mfa: "#008fd6",
    legacy_auth: "#e75a00",
    compliant_device: "#00a96e",
    hybrid_join: "#00a96e",
    app_protection: "#008fd6",
    approved_client: "#00a96e",
    named_locations: "#f2aa00",
    sign_in_risk: "#e1063a",
    user_risk: "#e1063a",
    session_controls: "#6f675f",
    terms_of_use: "#6f675f",
    block_unknown_platforms: "#e1063a",
    require_password_change: "#e75a00"
  };
  var ZERO_TRUST_PRINCIPLES = {
    verify: { label: "Verify Explicitly", color: "#008fd6", icon: "\u{1F50D}" },
    least: { label: "Least Privilege Access", color: "#6f675f", icon: "\u{1F512}" },
    breach: { label: "Assume Breach", color: "#e1063a", icon: "\u{1F6E1}\uFE0F" }
  };
  var MITRE_TECHNIQUES = {
    "T1078": { name: "Valid Accounts", tactic: "Initial Access", severity: "High" },
    "T1110": { name: "Brute Force", tactic: "Credential Access", severity: "High" },
    "T1528": { name: "Steal Application Access Token", tactic: "Credential Access", severity: "High" },
    "T1539": { name: "Steal Web Session Cookie", tactic: "Credential Access", severity: "Medium" },
    "T1556": { name: "Modify Authentication Process", tactic: "Credential Access", severity: "High" },
    "T1621": { name: "MFA Request Generation", tactic: "Credential Access", severity: "High" },
    "T1098": { name: "Account Manipulation", tactic: "Persistence", severity: "Medium" },
    "T1484": { name: "Domain Policy Modification", tactic: "Defense Evasion", severity: "Medium" },
    "T1557": { name: "Adversary-in-the-Middle", tactic: "Credential Access", severity: "High" },
    "T1606": { name: "Forge Web Credentials", tactic: "Credential Access", severity: "High" },
    "T1133": { name: "External Remote Services", tactic: "Persistence", severity: "Medium" },
    "T1199": { name: "Trusted Relationship", tactic: "Initial Access", severity: "Medium" }
  };
  var IDENTITY_TYPES = [
    { id: "user", label: "Standard User", icon: "\u{1F464}", desc: "Regular employees, contractors", baseRisk: 45 },
    { id: "admin", label: "Administrator", icon: "\u2699\uFE0F", desc: "Global admin, privileged roles", baseRisk: 85 },
    { id: "guest", label: "Guest / External", icon: "\u{1F310}", desc: "B2B collaborators, partners", baseRisk: 70 },
    { id: "workload", label: "Workload Identity", icon: "\u{1F916}", desc: "Service principals, managed identities", baseRisk: 60 }
  ];
  var ACCESS_TARGETS = [
    { id: "all_apps", label: "All Cloud Apps", icon: "\u2601\uFE0F", desc: "Broadest coverage" },
    { id: "admin_portals", label: "Microsoft Admin Portals", icon: "\u{1F3DB}\uFE0F", desc: "Azure, Entra, Intune" },
    { id: "office365", label: "Microsoft 365", icon: "\u{1F4E7}", desc: "Exchange, SharePoint, Teams" },
    { id: "specific", label: "Specific Applications", icon: "\u{1F3AF}", desc: "Target individual apps" }
  ];
  var SESSION_TIMEOUT_OPTIONS = [
    { value: 1, label: "1 hour", riskReduction: 8, recommended: false },
    { value: 4, label: "4 hours", riskReduction: 6, recommended: true },
    { value: 8, label: "8 hours", riskReduction: 4, recommended: false },
    { value: 12, label: "12 hours", riskReduction: 2, recommended: false },
    { value: 24, label: "24 hours", riskReduction: 0, recommended: false }
  ];
  var SIGN_IN_FREQUENCY_OPTIONS = [
    { value: 1, label: "Every sign-in", riskReduction: 5, recommended: true },
    { value: 24, label: "Daily", riskReduction: 3, recommended: false },
    { value: 168, label: "Weekly", riskReduction: 1, recommended: false }
  ];
  var RISK_LEVEL_OPTIONS = [
    { value: "low", label: "Low and above", riskReduction: 12, recommended: false },
    { value: "medium", label: "Medium and above", riskReduction: 18, recommended: true },
    { value: "high", label: "High only", riskReduction: 25, recommended: false }
  ];
  var POLICY_CONTROLS = [
    {
      id: "phish_mfa",
      label: "Require Phishing-Resistant MFA",
      category: "authentication",
      baseRiskReduction: 35,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "FIDO2 security keys or Windows Hello for Business",
      why: "Cryptographically bound to origin - cannot be phished, relayed, or replayed. Blocks AiTM attacks completely.",
      mitreBlocked: ["T1621", "T1110", "T1557", "T1078", "T1606"],
      warnings: ["Requires FIDO2 hardware keys or WHfB enrollment"],
      bestPractice: "Mandatory for all administrator accounts. Consider hardware tokens for high-value users."
    },
    {
      id: "mfa",
      label: "Require MFA",
      category: "authentication",
      baseRiskReduction: 25,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Multi-factor authentication (any method)",
      why: "Blocks 99.9% of automated attacks even with stolen passwords.",
      mitreBlocked: ["T1110", "T1078"],
      warnings: ["Can be bypassed by sophisticated phishing - use phishing-resistant MFA instead"],
      bestPractice: "Minimum baseline for all users. Upgrade to phishing-resistant for admins."
    },
    {
      id: "legacy_auth",
      label: "Block Legacy Authentication",
      category: "authentication",
      baseRiskReduction: 22,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Block IMAP, POP3, SMTP Auth, older protocols",
      why: "Legacy protocols bypass MFA. 99% of password spray attacks use legacy auth.",
      mitreBlocked: ["T1110", "T1078", "T1133"],
      warnings: ["Check for legacy Outlook clients (2010/2013) before enabling"],
      bestPractice: "Block for all users. No legitimate need for legacy auth in modern environments."
    },
    {
      id: "compliant_device",
      label: "Require Compliant Device",
      category: "device",
      baseRiskReduction: 20,
      hasSettings: false,
      ztPrinciples: ["verify", "breach"],
      desc: "Intune-enrolled, policy-compliant devices only",
      why: "Ensures endpoint security baselines, encryption, and patch compliance before access.",
      mitreBlocked: ["T1078", "T1528", "T1539"],
      warnings: ["Ensure device enrollment is complete before enforcement"],
      bestPractice: "Required for accessing sensitive data. Provide enrollment grace period for new devices."
    },
    {
      id: "hybrid_join",
      label: "Require Hybrid Azure AD Joined Device",
      category: "device",
      baseRiskReduction: 15,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Domain-joined devices synced to Azure AD",
      why: "Ensures devices are managed by corporate AD and Azure AD policies.",
      mitreBlocked: ["T1078", "T1199"],
      warnings: ["Only works for hybrid AD environments"],
      bestPractice: "Use for on-premises integration scenarios. Prefer Compliant Device for cloud-native."
    },
    {
      id: "app_protection",
      label: "Require App Protection Policy",
      category: "device",
      baseRiskReduction: 8,
      hasSettings: false,
      ztPrinciples: ["least", "breach"],
      desc: "Intune App Protection on mobile devices",
      why: "Containerises corporate data, enables selective wipe on unmanaged BYOD devices.",
      mitreBlocked: ["T1539"],
      warnings: [],
      bestPractice: "Essential for BYOD scenarios. Combine with Compliant Device for corporate-owned."
    },
    {
      id: "approved_client",
      label: "Require Approved Client App",
      category: "device",
      baseRiskReduction: 10,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Only Microsoft-approved mobile apps (Outlook, Teams, etc.)",
      why: "Prevents data access from unsecured third-party apps that can't enforce protection policies.",
      mitreBlocked: ["T1539"],
      warnings: [],
      bestPractice: "Use for mobile access to email/chat. Prevents unmanaged apps accessing corporate data."
    },
    {
      id: "named_locations",
      label: "Restrict to Trusted Locations",
      category: "location",
      baseRiskReduction: 15,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Allow only from corporate networks or trusted IPs",
      why: "Geo-fencing reduces credential blast radius. Blocks access from unexpected locations.",
      mitreBlocked: ["T1078"],
      warnings: ["Must include VPN endpoints and home IPs for remote workers"],
      bestPractice: "Define trusted locations: corporate offices, VPN exit points, approved remote IPs. Block high-risk countries."
    },
    {
      id: "sign_in_risk",
      label: "Block Risky Sign-ins (Identity Protection)",
      category: "risk",
      baseRiskReduction: 0,
      // Variable based on settings
      hasSettings: true,
      settingType: "risk_level",
      ztPrinciples: ["verify", "breach"],
      desc: "ML-based detection of anomalous sign-in patterns",
      why: "Detects leaked credentials, anonymous IPs, impossible travel, and atypical patterns in real-time.",
      mitreBlocked: ["T1078", "T1528", "T1606"],
      warnings: ["Requires Azure AD Premium P2"],
      bestPractice: "Block high-risk sign-ins. Challenge medium-risk with MFA. Monitor low-risk."
    },
    {
      id: "user_risk",
      label: "Require Password Change on User Risk",
      category: "risk",
      baseRiskReduction: 0,
      // Variable based on settings
      hasSettings: true,
      settingType: "risk_level",
      ztPrinciples: ["breach"],
      desc: "Force password reset when account is compromised",
      why: "When credentials appear in breach databases, immediate remediation prevents account takeover.",
      mitreBlocked: ["T1078", "T1098"],
      warnings: ["Requires Azure AD Premium P2"],
      bestPractice: "Require secure password change for high-risk users. Medium-risk may need MFA re-authentication."
    },
    {
      id: "session_controls",
      label: "Session Controls & Token Lifetime",
      category: "session",
      baseRiskReduction: 0,
      // Variable based on settings
      hasSettings: true,
      settingType: "session_timeout",
      ztPrinciples: ["least", "breach"],
      desc: "Limit session duration and sign-in frequency",
      why: "Short-lived tokens reduce window for replay attacks. Forces periodic re-authentication.",
      mitreBlocked: ["T1528", "T1539"],
      warnings: [],
      bestPractice: "4-hour sessions for standard users, 1-hour for admins. Disable persistent browser sessions."
    },
    {
      id: "terms_of_use",
      label: "Require Terms of Use Acceptance",
      category: "compliance",
      baseRiskReduction: 2,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Periodic acceptance of usage policies",
      why: "Legal requirement for compliance. Ensures users acknowledge security policies.",
      mitreBlocked: [],
      warnings: [],
      bestPractice: "Require re-acceptance every 90 days. Critical for guest users and contractors."
    },
    {
      id: "block_unknown_platforms",
      label: "Block Unknown/Unsupported Platforms",
      category: "device",
      baseRiskReduction: 8,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Block access from Linux, ChromeOS, or unknown devices",
      why: "Reduces attack surface from potentially unmanaged platforms.",
      mitreBlocked: ["T1078"],
      warnings: ["May block legitimate developer workstations - review exceptions"],
      bestPractice: "Block for standard users. Create exceptions for DevOps teams as needed."
    },
    {
      id: "require_password_change",
      label: "Require Password Change (First Sign-in)",
      category: "compliance",
      baseRiskReduction: 5,
      hasSettings: false,
      ztPrinciples: ["verify"],
      desc: "Force password change on first sign-in for new accounts",
      why: "Ensures default/temporary passwords are replaced immediately.",
      mitreBlocked: ["T1078"],
      warnings: [],
      bestPractice: "Always enable for new user accounts and password resets."
    }
  ];
  var ZERO_TRUST_MATURITY = {
    traditional: {
      level: "Traditional",
      color: COLORS.danger,
      desc: "Perimeter-based security, limited identity verification"
    },
    advanced: {
      level: "Advanced",
      color: COLORS.warning,
      desc: "Some cloud-based controls, basic MFA"
    },
    optimal: {
      level: "Optimal",
      color: COLORS.success,
      desc: "Full Zero Trust implementation with phishing-resistant MFA"
    }
  };
  var DEFENSE_IN_DEPTH_LAYERS = [
    { layer: "Perimeter", example: "Network firewalls, WAF", color: "#ef4444" },
    { layer: "Network", example: "Named locations, geo-blocking", color: "#f97316" },
    { layer: "Identity", example: "MFA, phishing-resistant auth", color: "#eab308" },
    { layer: "Device", example: "Compliant devices, app protection", color: "#10b981" },
    { layer: "Application", example: "App controls, session limits", color: "#3b82f6" },
    { layer: "Data", example: "Encryption, DLP policies", color: "#8b5cf6" }
  ];
  var BEST_PRACTICES = [
    {
      id: "breakglass",
      title: "Break-Glass Accounts",
      icon: "\u{1F6A8}",
      desc: "Maintain 2+ emergency access accounts excluded from ALL Conditional Access policies",
      why: "Prevents complete lockout if policies misconfigure. Critical for disaster recovery.",
      steps: [
        "Create 2 cloud-only global admin accounts (not synced from AD)",
        "Use 25+ character random passwords stored in secure physical safe",
        "Exclude from ALL CA policies including MFA",
        "Monitor with dedicated alerts - any use triggers investigation",
        "Rotate passwords quarterly",
        "Document in security runbook"
      ],
      critical: true,
      msReference: "Microsoft Zero Trust Deployment Guide - Emergency Access"
    },
    {
      id: "report_only",
      title: "Report-Only Mode Testing",
      icon: "\u{1F4CA}",
      desc: "Always test new policies in report-only mode first",
      why: "Identifies potential lockout scenarios before enforcement. See who would be impacted.",
      steps: [
        "Create policy in 'Report-only' state",
        "Monitor sign-in logs for 7-14 days",
        "Review 'What If' tool results for different scenarios",
        "Check for unexpected user/app combinations",
        "Only enable after validation"
      ],
      critical: true,
      msReference: "Microsoft Conditional Access Deployment Best Practices"
    },
    {
      id: "named_locations",
      title: "Named Locations Configuration",
      icon: "\u{1F4CD}",
      desc: "Define trusted locations for geo-fencing policies",
      why: "Enables location-based access controls and blocks access from unexpected regions.",
      steps: [
        "Add corporate office IP ranges",
        "Include VPN exit points",
        "Add approved remote work locations (home IPs for executives)",
        "Mark trusted locations for MFA bypass (only for low-risk scenarios)",
        "Block known high-risk countries (match your threat intelligence)",
        "Use 'Trusted' flag carefully - limits its security benefit"
      ],
      critical: false,
      msReference: "Zero Trust Principle: Verify Explicitly - Network Controls"
    },
    {
      id: "policy_exclusions",
      title: "Exclusion Groups Best Practices",
      icon: "\u{1F465}",
      desc: "Manage policy exceptions safely",
      why: "Exclusions create security gaps. Must be tightly controlled and audited.",
      steps: [
        "Use groups for exclusions (never individual users)",
        "Name clearly: 'CA-Exclusion-[PolicyName]-[Reason]'",
        "Require approval workflow for adding members",
        "Review quarterly - remove when no longer needed",
        "Alert on membership changes",
        "Document business justification for each exclusion",
        "Prefer time-limited exceptions where possible"
      ],
      critical: false,
      msReference: "Microsoft Conditional Access Framework - Exception Management"
    },
    {
      id: "admin_protection",
      title: "Administrator Protection Strategy",
      icon: "\u{1F6E1}\uFE0F",
      desc: "Separate policies for privileged accounts",
      why: "Admin accounts are highest-value targets. Require strictest controls.",
      steps: [
        "Phishing-resistant MFA mandatory (no exceptions)",
        "Require compliant devices only",
        "1-hour session lifetime maximum",
        "Block legacy authentication entirely",
        "Restrict to trusted locations only",
        "Separate admin accounts from daily-use accounts",
        "Consider Privileged Access Workstations (PAWs)"
      ],
      critical: true,
      msReference: "Zero Trust - Least Privilege & Microsoft Privileged Access Strategy"
    },
    {
      id: "monitoring",
      title: "Policy Monitoring & Alerts",
      icon: "\u{1F514}",
      desc: "Continuous monitoring of policy effectiveness",
      why: "Policies must be monitored for gaps, failures, and abuse attempts.",
      steps: [
        "Monitor sign-in logs for policy failures/successes",
        "Alert on break-glass account usage",
        "Track policy exclusion group changes",
        "Review risk detections (Identity Protection)",
        "Monitor for policy conflicts or gaps",
        "Weekly review of blocked sign-ins",
        "Quarterly policy effectiveness audit"
      ],
      critical: false,
      msReference: "Zero Trust - Assume Breach & Continuous Verification"
    }
  ];
  var Btn = ({ label, onClick, disabled, danger, secondary, small }) => /* @__PURE__ */ React.createElement(
    "button",
    {
      onClick,
      disabled,
      style: {
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
        opacity: disabled ? 0.5 : 1
      }
    },
    label
  );
  var ThemeToggleButton = () => /* @__PURE__ */ React.createElement("button", { className: "theme-toggle-btn", type: "button", "data-xdr-theme-toggle": true, "aria-label": "Enable dark mode", title: "Enable dark mode" }, /* @__PURE__ */ React.createElement("svg", { className: "icon-moon", viewBox: "0 0 24 24", fill: "none", "aria-hidden": "true" }, /* @__PURE__ */ React.createElement("path", { d: "M20 14.2A8 8 0 1 1 9.8 4a6.5 6.5 0 1 0 10.2 10.2Z", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round" })), /* @__PURE__ */ React.createElement("svg", { className: "icon-sun", viewBox: "0 0 24 24", fill: "none", "aria-hidden": "true" }, /* @__PURE__ */ React.createElement("circle", { cx: "12", cy: "12", r: "4", stroke: "currentColor", strokeWidth: "1.8" }), /* @__PURE__ */ React.createElement("path", { d: "M12 2v2.4M12 19.6V22M4.9 4.9l1.7 1.7M17.4 17.4l1.7 1.7M2 12h2.4M19.6 12H22M4.9 19.1l1.7-1.7M17.4 6.6l1.7-1.7", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round" })));
  var RiskMeter = ({ score, size = 80 }) => {
    const getColor = () => {
      if (score < 25) return COLORS.success;
      if (score < 50) return COLORS.warning;
      return COLORS.danger;
    };
    return /* @__PURE__ */ React.createElement("div", { style: { position: "relative", width: size, height: size } }, /* @__PURE__ */ React.createElement("svg", { width: size, height: size, style: { transform: "rotate(-90deg)" } }, /* @__PURE__ */ React.createElement("circle", { cx: size / 2, cy: size / 2, r: size / 2 - 8, fill: "none", stroke: COLORS.border, strokeWidth: "6" }), /* @__PURE__ */ React.createElement(
      "circle",
      {
        cx: size / 2,
        cy: size / 2,
        r: size / 2 - 8,
        fill: "none",
        stroke: getColor(),
        strokeWidth: "6",
        strokeDasharray: `${2 * Math.PI * (size / 2 - 8)}`,
        strokeDashoffset: `${2 * Math.PI * (size / 2 - 8) * (1 - score / 100)}`,
        style: { transition: "stroke-dashoffset 0.5s" }
      }
    )), /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: size * 0.25, fontWeight: 700, color: getColor() } }, score), /* @__PURE__ */ React.createElement("div", { style: { fontSize: size * 0.1, color: COLORS.textMuted } }, "RISK")));
  };
  var ThreatAnalyticsSidebar = ({ identity, target, controls, controlSettings }) => {
    const calculateRisk = () => {
      if (!identity) return 100;
      let base = IDENTITY_TYPES.find((i) => i.id === identity)?.baseRisk || 50;
      controls.forEach((id) => {
        const ctrl = POLICY_CONTROLS.find((p) => p.id === id);
        if (!ctrl) return;
        if (ctrl.hasSettings && controlSettings[id]) {
          if (id === "session_controls") {
            const setting = controlSettings[id];
            const timeoutOption = SESSION_TIMEOUT_OPTIONS.find((o) => o.value === setting.timeout);
            const freqOption = SIGN_IN_FREQUENCY_OPTIONS.find((o) => o.value === setting.frequency);
            base -= (timeoutOption?.riskReduction || 0) + (freqOption?.riskReduction || 0);
          } else if (id === "sign_in_risk" || id === "user_risk") {
            const riskOption = RISK_LEVEL_OPTIONS.find((o) => o.value === controlSettings[id].level);
            base -= riskOption?.riskReduction || 0;
          }
        } else {
          base -= ctrl.baseRiskReduction;
        }
      });
      return Math.max(0, base);
    };
    const getCoveredTechniques = () => {
      const covered2 = /* @__PURE__ */ new Set();
      controls.forEach((controlId) => {
        const ctrl = POLICY_CONTROLS.find((c) => c.id === controlId);
        if (ctrl?.mitreBlocked) {
          ctrl.mitreBlocked.forEach((t) => covered2.add(t));
        }
      });
      return covered2;
    };
    const covered = getCoveredTechniques();
    const riskScore = calculateRisk();
    const baseRisk = identity ? IDENTITY_TYPES.find((i) => i.id === identity)?.baseRisk || 50 : 100;
    const coverage = Math.round(covered.size / Object.keys(MITRE_TECHNIQUES).length * 100);
    return /* @__PURE__ */ React.createElement("div", { style: { position: "sticky", top: 24, height: "fit-content" } }, /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 14 } }, "REAL-TIME RISK ANALYSIS"), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-around", marginBottom: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textMuted, marginBottom: 6 } }, "BASELINE"), /* @__PURE__ */ React.createElement(RiskMeter, { score: baseRisk, size: 70 })), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 18, color: COLORS.accentBright } }, "\u2192"), /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textMuted, marginBottom: 6 } }, "CURRENT"), /* @__PURE__ */ React.createElement(RiskMeter, { score: riskScore, size: 70 }))), /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center", padding: "8px", background: `${COLORS.success}10`, borderRadius: 6, border: `1px solid ${COLORS.success}30` } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, color: COLORS.success } }, "\u2193 ", baseRisk - riskScore, " POINTS REDUCED"))), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 12 } }, "MITRE ATT&CK COVERAGE"), /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: 6 } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 9, color: COLORS.textMuted } }, "TECHNIQUES MITIGATED"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11, fontWeight: 700, color: COLORS.success } }, covered.size, "/", Object.keys(MITRE_TECHNIQUES).length)), /* @__PURE__ */ React.createElement("div", { style: { height: 6, background: COLORS.border, borderRadius: 3, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { height: "100%", width: `${coverage}%`, background: `linear-gradient(90deg, ${COLORS.success}, ${COLORS.accentBright})`, transition: "width 0.5s" } })), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, color: COLORS.success, marginTop: 4, textAlign: "center" } }, coverage, "%")), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 } }, ["High", "Medium"].map((severity) => {
      const total = Object.values(MITRE_TECHNIQUES).filter((t) => t.severity === severity).length;
      const coveredCount = Object.entries(MITRE_TECHNIQUES).filter(([id, t]) => t.severity === severity && covered.has(id)).length;
      return /* @__PURE__ */ React.createElement("div", { key: severity, style: { background: COLORS.surfaceAlt, borderRadius: 6, padding: 8 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textMuted, marginBottom: 4 } }, severity.toUpperCase()), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, fontWeight: 700, color: coveredCount === total ? COLORS.success : COLORS.warning } }, coveredCount, "/", total));
    }))), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, letterSpacing: "0.15em", color: COLORS.textMuted, marginBottom: 10 } }, "ACTIVE CONTROLS (", controls.length, ")"), controls.length === 0 ? /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textMuted, textAlign: "center", padding: 16 } }, "No controls selected") : /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 4 } }, controls.map((id) => {
      const c = POLICY_CONTROLS.find((p) => p.id === id);
      const col = CONTROL_COLORS[id] || COLORS.accent;
      return /* @__PURE__ */ React.createElement("div", { key: id, style: { fontSize: 9, color: col, display: "flex", alignItems: "center", gap: 6 } }, /* @__PURE__ */ React.createElement("div", { style: { width: 4, height: 4, borderRadius: "50%", background: col } }), /* @__PURE__ */ React.createElement("span", null, c?.label));
    }))), covered.size < Object.keys(MITRE_TECHNIQUES).length && /* @__PURE__ */ React.createElement("div", { style: { background: `${COLORS.danger}08`, border: `1px solid ${COLORS.danger}30`, borderRadius: 12, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, letterSpacing: "0.15em", color: COLORS.danger, marginBottom: 8 } }, "\u26A0 GAPS IDENTIFIED"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 8 } }, Object.keys(MITRE_TECHNIQUES).length - covered.size, " techniques not mitigated"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textDim } }, Object.entries(MITRE_TECHNIQUES).filter(([id]) => !covered.has(id)).slice(0, 3).map(([id, t]) => /* @__PURE__ */ React.createElement("div", { key: id, style: { marginBottom: 2 } }, "\u2022 ", id, ": ", t.name)), Object.keys(MITRE_TECHNIQUES).length - covered.size > 3 && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 4, fontSize: 8, color: COLORS.textMuted } }, "+", Object.keys(MITRE_TECHNIQUES).length - covered.size - 3, " more..."))));
  };
  var ThreatCoverageMap = ({ controls, controlSettings, identity }) => {
    const [selectedTechnique, setSelectedTechnique] = useState(null);
    const [view, setView] = useState("matrix");
    const getCoveredTechniques = () => {
      const covered2 = /* @__PURE__ */ new Set();
      controls.forEach((controlId) => {
        const ctrl = POLICY_CONTROLS.find((c) => c.id === controlId);
        if (ctrl?.mitreBlocked) {
          ctrl.mitreBlocked.forEach((t) => covered2.add(t));
        }
      });
      return covered2;
    };
    const getZeroTrustMaturity = () => {
      const hasPhishResistantMFA = controls.includes("phish_mfa");
      const hasDeviceCompliance = controls.includes("compliant_device");
      const hasSessionControls = controls.includes("session_controls");
      const hasRiskPolicies = controls.includes("sign_in_risk") || controls.includes("user_risk");
      if (hasPhishResistantMFA && hasDeviceCompliance && hasSessionControls && hasRiskPolicies && controls.length >= 6) {
        return "optimal";
      } else if (controls.includes("mfa") || controls.includes("phish_mfa")) {
        return "advanced";
      }
      return "traditional";
    };
    const getDefenseLayerCoverage = () => {
      const layers = {};
      DEFENSE_IN_DEPTH_LAYERS.forEach((l) => {
        layers[l.layer] = 0;
      });
      if (controls.includes("named_locations")) layers["Network"] += 1;
      if (controls.includes("phish_mfa") || controls.includes("mfa")) layers["Identity"] += 1;
      if (controls.includes("legacy_auth")) layers["Identity"] += 1;
      if (controls.includes("sign_in_risk") || controls.includes("user_risk")) layers["Identity"] += 1;
      if (controls.includes("compliant_device") || controls.includes("hybrid_join")) layers["Device"] += 1;
      if (controls.includes("app_protection") || controls.includes("approved_client")) layers["Device"] += 1;
      if (controls.includes("session_controls") || controls.includes("terms_of_use")) layers["Application"] += 1;
      return layers;
    };
    const covered = getCoveredTechniques();
    const coverage = Math.round(covered.size / Object.keys(MITRE_TECHNIQUES).length * 100);
    const maturityLevel = getZeroTrustMaturity();
    const layerCoverage = getDefenseLayerCoverage();
    return /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24, marginTop: 24 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 16, fontWeight: 700, marginBottom: 4 } }, "Comprehensive Threat Coverage Analysis"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textMuted } }, "MITRE ATT&CK mapping, Zero Trust maturity, and Defense in Depth visualization")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6 } }, /* @__PURE__ */ React.createElement(Btn, { label: "MITRE MATRIX", onClick: () => setView("matrix"), secondary: view !== "matrix", small: true }), /* @__PURE__ */ React.createElement(Btn, { label: "ZERO TRUST", onClick: () => setView("zerotrust"), secondary: view !== "zerotrust", small: true }), /* @__PURE__ */ React.createElement(Btn, { label: "DEFENSE LAYERS", onClick: () => setView("defense"), secondary: view !== "defense", small: true }))), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 } }, /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 14, border: `1px solid ${COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "MITRE COVERAGE"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 24, fontWeight: 700, color: COLORS.success } }, coverage, "%"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginTop: 2 } }, covered.size, "/", Object.keys(MITRE_TECHNIQUES).length, " techniques")), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 14, border: `1px solid ${COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "ZERO TRUST MATURITY"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14, fontWeight: 700, color: ZERO_TRUST_MATURITY[maturityLevel].color } }, ZERO_TRUST_MATURITY[maturityLevel].level), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginTop: 2 } }, ZERO_TRUST_MATURITY[maturityLevel].desc)), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 14, border: `1px solid ${COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "DEFENSE LAYERS"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 24, fontWeight: 700, color: COLORS.accentBright } }, Object.values(layerCoverage).filter((v) => v > 0).length, "/6"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginTop: 2 } }, "Active layers")), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 14, border: `1px solid ${COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "CONTROLS ACTIVE"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 24, fontWeight: 700, color: COLORS.accent } }, controls.length), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginTop: 2 } }, "Security controls"))), view === "matrix" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright } }, "\u{1F4CA} MITRE ATT&CK Technique Coverage Matrix"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 12 } }, "Click any technique for detailed mitigation information. Green = Mitigated, Red = Gap")), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 10 } }, Object.entries(MITRE_TECHNIQUES).map(([id, tech]) => {
      const isCovered = covered.has(id);
      const coveringControls = POLICY_CONTROLS.filter((c) => controls.includes(c.id) && c.mitreBlocked?.includes(id));
      const isSelected = selectedTechnique === id;
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          key: id,
          onClick: () => setSelectedTechnique(isSelected ? null : id),
          style: {
            background: isCovered ? `${COLORS.success}08` : `${COLORS.danger}08`,
            border: `2px solid ${isSelected ? COLORS.accentBright : isCovered ? `${COLORS.success}40` : `${COLORS.danger}40`}`,
            borderRadius: 8,
            padding: 12,
            cursor: "pointer",
            transition: "all 0.2s",
            transform: isSelected ? "scale(1.02)" : "scale(1)"
          }
        },
        /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "start", justifyContent: "space-between", marginBottom: 8 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 6 } }, /* @__PURE__ */ React.createElement("span", { style: { fontFamily: "monospace", fontWeight: 700, fontSize: 9, color: COLORS.textMuted, background: COLORS.surfaceAlt, padding: "2px 6px", borderRadius: 3 } }, id), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 8, padding: "2px 6px", borderRadius: 3, background: tech.severity === "High" ? `${COLORS.danger}20` : `${COLORS.warning}20`, color: tech.severity === "High" ? COLORS.danger : COLORS.warning, fontWeight: 700 } }, tech.severity)), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 18, lineHeight: 1 } }, isCovered ? "\u2713" : "\u2717")),
        /* @__PURE__ */ React.createElement("div", { style: { fontWeight: 700, fontSize: 11, marginBottom: 4, color: COLORS.text } }, tech.name),
        /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6 } }, tech.tactic),
        !isSelected && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textDim, fontStyle: "italic" } }, tech.desc),
        isSelected && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 12, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` } }, isCovered ? /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.success, fontWeight: 700, marginBottom: 6 } }, "\u2713 MITIGATED BY:"), coveringControls.map((c) => /* @__PURE__ */ React.createElement("div", { key: c.id, style: { fontSize: 9, color: COLORS.textDim, marginBottom: 4, paddingLeft: 8, borderLeft: `2px solid ${CONTROL_COLORS[c.id] || COLORS.success}` } }, "\u2022 ", c.label))) : /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.danger, fontWeight: 700, marginBottom: 4 } }, "\u26A0 VULNERABILITY GAP"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textDim } }, "No active controls mitigate this technique. Consider adding relevant controls.")))
      );
    })), covered.size < Object.keys(MITRE_TECHNIQUES).length && /* @__PURE__ */ React.createElement("div", { style: { marginTop: 16, background: `${COLORS.warning}10`, border: `1px solid ${COLORS.warning}40`, borderRadius: 8, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, color: COLORS.warning, marginBottom: 6 } }, "\u26A0 ", Object.keys(MITRE_TECHNIQUES).length - covered.size, " Technique Gap", Object.keys(MITRE_TECHNIQUES).length - covered.size > 1 ? "s" : "", " Identified"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim } }, "Your current policy configuration does not mitigate all known identity-based attack techniques. Review uncovered (red) techniques above and consider adding controls to close these gaps."))), view === "zerotrust" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright } }, "\u{1F50D} Zero Trust Maturity Assessment"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 12 } }, "Based on Microsoft Zero Trust deployment framework and CISA Zero Trust Maturity Model")), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surfaceAlt, borderRadius: 12, padding: 20, marginBottom: 16, border: `2px solid ${ZERO_TRUST_MATURITY[maturityLevel].color}` } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 48 } }, "\u{1F3C6}"), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 4, letterSpacing: "0.1em" } }, "CURRENT MATURITY LEVEL"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 20, fontWeight: 700, color: ZERO_TRUST_MATURITY[maturityLevel].color, marginBottom: 6 } }, ZERO_TRUST_MATURITY[maturityLevel].level), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textDim } }, ZERO_TRUST_MATURITY[maturityLevel].desc)))), /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, marginBottom: 12, color: COLORS.text } }, "Microsoft Zero Trust Principles Coverage"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gap: 12 } }, Object.entries(ZERO_TRUST_PRINCIPLES).map(([key, principle]) => {
      const relevantControls = POLICY_CONTROLS.filter((c) => controls.includes(c.id) && c.ztPrinciples.includes(key));
      const coveragePercent = Math.min(100, relevantControls.length / 3 * 100);
      return /* @__PURE__ */ React.createElement("div", { key, style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 16, border: `1px solid ${principle.color}30` } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12, marginBottom: 10 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 24 } }, principle.icon), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, color: principle.color, marginBottom: 4 } }, principle.label), /* @__PURE__ */ React.createElement("div", { style: { height: 6, background: COLORS.border, borderRadius: 3, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { height: "100%", width: `${coveragePercent}%`, background: principle.color, transition: "width 0.5s" } }))), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, fontWeight: 700, color: principle.color } }, relevantControls.length, " controls")), relevantControls.length > 0 && /* @__PURE__ */ React.createElement("div", { style: { paddingLeft: 36 } }, relevantControls.map((c) => /* @__PURE__ */ React.createElement("div", { key: c.id, style: { fontSize: 9, color: COLORS.textDim, marginBottom: 2 } }, "\u2022 ", c.label))));
    }))), maturityLevel !== "optimal" && /* @__PURE__ */ React.createElement("div", { style: { background: `${COLORS.accentBright}10`, border: `1px solid ${COLORS.accentBright}40`, borderRadius: 8, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, color: COLORS.accentBright, marginBottom: 8 } }, "\u{1F4C8} Path to Optimal Zero Trust Maturity"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginBottom: 8 } }, "To achieve Optimal maturity level, consider implementing:"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.text } }, !controls.includes("phish_mfa") && /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "\u2022 Phishing-resistant MFA for all users (especially admins)"), !controls.includes("compliant_device") && /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "\u2022 Device compliance requirements"), !controls.includes("session_controls") && /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "\u2022 Session controls with limited token lifetime"), !controls.includes("sign_in_risk") && !controls.includes("user_risk") && /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "\u2022 Identity Protection risk policies"), controls.length < 6 && /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "\u2022 Additional layered controls for defense in depth")))), view === "defense" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, marginBottom: 10, color: COLORS.accentBright } }, "\u{1F6E1}\uFE0F Defense in Depth Layer Analysis"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 12 } }, "Microsoft security framework: Multiple layers of protection ensure no single point of failure")), /* @__PURE__ */ React.createElement("div", { style: { position: "relative", marginBottom: 24 } }, DEFENSE_IN_DEPTH_LAYERS.map((layer, idx) => {
      const controlCount = layerCoverage[layer.layer] || 0;
      const isActive = controlCount > 0;
      const size = 60 + idx * 30;
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          key: layer.layer,
          style: {
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
            transition: "all 0.3s"
          }
        },
        /* @__PURE__ */ React.createElement("div", { style: { textAlign: "center" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, color: isActive ? layer.color : COLORS.textMuted, marginBottom: 2 } }, layer.layer), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.textDim } }, layer.example), isActive && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: layer.color, marginTop: 4, fontWeight: 700 } }, controlCount, " control", controlCount > 1 ? "s" : "", " active"))
      );
    })), /* @__PURE__ */ React.createElement("div", { style: { marginTop: `${DEFENSE_IN_DEPTH_LAYERS.length * 40 + 100}px` } }, /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 } }, DEFENSE_IN_DEPTH_LAYERS.map((layer) => {
      const controlCount = layerCoverage[layer.layer] || 0;
      const isActive = controlCount > 0;
      return /* @__PURE__ */ React.createElement("div", { key: layer.layer, style: { background: COLORS.surfaceAlt, borderRadius: 8, padding: 14, border: `1px solid ${isActive ? layer.color : COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, color: isActive ? layer.color : COLORS.textMuted } }, layer.layer, " Layer"), isActive ? /* @__PURE__ */ React.createElement("span", { style: { fontSize: 16, color: layer.color } }, "\u2713") : /* @__PURE__ */ React.createElement("span", { style: { fontSize: 16, color: COLORS.textMuted } }, "\u25CB")), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, marginBottom: 8 } }, layer.example), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: isActive ? COLORS.success : COLORS.warning, fontWeight: 700 } }, isActive ? `${controlCount} control${controlCount > 1 ? "s" : ""} protecting this layer` : "No controls - vulnerability gap"));
    })), /* @__PURE__ */ React.createElement("div", { style: { marginTop: 16, background: `${COLORS.accentBright}10`, border: `1px solid ${COLORS.accentBright}40`, borderRadius: 8, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, color: COLORS.accentBright, marginBottom: 6 } }, "\u{1F4DA} Microsoft Defense in Depth Principle"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim } }, "Defense in Depth is a layered approach to security. If one layer is compromised, subsequent layers provide continued protection. Microsoft recommends implementing controls across ALL layers - from network perimeter to data encryption - to ensure comprehensive security posture. Each layer reduces the attack surface and provides additional opportunities to detect and prevent threats.")))));
  };
  function ConditionalAccessBuilder() {
    const [theme, setTheme] = useState(getStoredTheme());
    const [step, setStep] = useState(0);
    const [identity, setIdentity] = useState(null);
    const [target, setTarget] = useState(null);
    const [selectedControls, setSelectedControls] = useState([]);
    const [controlSettings, setControlSettings] = useState({});
    const [showBestPractices, setShowBestPractices] = useState(false);
    useEffect(() => {
      applyBuilderTheme(theme);
    }, [theme]);
    useEffect(() => {
      const onThemeChange = (event) => {
        setTheme(event.detail?.theme === "dark-mode" ? "dark-mode" : "light");
      };
      window.addEventListener("xdr-theme-change", onThemeChange);
      return () => window.removeEventListener("xdr-theme-change", onThemeChange);
    }, []);
    const handleReset = () => {
      setStep(0);
      setIdentity(null);
      setTarget(null);
      setSelectedControls([]);
      setControlSettings({});
      setShowBestPractices(false);
    };
    const toggleControl = (id) => {
      const ctrl = POLICY_CONTROLS.find((c) => c.id === id);
      if (id === "phish_mfa" && selectedControls.includes("mfa")) {
        setSelectedControls((prev) => [...prev.filter((c) => c !== "mfa"), id]);
      } else if (id === "mfa" && selectedControls.includes("phish_mfa")) {
        return;
      } else if (selectedControls.includes(id)) {
        setSelectedControls((prev) => prev.filter((c) => c !== id));
        const newSettings = { ...controlSettings };
        delete newSettings[id];
        setControlSettings(newSettings);
      } else {
        setSelectedControls((prev) => [...prev, id]);
        if (ctrl.hasSettings) {
          if (id === "session_controls") {
            setControlSettings((prev) => ({
              ...prev,
              [id]: { timeout: 4, frequency: 1 }
            }));
          } else if (id === "sign_in_risk" || id === "user_risk") {
            setControlSettings((prev) => ({
              ...prev,
              [id]: { level: "medium" }
            }));
          }
        }
      }
    };
    const updateControlSetting = (controlId, setting, value) => {
      setControlSettings((prev) => ({
        ...prev,
        [controlId]: {
          ...prev[controlId],
          [setting]: value
        }
      }));
    };
    const phishMfaActive = selectedControls.includes("phish_mfa");
    return /* @__PURE__ */ React.createElement("div", { style: {
      minHeight: "100vh",
      background: COLORS.bg,
      color: COLORS.text,
      fontFamily: "'Plus Jakarta Sans', sans-serif",
      padding: 24
    } }, /* @__PURE__ */ React.createElement("div", { style: { maxWidth: 1600, margin: "0 auto" } }, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 24, display: "flex", alignItems: "center", justifyContent: "space-between" } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 26, fontWeight: 800, marginBottom: 6 } }, "\u{1F6E1}\uFE0F Entra ID Conditional Access Policy Builder"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: COLORS.textMuted } }, "Zero Trust-aligned policy design with real-time MITRE ATT&CK threat analysis")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8 } }, /* @__PURE__ */ React.createElement(ThemeToggleButton, null), /* @__PURE__ */ React.createElement(Btn, { label: "\u{1F4DA} BEST PRACTICES", onClick: () => setShowBestPractices(!showBestPractices), secondary: true, small: true }), /* @__PURE__ */ React.createElement(Btn, { label: "\u21BA RESET", onClick: handleReset, danger: true }))), showBestPractices && /* @__PURE__ */ React.createElement("div", { style: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 } }, /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, borderRadius: 16, maxWidth: 900, maxHeight: "90vh", overflow: "auto", border: `2px solid ${COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { position: "sticky", top: 0, background: COLORS.surface, padding: 24, borderBottom: `1px solid ${COLORS.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 18, fontWeight: 700 } }, "Microsoft Best Practices & Guidance"), /* @__PURE__ */ React.createElement("button", { onClick: () => setShowBestPractices(false), style: { background: "none", border: "none", color: COLORS.text, fontSize: 24, cursor: "pointer" } }, "\xD7")), /* @__PURE__ */ React.createElement("div", { style: { padding: 24 } }, BEST_PRACTICES.map((bp) => /* @__PURE__ */ React.createElement("div", { key: bp.id, style: { background: COLORS.surfaceAlt, borderRadius: 12, padding: 20, marginBottom: 16, border: `1px solid ${bp.critical ? COLORS.danger : COLORS.border}` } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "start", gap: 12, marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 32 } }, bp.icon), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8, marginBottom: 6 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 16, fontWeight: 700 } }, bp.title), bp.critical && /* @__PURE__ */ React.createElement("span", { style: { fontSize: 9, padding: "2px 8px", background: `${COLORS.danger}20`, color: COLORS.danger, borderRadius: 4, fontWeight: 700 } }, "CRITICAL")), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: COLORS.textMuted, marginBottom: 8 } }, bp.desc), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textDim, fontStyle: "italic", marginBottom: 8 } }, "Why: ", bp.why), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.accentBright, padding: "4px 8px", background: `${COLORS.accent}10`, borderRadius: 4, display: "inline-block" } }, "\u{1F4DA} ", bp.msReference))), /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, borderRadius: 8, padding: 14 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, letterSpacing: "0.1em", color: COLORS.textMuted, marginBottom: 8 } }, "IMPLEMENTATION STEPS:"), bp.steps.map((step2, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, style: { fontSize: 10, color: COLORS.textDim, marginBottom: 6, display: "flex", gap: 8 } }, /* @__PURE__ */ React.createElement("span", { style: { color: COLORS.accent, fontWeight: 700 } }, idx + 1, "."), /* @__PURE__ */ React.createElement("span", null, step2))))))))), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "1fr 320px", gap: 24, marginBottom: 24 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 18, marginBottom: 18 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12 } }, ["1. IDENTITY", "2. ACCESS SCOPE", "3. CONTROLS"].map((label, idx) => /* @__PURE__ */ React.createElement("div", { key: idx, style: { display: "flex", alignItems: "center", gap: 8, flex: 1 } }, /* @__PURE__ */ React.createElement("div", { style: {
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
      border: `2px solid ${step > idx ? COLORS.success : step === idx ? COLORS.accent : COLORS.border}`
    } }, step > idx ? "\u2713" : idx + 1), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 600, color: step >= idx ? COLORS.text : COLORS.textMuted } }, label), idx < 2 && /* @__PURE__ */ React.createElement("div", { style: { flex: 1, height: 2, background: step > idx ? COLORS.success : COLORS.border, borderRadius: 1 } }))))), step === 0 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 18, fontWeight: 700, marginBottom: 16 } }, "Select Identity Type"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14 } }, IDENTITY_TYPES.map((i) => /* @__PURE__ */ React.createElement(
      "div",
      {
        key: i.id,
        onClick: () => {
          setIdentity(i.id);
          setStep(1);
        },
        style: {
          background: identity === i.id ? COLORS.surfaceAlt : COLORS.surface,
          border: `1px solid ${identity === i.id ? COLORS.accent : COLORS.border}`,
          borderRadius: 12,
          padding: 20,
          cursor: "pointer",
          transition: "all 0.15s"
        }
      },
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 32, marginBottom: 10 } }, i.icon),
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 15, fontWeight: 700, marginBottom: 6 } }, i.label),
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: COLORS.textMuted, marginBottom: 12 } }, i.desc),
      /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 9, color: COLORS.textMuted } }, "BASE RISK:"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 13, fontWeight: 700, color: i.baseRisk > 70 ? COLORS.danger : i.baseRisk > 50 ? COLORS.warning : COLORS.success } }, i.baseRisk))
    )))), step === 1 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 18, fontWeight: 700, marginBottom: 16 } }, "Select Access Scope"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14 } }, ACCESS_TARGETS.map((t) => /* @__PURE__ */ React.createElement(
      "div",
      {
        key: t.id,
        onClick: () => {
          setTarget(t.id);
          setStep(2);
        },
        style: {
          background: target === t.id ? COLORS.surfaceAlt : COLORS.surface,
          border: `1px solid ${target === t.id ? COLORS.accent : COLORS.border}`,
          borderRadius: 12,
          padding: 20,
          cursor: "pointer",
          transition: "all 0.15s"
        }
      },
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 32, marginBottom: 10 } }, t.icon),
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 15, fontWeight: 700, marginBottom: 6 } }, t.label),
      /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: COLORS.textMuted } }, t.desc)
    ))), /* @__PURE__ */ React.createElement("div", { style: { marginTop: 16 } }, /* @__PURE__ */ React.createElement(Btn, { label: "\u2190 BACK", onClick: () => setStep(0), secondary: true }))), step === 2 && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 18, fontWeight: 700, marginBottom: 16 } }, "Configure Security Controls"), identity === "admin" && !phishMfaActive && /* @__PURE__ */ React.createElement("div", { style: { background: `${COLORS.danger}10`, border: `1px solid ${COLORS.danger}40`, borderRadius: 12, padding: 14, marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontWeight: 700, color: COLORS.danger, marginBottom: 4 } }, "\u{1F6A8} CRITICAL: Phishing-resistant MFA required for administrators"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textDim } }, "Standard MFA can be bypassed via AiTM attacks. FIDO2/WHfB is mandatory for admin accounts.")), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gap: 10 } }, POLICY_CONTROLS.map((c) => {
      const isSelected = selectedControls.includes(c.id);
      const col = CONTROL_COLORS[c.id] || COLORS.accent;
      const isDisabled = c.id === "mfa" && phishMfaActive;
      return /* @__PURE__ */ React.createElement(
        "div",
        {
          key: c.id,
          style: {
            background: isSelected ? `${col}08` : COLORS.surface,
            border: `1px solid ${isSelected ? `${col}50` : COLORS.border}`,
            borderRadius: 10,
            padding: 16,
            opacity: isDisabled ? 0.5 : 1
          }
        },
        /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "start", gap: 12, marginBottom: c.hasSettings && isSelected ? 12 : 0 } }, /* @__PURE__ */ React.createElement(
          "div",
          {
            onClick: () => !isDisabled && toggleControl(c.id),
            style: {
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
              cursor: isDisabled ? "not-allowed" : "pointer"
            }
          },
          isSelected && /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11, color: "#fff" } }, "\u2713")
        ), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8, marginBottom: 6 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 700, color: isSelected ? col : COLORS.text } }, c.label), !c.hasSettings && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4, background: `${COLORS.success}20`, color: COLORS.success } }, "-", c.baseRiskReduction, "% RISK")), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: COLORS.textMuted, marginBottom: 6 } }, c.desc), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textDim, fontStyle: "italic", marginBottom: 8 } }, c.why), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 8 } }, c.mitreBlocked.map((m) => /* @__PURE__ */ React.createElement("span", { key: m, style: { fontSize: 8, padding: "2px 6px", borderRadius: 3, background: `${COLORS.danger}15`, color: COLORS.danger, fontFamily: "monospace", fontWeight: 600 } }, m))), c.bestPractice && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, padding: 8, background: `${COLORS.accent}08`, borderRadius: 6, border: `1px solid ${COLORS.accent}20`, color: COLORS.accentBright } }, "\u{1F4A1} ", /* @__PURE__ */ React.createElement("strong", null, "Best Practice:"), " ", c.bestPractice))),
        c.hasSettings && isSelected && /* @__PURE__ */ React.createElement("div", { style: { paddingLeft: 30, marginTop: 12, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` } }, c.id === "session_controls" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "SESSION TIMEOUT"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(80px, 1fr))", gap: 6 } }, SESSION_TIMEOUT_OPTIONS.map((opt) => /* @__PURE__ */ React.createElement(
          "button",
          {
            key: opt.value,
            onClick: () => updateControlSetting("session_controls", "timeout", opt.value),
            style: {
              padding: "8px",
              background: controlSettings.session_controls?.timeout === opt.value ? `${col}30` : COLORS.surfaceAlt,
              border: `1px solid ${controlSettings.session_controls?.timeout === opt.value ? col : COLORS.border}`,
              borderRadius: 6,
              color: controlSettings.session_controls?.timeout === opt.value ? col : COLORS.text,
              cursor: "pointer",
              fontSize: 9,
              fontWeight: 700,
              fontFamily: "inherit",
              position: "relative"
            }
          },
          opt.label,
          opt.recommended && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 7, color: COLORS.success, marginTop: 2 } }, "\u2713 RECOMMENDED"),
          /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.success, marginTop: 2 } }, "-", opt.riskReduction, "%")
        )))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "SIGN-IN FREQUENCY"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(80px, 1fr))", gap: 6 } }, SIGN_IN_FREQUENCY_OPTIONS.map((opt) => /* @__PURE__ */ React.createElement(
          "button",
          {
            key: opt.value,
            onClick: () => updateControlSetting("session_controls", "frequency", opt.value),
            style: {
              padding: "8px",
              background: controlSettings.session_controls?.frequency === opt.value ? `${col}30` : COLORS.surfaceAlt,
              border: `1px solid ${controlSettings.session_controls?.frequency === opt.value ? col : COLORS.border}`,
              borderRadius: 6,
              color: controlSettings.session_controls?.frequency === opt.value ? col : COLORS.text,
              cursor: "pointer",
              fontSize: 9,
              fontWeight: 700,
              fontFamily: "inherit"
            }
          },
          opt.label,
          opt.recommended && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 7, color: COLORS.success, marginTop: 2 } }, "\u2713 RECOMMENDED"),
          /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.success, marginTop: 2 } }, "-", opt.riskReduction, "%")
        ))))), (c.id === "sign_in_risk" || c.id === "user_risk") && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 9, color: COLORS.textMuted, marginBottom: 6, letterSpacing: "0.1em" } }, "RISK THRESHOLD"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(100px, 1fr))", gap: 6 } }, RISK_LEVEL_OPTIONS.map((opt) => /* @__PURE__ */ React.createElement(
          "button",
          {
            key: opt.value,
            onClick: () => updateControlSetting(c.id, "level", opt.value),
            style: {
              padding: "10px",
              background: controlSettings[c.id]?.level === opt.value ? `${col}30` : COLORS.surfaceAlt,
              border: `1px solid ${controlSettings[c.id]?.level === opt.value ? col : COLORS.border}`,
              borderRadius: 6,
              color: controlSettings[c.id]?.level === opt.value ? col : COLORS.text,
              cursor: "pointer",
              fontSize: 9,
              fontWeight: 700,
              fontFamily: "inherit"
            }
          },
          opt.label,
          opt.recommended && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 7, color: COLORS.success, marginTop: 2 } }, "\u2713 RECOMMENDED"),
          /* @__PURE__ */ React.createElement("div", { style: { fontSize: 8, color: COLORS.success, marginTop: 2 } }, "-", opt.riskReduction, "%")
        )))))
      );
    })), /* @__PURE__ */ React.createElement("div", { style: { marginTop: 16 } }, /* @__PURE__ */ React.createElement(Btn, { label: "\u2190 BACK", onClick: () => setStep(1), secondary: true })))), /* @__PURE__ */ React.createElement(
      ThreatAnalyticsSidebar,
      {
        identity,
        target,
        controls: selectedControls,
        controlSettings
      }
    )), /* @__PURE__ */ React.createElement(ThreatCoverageMap, { controls: selectedControls, controlSettings, identity })));
  }
  var root = ReactDOM.createRoot(document.getElementById("root"));
  root.render(/* @__PURE__ */ React.createElement(ConditionalAccessBuilder, null));
})();
