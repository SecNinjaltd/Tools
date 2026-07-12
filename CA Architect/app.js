(() => {
  'use strict';

  const BASELINE = window.CA_BASELINE;
  const DECISIONS = { include: 'include', monitor: 'monitor', exclude: 'exclude' };
  const NON_REPORT_ONLY = new Set(['CA104', 'CA209']);
  const RECOMMENDED_STRATEGY_THREATS = ['T1078', 'T1110', 'T1557', 'T1621', 'T1528', 'AGENT-RISK'];
  const THEME_STORAGE_KEY = 'caArchitectTheme';
  const EXPERT_STORAGE_KEY = 'caArchitectExpertDetail';
  const GLOBAL_PREREQUISITES = [
    'Create security group CA-BreakGlassAccounts-Exclude for break-glass and emergency access exclusions'
  ];
  const STATIC_OBJECT_CATALOG = [
    ['role', '11451d60-acb2-45eb-a7d6-43d0f0125c13', 'Windows 365 Administrator'],
    ['role', '158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'],
    ['role', '1707125e-0aa2-4d4d-8655-a7c786c76a25', 'Microsoft 365 Backup Administrator'],
    ['role', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'],
    ['role', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'],
    ['role', '3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator'],
    ['role', '62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'],
    ['role', '69091246-20e8-4a56-aa4d-066075b2a7a8', 'Teams Administrator'],
    ['role', '6b942400-691f-4bf0-9d12-d8a254a2baf5', 'Agent Registry Administrator'],
    ['role', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'Helpdesk Administrator'],
    ['role', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'Privileged Authentication Administrator'],
    ['role', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'Password Administrator'],
    ['role', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'],
    ['role', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'Billing Administrator'],
    ['role', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'],
    ['role', 'b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb', 'Entra Backup Administrator'],
    ['role', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'],
    ['role', 'd2562ede-74db-457e-a7b6-544e236ebb61', 'AI Administrator'],
    ['role', 'd29b2b05-8046-44ba-8758-1e26182fcf32', 'Directory Synchronization Accounts'],
    ['role', 'db506228-d27e-4b7d-95e5-295956d6615f', 'Agent ID Administrator'],
    ['role', 'e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'],
    ['role', 'e93e3737-fa85-474a-aee4-7d3fb86510f3', 'Dragon Administrator'],
    ['role', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'],
    ['role', 'f2ef992c-3afb-46b9-b7cf-a126ee74c451', 'Global Reader'],
    ['role', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'],
    ['group', '2802b872-ccfb-4b29-a9a9-459808dfb11b', 'CA-BreakGlassAccounts-Exclude'],
    ['group', '77c1ed37-10d0-4ef1-93dc-198e70abb166', 'CA-ServiceAccounts'],
    ['application', '00000002-0000-0ff1-ce00-000000000000', 'Office 365 Exchange Online'],
    ['application', '00000003-0000-0ff1-ce00-000000000000', 'Office 365 SharePoint Online'],
    ['application', '0000000a-0000-0000-c000-000000000000', 'Microsoft Intune'],
    ['application', '14d82eec-204b-4c2f-b7e8-296a70dab67e', 'Microsoft Graph PowerShell'],
    ['application', 'd4ebce55-015a-49b5-a083-c84d1797ae8c', 'Microsoft Intune Enrollment'],
    ['application', 'f53895d3-095d-408f-8e93-8f94b391404e', 'Project for the web'],
    ['application', '2793995e-0a7d-40d7-bd35-6968ba142197', 'Microsoft Forms']
  ];
  const STATIC_OBJECT_LOOKUP = new Map(STATIC_OBJECT_CATALOG.map(([type, id, name]) => [
    objectCatalogKey(id, type),
    { id, type, name, source: 'static' }
  ]));
  const WORKFLOW_TABS = new Set(['start', 'strategy-builder', 'scenario-planner', 'policy-recommendations', 'import-compare']);
  const IMPORT_FILTERS = new Set(['all', 'exact', 'different', 'missing', 'extra', 'risk']);
  const COMPARE_FIELDS = [
    { path: ['state'], label: 'State' },
    { path: ['conditions', 'users', 'includeUsers'], label: 'Included users' },
    { path: ['conditions', 'users', 'excludeUsers'], label: 'Excluded users' },
    { path: ['conditions', 'users', 'includeGroups'], label: 'Included groups' },
    { path: ['conditions', 'users', 'excludeGroups'], label: 'Excluded groups' },
    { path: ['conditions', 'users', 'includeRoles'], label: 'Included roles' },
    { path: ['conditions', 'users', 'excludeRoles'], label: 'Excluded roles' },
    { path: ['conditions', 'applications', 'includeApplications'], label: 'Included apps/resources' },
    { path: ['conditions', 'applications', 'excludeApplications'], label: 'Excluded apps/resources' },
    { path: ['conditions', 'applications', 'includeUserActions'], label: 'User actions' },
    { path: ['conditions', 'clientAppTypes'], label: 'Client app types' },
    { path: ['conditions', 'platforms', 'includePlatforms'], label: 'Included platforms' },
    { path: ['conditions', 'platforms', 'excludePlatforms'], label: 'Excluded platforms' },
    { path: ['conditions', 'locations', 'includeLocations'], label: 'Included locations' },
    { path: ['conditions', 'locations', 'excludeLocations'], label: 'Excluded locations' },
    { path: ['conditions', 'signInRiskLevels'], label: 'Sign-in risk' },
    { path: ['conditions', 'userRiskLevels'], label: 'User risk' },
    { path: ['conditions', 'agentIdRiskLevels'], label: 'Agent risk' },
    { path: ['conditions', 'clientApplications', 'includeServicePrincipals'], label: 'Included service principals' },
    { path: ['conditions', 'clientApplications', 'excludeServicePrincipals'], label: 'Excluded service principals' },
    { path: ['conditions', 'clientApplications', 'includeAgentIdServicePrincipals'], label: 'Included agent identities' },
    { path: ['conditions', 'clientApplications', 'excludeAgentIdServicePrincipals'], label: 'Excluded agent identities' },
    { path: ['grantControls'], label: 'Grant controls' },
    { path: ['sessionControls'], label: 'Session controls' }
  ];
  const PURPOSE_GROUPS = [
    {
      id: 'risky-signins',
      title: 'Stop legacy and risky sign-ins',
      desc: 'Block old protocols, risky sign-ins, and weak authentication paths.',
      controls: ['legacy_auth', 'sign_in_risk', 'user_risk', 'auth_flows', 'mfa']
    },
    {
      id: 'admin-access',
      title: 'Strengthen administrator access',
      desc: 'Add stronger requirements for privileged users and admin portals.',
      controls: ['admin_mfa', 'phish_mfa', 'admin_session']
    },
    {
      id: 'sessions',
      title: 'Control sessions',
      desc: 'Limit session persistence and require safer browser experiences.',
      controls: ['session_controls', 'persistent_browser']
    },
    {
      id: 'devices-apps',
      title: 'Protect devices and apps',
      desc: 'Require compliant devices, app protection, and safer app targeting.',
      controls: ['device_compliance', 'app_protection', 'unknown_platforms', 'selected_app_block', 'guest_access', 'trusted_location', 'service_account_protection']
    },
    {
      id: 'agents-workloads',
      title: 'Agent and workload protections',
      desc: 'Protect service accounts, agent identities, and agent resource access.',
      controls: ['agent_risk', 'agent_identity_block', 'agent_user_risk', 'agent_compliant_device', 'agent_compliant_network', 'agent_users_block', 'users_agent_resources_block']
    },
    {
      id: 'scenarios',
      title: 'Scenario access packs',
      desc: 'Generated policies for a specific access group, resource, and access situation.',
      controls: []
    },
    {
      id: 'library',
      title: 'Other baseline policies',
      desc: 'Baseline items available for expert review.',
      controls: []
    }
  ];

  const IDENTITY_TYPES = [
    {
      id: 'all_users',
      label: 'All users',
      desc: 'Tenant-wide user coverage including guests',
      personas: ['Global', 'Admins', 'Internals', 'Guests'],
      baseRisk: 72,
      controls: ['mfa', 'legacy_auth'],
      threats: ['T1078', 'T1110', 'T1621']
    },
    {
      id: 'admins',
      label: 'Administrators',
      desc: 'Privileged roles and admin portals',
      personas: ['Global', 'Admins'],
      baseRisk: 90,
      controls: ['phish_mfa', 'admin_session', 'legacy_auth'],
      threats: ['T1078', 'T1557', 'T1621', 'T1098', 'T1484']
    },
    {
      id: 'internals',
      label: 'Internal users',
      desc: 'Employees and managed workforce identities',
      personas: ['Global', 'Internals'],
      baseRisk: 64,
      controls: ['mfa', 'device_compliance'],
      threats: ['T1078', 'T1110', 'T1539', 'T1528']
    },
    {
      id: 'guests',
      label: 'Guests and partners',
      desc: 'B2B, external collaboration, and partner access',
      personas: ['Global', 'Guests'],
      baseRisk: 76,
      controls: ['guest_access', 'mfa'],
      threats: ['T1199', 'T1078', 'T1110']
    },
    {
      id: 'service_accounts',
      label: 'Service accounts',
      desc: 'Named non-human accounts and operational identities',
      personas: ['Global', 'Service Accounts'],
      baseRisk: 78,
      controls: ['service_account_protection', 'trusted_location'],
      threats: ['T1078', 'T1133', 'T1528']
    },
    {
      id: 'agent_identities',
      label: 'Agent identities',
      desc: 'Copilot, agent ID, and autonomous agent service principals',
      personas: ['Agents'],
      baseRisk: 86,
      controls: ['agent_risk', 'agent_identity_block'],
      threats: ['AGENT-RISK', 'AGENT-RESOURCE', 'T1528']
    },
    {
      id: 'agent_users',
      label: 'Agent users',
      desc: 'Agents acting as users from endpoint-backed sessions',
      personas: ['Agents'],
      baseRisk: 82,
      controls: ['agent_user_risk', 'agent_compliant_device'],
      threats: ['AGENT-OBO', 'AGENT-RESOURCE', 'T1539']
    },
    {
      id: 'copilot_agents',
      label: 'Copilot agents',
      desc: 'Copilot Studio, Security Copilot, and M365 agent resources',
      personas: ['Global', 'Agents'],
      baseRisk: 88,
      controls: ['agent_risk', 'agent_identity_block', 'agent_users_block', 'users_agent_resources_block'],
      threats: ['AGENT-RISK', 'AGENT-OBO', 'AGENT-RESOURCE', 'T1528']
    }
  ];

  const TARGETS = [
    {
      id: 'all_resources',
      label: 'All resources',
      desc: 'Broad resource coverage',
      riskMultiplier: 1.4,
      controls: [],
      threats: ['T1078', 'T1528']
    },
    {
      id: 'admin_portals',
      label: 'Admin portals',
      desc: 'Microsoft Entra, Intune, Azure, and M365 admin surfaces',
      riskMultiplier: 1.75,
      controls: ['admin_mfa', 'admin_session', 'phish_mfa'],
      threats: ['T1556', 'T1484', 'T1606', 'T1557']
    },
    {
      id: 'office365',
      label: 'Microsoft 365',
      desc: 'Exchange, SharePoint, Teams, and Office 365 suite',
      riskMultiplier: 1.22,
      controls: ['app_protection', 'session_controls'],
      threats: ['T1528', 'T1539', 'T1606']
    },
    {
      id: 'selected_apps',
      label: 'Selected apps',
      desc: 'Specific enterprise applications or app suites',
      riskMultiplier: 1,
      controls: ['selected_app_block'],
      threats: ['T1199', 'T1528']
    },
    {
      id: 'agent_resources',
      label: 'Agent resources',
      desc: 'All agent resources and agent token requests',
      riskMultiplier: 1.65,
      controls: ['agent_identity_block', 'users_agent_resources_block'],
      threats: ['AGENT-RISK', 'AGENT-RESOURCE', 'AGENT-OBO']
    }
  ];

  const THREATS = [
    {
      id: 'T1078',
      name: 'Valid Accounts',
      tactic: 'Initial Access',
      severity: 'High',
      desc: 'Abuse of legitimate credentials, tokens, or sessions.',
      controls: ['mfa', 'phish_mfa', 'sign_in_risk', 'user_risk']
    },
    {
      id: 'T1110',
      name: 'Brute Force',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'Password spray, credential stuffing, and repeated guessing.',
      controls: ['legacy_auth', 'mfa', 'sign_in_risk']
    },
    {
      id: 'T1528',
      name: 'Steal Application Access Token',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'OAuth token theft against cloud applications and agents.',
      controls: ['app_protection', 'device_compliance', 'session_controls', 'agent_identity_block']
    },
    {
      id: 'T1539',
      name: 'Steal Web Session Cookie',
      tactic: 'Credential Access',
      severity: 'Medium',
      desc: 'Session hijacking through browser cookies or refresh tokens.',
      controls: ['session_controls', 'persistent_browser', 'device_compliance']
    },
    {
      id: 'T1556',
      name: 'Modify Authentication Process',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'Weakening or bypassing authentication controls.',
      controls: ['phish_mfa', 'admin_mfa', 'user_risk']
    },
    {
      id: 'T1621',
      name: 'MFA Request Generation',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'MFA fatigue and push approval coercion.',
      controls: ['phish_mfa', 'mfa', 'sign_in_risk']
    },
    {
      id: 'T1098',
      name: 'Account Manipulation',
      tactic: 'Persistence',
      severity: 'Medium',
      desc: 'Changing account settings to preserve access.',
      controls: ['user_risk', 'admin_session', 'phish_mfa']
    },
    {
      id: 'T1484',
      name: 'Domain Policy Modification',
      tactic: 'Defense Evasion',
      severity: 'Medium',
      desc: 'Policy tampering and administrator control plane abuse.',
      controls: ['admin_mfa', 'phish_mfa', 'admin_session']
    },
    {
      id: 'T1557',
      name: 'Adversary-in-the-Middle',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'Relay and phishing proxy attacks against sign-in flows.',
      controls: ['phish_mfa', 'sign_in_risk', 'auth_flows']
    },
    {
      id: 'T1606',
      name: 'Forge Web Credentials',
      tactic: 'Credential Access',
      severity: 'High',
      desc: 'Forged tokens, cookies, and assertions.',
      controls: ['phish_mfa', 'sign_in_risk', 'session_controls']
    },
    {
      id: 'T1133',
      name: 'External Remote Services',
      tactic: 'Persistence',
      severity: 'Medium',
      desc: 'Abuse of remote entry points and legacy protocols.',
      controls: ['legacy_auth', 'trusted_location', 'unknown_platforms']
    },
    {
      id: 'T1199',
      name: 'Trusted Relationship',
      tactic: 'Initial Access',
      severity: 'Medium',
      desc: 'Partner, guest, and third-party trust abuse.',
      controls: ['guest_access', 'trusted_location', 'selected_app_block']
    },
    {
      id: 'AGENT-RISK',
      name: 'Risky Agent Identity',
      tactic: 'Agentic Identity',
      severity: 'High',
      desc: 'Compromised Copilot or agent identity token requests.',
      controls: ['agent_risk', 'agent_identity_block']
    },
    {
      id: 'AGENT-OBO',
      name: 'Agent Acting as User',
      tactic: 'Agentic Identity',
      severity: 'High',
      desc: 'Agents performing delegated actions through agent user accounts.',
      controls: ['agent_user_risk', 'agent_compliant_device', 'agent_users_block']
    },
    {
      id: 'AGENT-RESOURCE',
      name: 'Agent Resource Access',
      tactic: 'Agentic Identity',
      severity: 'High',
      desc: 'Human or agent access to agent-specific resources.',
      controls: ['users_agent_resources_block', 'agent_identity_block', 'agent_compliant_network']
    }
  ];

  const CONTROLS = {
    mfa: {
      label: 'Require MFA',
      category: 'Authentication',
      reduction: 18,
      color: '#008fd6',
      policyIds: ['CA000', 'CA100', 'CA101', 'CA200', 'CA300', 'CA400']
    },
    admin_mfa: {
      label: 'Admin MFA',
      category: 'Authentication',
      reduction: 18,
      color: '#008fd6',
      policyIds: ['CA100', 'CA101']
    },
    phish_mfa: {
      label: 'Phishing-resistant MFA',
      category: 'Authentication',
      reduction: 30,
      color: '#7f3fbf',
      policyIds: ['CA105']
    },
    legacy_auth: {
      label: 'Block legacy authentication',
      category: 'Attack Surface',
      reduction: 24,
      color: '#e8610a',
      policyIds: ['CA002']
    },
    auth_flows: {
      label: 'Block risky authentication flows',
      category: 'Attack Surface',
      reduction: 16,
      color: '#e1063a',
      policyIds: ['CA004']
    },
    device_compliance: {
      label: 'Require compliant device',
      category: 'Device',
      reduction: 18,
      color: '#00a96e',
      policyIds: ['CA205', 'CA208']
    },
    app_protection: {
      label: 'App protection and restrictions',
      category: 'Data Protection',
      reduction: 17,
      color: '#00a96e',
      policyIds: ['CA005', 'CA006']
    },
    trusted_location: {
      label: 'Trusted location controls',
      category: 'Network',
      reduction: 15,
      color: '#a05a00',
      policyIds: ['CA001', 'CA301']
    },
    sign_in_risk: {
      label: 'Block high sign-in risk',
      category: 'Identity Protection',
      reduction: 22,
      color: '#e1063a',
      policyIds: ['CA210']
    },
    user_risk: {
      label: 'Block high user risk',
      category: 'Identity Protection',
      reduction: 20,
      color: '#c2175b',
      policyIds: ['CA201']
    },
    session_controls: {
      label: 'Session controls',
      category: 'Session',
      reduction: 12,
      color: '#4254b5',
      policyIds: ['CA102', 'CA104', 'CA202', 'CA209', 'CA402']
    },
    persistent_browser: {
      label: 'Persistent browser controls',
      category: 'Session',
      reduction: 10,
      color: '#4254b5',
      policyIds: ['CA103', 'CA206', 'CA403']
    },
    admin_session: {
      label: 'Admin session controls',
      category: 'Session',
      reduction: 12,
      color: '#4254b5',
      policyIds: ['CA102', 'CA103', 'CA104']
    },
    unknown_platforms: {
      label: 'Block unknown platforms',
      category: 'Device',
      reduction: 10,
      color: '#e1063a',
      policyIds: ['CA204']
    },
    selected_app_block: {
      label: 'Selected app block controls',
      category: 'Attack Surface',
      reduction: 10,
      color: '#e8610a',
      policyIds: ['CA207', 'CA404']
    },
    guest_access: {
      label: 'Guest access guardrails',
      category: 'External Identity',
      reduction: 18,
      color: '#008fd6',
      policyIds: ['CA400', 'CA401', 'CA402', 'CA403', 'CA404']
    },
    service_account_protection: {
      label: 'Service account protection',
      category: 'Workload Identity',
      reduction: 16,
      color: '#008fd6',
      policyIds: ['CA300', 'CA301']
    },
    agent_risk: {
      label: 'Agent risk blocking',
      category: 'Agent Identity',
      reduction: 24,
      color: '#7f3fbf',
      policyIds: ['CA501', 'CA504']
    },
    agent_identity_block: {
      label: 'Block unapproved agent identities',
      category: 'Agent Identity',
      reduction: 28,
      color: '#e1063a',
      policyIds: ['CA502']
    },
    agent_user_risk: {
      label: 'Agent user risk blocking',
      category: 'Agent User',
      reduction: 22,
      color: '#c2175b',
      policyIds: ['CA504']
    },
    agent_compliant_device: {
      label: 'Agent user compliant device',
      category: 'Agent User',
      reduction: 16,
      color: '#00a96e',
      policyIds: ['CA503']
    },
    agent_compliant_network: {
      label: 'Agent compliant network',
      category: 'Agent User',
      reduction: 16,
      color: '#a05a00',
      policyIds: ['CA505']
    },
    agent_users_block: {
      label: 'Block all agent users',
      category: 'Agent User',
      reduction: 24,
      color: '#e1063a',
      policyIds: ['CA506']
    },
    users_agent_resources_block: {
      label: 'Block users from agent resources',
      category: 'Agent Resource',
      reduction: 22,
      color: '#e1063a',
      policyIds: ['CA507']
    }
  };

  const OVERRIDE_FIELDS = [
    { id: 'excludeUsers', label: 'Exclude users', path: ['conditions', 'users', 'excludeUsers'], className: 'identity-edit' },
    { id: 'excludeGroups', label: 'Exclude groups', path: ['conditions', 'users', 'excludeGroups'], className: 'identity-edit' },
    { id: 'excludeRoles', label: 'Exclude roles', path: ['conditions', 'users', 'excludeRoles'], className: 'identity-edit' },
    { id: 'excludeServicePrincipals', label: 'Exclude service principals', path: ['conditions', 'clientApplications', 'excludeServicePrincipals'], className: 'workload-edit' },
    { id: 'includeAgentIdServicePrincipals', label: 'Include agent identities', path: ['conditions', 'clientApplications', 'includeAgentIdServicePrincipals'], className: 'agent-edit' },
    { id: 'excludeAgentIdServicePrincipals', label: 'Exclude agent identities', path: ['conditions', 'clientApplications', 'excludeAgentIdServicePrincipals'], className: 'agent-edit' },
    { id: 'includeApplications', label: 'Include target resources', path: ['conditions', 'applications', 'includeApplications'], className: 'resource-edit' },
    { id: 'excludeApplications', label: 'Exclude target resources', path: ['conditions', 'applications', 'excludeApplications'], className: 'resource-edit' },
    { id: 'includeLocations', label: 'Include locations', path: ['conditions', 'locations', 'includeLocations'], className: 'location-edit' },
    { id: 'excludeLocations', label: 'Exclude locations', path: ['conditions', 'locations', 'excludeLocations'], className: 'location-edit' }
  ];

  const GENERATED_POLICIES = [
    {
      id: 'CA506',
      persona: 'Agents',
      displayName: 'CA506-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-BLOCK',
      sourceFile: 'Generated/ConditionalAccess/CA506-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-BLOCK.json',
      state: 'enabledForReportingButNotEnforced',
      risk: 'critical',
      summary: 'Block all agent user accounts from accessing resources while agent user inventory is validated.',
      prerequisites: [
        'Microsoft Graph beta Conditional Access support reviewed',
        'Agent user account inventory reviewed'
      ],
      requiredObjects: [],
      rolloutDefault: 'monitor',
      kind: 'generated',
      generated: true,
      preview: true,
      policy: {
        displayName: 'CA506-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-BLOCK',
        state: 'enabledForReportingButNotEnforced',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeUsers: ['AllAgentIdUsers']
          },
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls: {
          operator: 'AND',
          builtInControls: ['block']
        }
      }
    },
    {
      id: 'CA507',
      persona: 'Global',
      displayName: 'CA507-Global-AttackSurfaceReduction-AllUsers-AllAgentResources-BLOCK',
      sourceFile: 'Generated/ConditionalAccess/CA507-Global-AttackSurfaceReduction-AllUsers-AllAgentResources-BLOCK.json',
      state: 'enabledForReportingButNotEnforced',
      risk: 'critical',
      summary: 'Block users from signing into agent resources or initiating delegated agent actions until approved.',
      prerequisites: [
        'Microsoft Graph beta Conditional Access support reviewed',
        'Approved agent resource access paths documented'
      ],
      requiredObjects: [],
      rolloutDefault: 'monitor',
      kind: 'generated',
      generated: true,
      preview: true,
      policy: {
        displayName: 'CA507-Global-AttackSurfaceReduction-AllUsers-AllAgentResources-BLOCK',
        state: 'enabledForReportingButNotEnforced',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeUsers: ['All']
          },
          applications: {
            includeApplications: ['AllAgentIdResources'],
            excludeApplications: []
          }
        },
        grantControls: {
          operator: 'AND',
          builtInControls: ['block']
        }
      }
    }
  ];

  const STRATEGY_DEFAULTS = {
    protection: 'maximum',
    rollout: 'balanced',
    admins: false,
    internals: false,
    managedDevices: false,
    guests: false,
    serviceAccounts: false,
    agents: false,
    trustedLocations: false,
    legacyExceptions: false,
    mode: 'consolidated'
  };

  const STRATEGY_LEVELS = {
    starter: {
      label: 'Starter baseline',
      desc: 'Lower-friction settings for the requirements you select. No policies are generated until a requirement is selected.'
    },
    strong: {
      label: 'Strong defaults',
      desc: 'Recommended settings for the requirements you select, while keeping policy count low.'
    },
    maximum: {
      label: 'Maximum protection',
      desc: 'Strongest practical controls for the requirements you select, with only unavoidable guardrails kept separate.'
    }
  };

  const STRATEGY_REQUIREMENTS = {
    admins: {
      label: 'Privileged admin hardening',
      controls: ['admin_mfa', 'phish_mfa', 'admin_session'],
      controlsByLevel: {
        starter: ['admin_mfa', 'admin_session'],
        strong: ['admin_mfa', 'phish_mfa', 'admin_session', 'persistent_browser'],
        maximum: ['admin_mfa', 'phish_mfa', 'admin_session', 'session_controls', 'persistent_browser', 'legacy_auth', 'auth_flows', 'sign_in_risk', 'user_risk']
      },
      threats: ['T1078', 'T1557', 'T1621', 'T1484']
    },
    internals: {
      label: 'Internal workforce',
      controls: ['mfa', 'session_controls'],
      controlsByLevel: {
        starter: ['mfa'],
        strong: ['mfa', 'session_controls', 'persistent_browser'],
        maximum: ['mfa', 'session_controls', 'persistent_browser', 'legacy_auth', 'sign_in_risk', 'user_risk']
      },
      threats: ['T1078', 'T1110', 'T1539', 'T1528']
    },
    managedDevices: {
      label: 'Managed device posture',
      controls: ['device_compliance', 'app_protection', 'unknown_platforms'],
      controlsByLevel: {
        starter: ['device_compliance'],
        strong: ['device_compliance', 'app_protection'],
        maximum: ['device_compliance', 'app_protection', 'unknown_platforms']
      },
      threats: ['T1528', 'T1539']
    },
    guests: {
      label: 'Guests and partners',
      controls: ['guest_access'],
      controlsByLevel: {
        starter: ['guest_access'],
        strong: ['guest_access', 'session_controls'],
        maximum: ['guest_access', 'session_controls', 'persistent_browser', 'selected_app_block']
      },
      threats: ['T1199', 'T1078']
    },
    serviceAccounts: {
      label: 'Service accounts',
      controls: ['service_account_protection'],
      controlsByLevel: {
        starter: ['service_account_protection'],
        strong: ['service_account_protection', 'trusted_location'],
        maximum: ['service_account_protection', 'trusted_location', 'legacy_auth']
      },
      threats: ['T1078', 'T1133']
    },
    agents: {
      label: 'Copilot and agent identities',
      controls: ['agent_risk', 'agent_identity_block', 'agent_user_risk', 'agent_compliant_device', 'agent_compliant_network', 'agent_users_block', 'users_agent_resources_block'],
      controlsByLevel: {
        starter: ['agent_risk', 'agent_identity_block'],
        strong: ['agent_risk', 'agent_identity_block', 'agent_user_risk', 'agent_compliant_device'],
        maximum: ['agent_risk', 'agent_identity_block', 'agent_user_risk', 'agent_compliant_device', 'agent_compliant_network', 'agent_users_block', 'users_agent_resources_block']
      },
      threats: ['AGENT-RISK', 'AGENT-OBO', 'AGENT-RESOURCE']
    },
    trustedLocations: {
      label: 'Trusted network locations',
      controls: ['trusted_location'],
      controlsByLevel: {
        starter: ['trusted_location'],
        strong: ['trusted_location'],
        maximum: ['trusted_location']
      },
      threats: ['T1133', 'T1199']
    },
    legacyExceptions: {
      label: 'Legacy-auth exceptions required',
      controls: [],
      threats: ['T1110', 'T1133']
    }
  };

  const SCENARIO_DEFAULTS = {
    template: 'externalSharePoint',
    groupName: 'CA-Scenario-ExternalCollaboration-Users',
    groupId: '',
    locationId: '',
    accountType: 'externalGuest',
    resource: 'sharepoint',
    deviceTrust: 'browserOnly',
    platforms: 'any',
    location: 'any',
    riskTolerance: 'strict',
    authRequirement: 'standardMfa',
    accessDecision: 'grant',
    riskResponse: 'signInRisk',
    session: 'browserLocked',
    duration: 'temporary',
    sensitivity: 'sensitive',
    rollout: 'reportOnly'
  };

  const SCENARIO_TEMPLATES = [
    {
      id: 'externalSharePoint',
      label: 'External Collaboration Access',
      desc: 'External identity needs secure access to shared SharePoint or OneDrive content.',
      groupName: 'CA-Scenario-ExternalCollaboration-Users',
      fields: { accountType: 'externalGuest', resource: 'sharepoint', deviceTrust: 'browserOnly', platforms: 'any', location: 'any', riskTolerance: 'strict', authRequirement: 'standardMfa', session: 'browserLocked', duration: 'temporary', sensitivity: 'sensitive' },
      controls: ['mfa', 'app_protection', 'session_controls', 'persistent_browser', 'guest_access'],
      mitre: ['T1078', 'T1528', 'T1539', 'T1199'],
      policyId: 'CA900C',
      policyName: 'Scenario-ExternalCollaboration-BrowserRestrictedAccess',
      persona: 'Guests',
      risk: 'high',
      summary: 'Protect a specific external collaboration group accessing SharePoint content with MFA, browser restrictions, and short sessions.',
      prerequisites: [
        'Invite or verify the external identity redemption path.',
        'Create the scenario security group and add only approved external identities.',
        'Share the SharePoint folder/site with least privilege and remove anonymous sharing links.',
        'Conditional Access cannot target one SharePoint folder directly; use SharePoint permissions, site sensitivity, and sharing controls for the folder boundary.',
        'Configure SharePoint unmanaged-device access if you want browser-only or limited download behavior.'
      ],
      guidance: [
        'Target SharePoint Online only unless the same external identity also needs Teams or broader Microsoft 365 access.',
        'Use browser/app-enforced restrictions for unmanaged devices, and avoid requiring compliant device for external identities unless their device is genuinely manageable by your tenant.',
        'Use temporary access review or an expiry date for the scenario group membership.'
      ]
    },
    {
      id: 'm365AppUntrusted',
      label: 'Microsoft 365 App Access From Untrusted Device',
      desc: 'Internal identity needs Microsoft 365 app access from a device the organization does not manage.',
      groupName: 'CA-Scenario-M365App-UntrustedDevice',
      fields: { accountType: 'internalUser', resource: 'exchange', deviceTrust: 'browserOnly', platforms: 'windows', location: 'any', riskTolerance: 'balanced', authRequirement: 'standardMfa', session: 'browserLocked', duration: 'ongoing', sensitivity: 'standard' },
      controls: ['mfa', 'app_protection', 'session_controls', 'persistent_browser'],
      mitre: ['T1078', 'T1528', 'T1539'],
      policyId: 'CA910C',
      policyName: 'Scenario-M365App-UntrustedDevice',
      persona: 'Internals',
      risk: 'high',
      summary: 'Allow a specific access group to use Microsoft 365 apps safely from an untrusted device by preferring browser-only access with MFA and session restrictions.',
      prerequisites: [
        'Create the scenario security group and add only the approved identity.',
        'Decide whether desktop Office apps are allowed. Browser-only access is safer for unmanaged devices.',
        'Confirm the identity has only the mailbox, groups, and content permissions required for the access pattern.'
      ],
      guidance: [
        'Default to Exchange Online or Microsoft 365 browser clients with app-enforced restrictions where supported.',
        'If desktop app access is required on an unmanaged device, treat it as a risk exception and document owner, expiry, and compensating controls.',
        'Use short sign-in frequency and never persist browser sessions.'
      ]
    },
    {
      id: 'limitedCollaboration',
      label: 'Limited Collaboration Access',
      desc: 'External or temporary identity needs constrained Microsoft 365 collaboration.',
      groupName: 'CA-Scenario-LimitedCollaboration-Users',
      fields: { accountType: 'externalGuest', resource: 'office365', deviceTrust: 'unmanaged', platforms: 'any', location: 'any', riskTolerance: 'balanced', authRequirement: 'standardMfa', session: 'short', duration: 'temporary', sensitivity: 'standard' },
      controls: ['mfa', 'guest_access', 'session_controls', 'persistent_browser', 'app_protection'],
      mitre: ['T1078', 'T1199', 'T1528', 'T1539'],
      policyId: 'CA920C',
      policyName: 'Scenario-LimitedCollaboration-M365Access',
      persona: 'Guests',
      risk: 'medium',
      summary: 'Create a bounded collaboration access policy for Microsoft 365 core apps with MFA and reduced session persistence.',
      prerequisites: [
        'Create a limited-collaboration scenario group with named owner and expiry.',
        'Confirm guest settings, sharing settings, and application permissions before policy rollout.',
        'Exclude this population from broad risk-based guest policies only when a dedicated always-MFA policy covers the same access.'
      ],
      guidance: [
        'Keep the target resource to Office 365 unless the access pattern needs broader SaaS access.',
        'Use guest-specific access reviews and group expiry outside Conditional Access.'
      ]
    },
    {
      id: 'temporaryAdmin',
      label: 'Elevated Portal Access',
      desc: 'Privileged or temporary operator needs tightly controlled admin portal access.',
      groupName: 'CA-Scenario-ElevatedPortalAccess-Users',
      fields: { accountType: 'admin', resource: 'adminPortals', deviceTrust: 'managed', platforms: 'any', location: 'trustedOnly', riskTolerance: 'strict', authRequirement: 'phishingResistantMfa', session: 'short', duration: 'temporary', sensitivity: 'highlySensitive' },
      controls: ['phish_mfa', 'admin_mfa', 'admin_session', 'persistent_browser', 'device_compliance'],
      mitre: ['T1078', 'T1557', 'T1621', 'T1484'],
      policyId: 'CA930C',
      policyName: 'Scenario-ElevatedPortal-PhishingResistantMFA',
      persona: 'Admins',
      risk: 'critical',
      summary: 'Require phishing-resistant MFA, managed device posture, and short sessions for elevated portal access.',
      prerequisites: [
        'Use PIM or a time-boxed role assignment where possible.',
        'Create the scenario group, owner, ticket reference, and expiry date.',
        'Confirm break-glass accounts are excluded from this scenario policy.'
      ],
      guidance: [
        'Use phishing-resistant authentication strength for admin portal access.',
        'Keep this as a focused admin scenario policy and do not merge it with tenant-wide block policies.'
      ]
    },
    {
      id: 'serviceException',
      label: 'Automation Access Boundary',
      desc: 'Automation or non-human account needs tightly bounded access.',
      groupName: 'CA-Scenario-AutomationAccess-Boundary',
      fields: { accountType: 'serviceAccount', resource: 'allApps', deviceTrust: 'trustedLocation', platforms: 'any', location: 'trustedOnly', riskTolerance: 'strict', authRequirement: 'standardMfa', session: 'standard', duration: 'ongoing', sensitivity: 'sensitive' },
      controls: ['service_account_protection', 'trusted_location', 'legacy_auth'],
      mitre: ['T1078', 'T1133', 'T1110'],
      policyId: 'CA940C',
      policyName: 'Scenario-AutomationAccess-TrustedLocationOnly',
      persona: 'Service Accounts',
      risk: 'high',
      summary: 'Restrict automation access to trusted named locations and make ownership/exception boundaries explicit.',
      prerequisites: [
        'Create or confirm the service account group with owner, purpose, and review cadence.',
        'Provide the trusted named location object ID before export.',
        'Disable interactive sign-in where possible and replace legacy authentication with modern auth.'
      ],
      guidance: [
        'Use location boundaries only when IP ranges are stable and maintained.',
        'Do not use user MFA as the only protection for non-human automation accounts.'
      ],
      requiresLocation: true
    },
    {
      id: 'highSensitivityAccess',
      label: 'High-Sensitivity User Access',
      desc: 'High-sensitivity identity needs stronger access controls for elevated-risk conditions.',
      groupName: 'CA-Scenario-HighSensitivity-Users',
      fields: { accountType: 'internalUser', resource: 'office365', deviceTrust: 'managed', platforms: 'any', location: 'any', riskTolerance: 'strict', authRequirement: 'phishingResistantMfa', session: 'short', duration: 'temporary', sensitivity: 'highlySensitive' },
      controls: ['phish_mfa', 'mfa', 'sign_in_risk', 'session_controls', 'persistent_browser', 'device_compliance'],
      mitre: ['T1078', 'T1557', 'T1621', 'T1528', 'T1539'],
      policyId: 'CA950C',
      policyName: 'Scenario-HighSensitivity-StrongAuthSessions',
      persona: 'Internals',
      risk: 'high',
      summary: 'Tighten authentication, device, and session controls for a high-sensitivity identity or elevated-risk access pattern.',
      prerequisites: [
        'Confirm the access window, expected locations, and device inventory.',
        'Create a time-boxed scenario group and remove membership after the access window.',
        'Review sign-in risk detections during and after the high-sensitivity access period.'
      ],
      guidance: [
        'Prefer managed/compliant devices and phishing-resistant MFA for high-value users.',
        'Keep sign-in risk response separate from grant/session controls when generated.'
      ]
    },
    {
      id: 'breakGlassValidation',
      label: 'Emergency Access Validation',
      desc: 'Validate emergency accounts without weakening tenant controls.',
      groupName: 'CA-Scenario-EmergencyAccess-Validation',
      fields: { accountType: 'admin', resource: 'allApps', deviceTrust: 'trustedLocation', platforms: 'any', location: 'trustedOnly', riskTolerance: 'strict', authRequirement: 'phishingResistantMfa', session: 'standard', duration: 'emergency', sensitivity: 'highlySensitive' },
      controls: ['trusted_location', 'admin_session'],
      mitre: ['T1078', 'T1484'],
      policyId: 'CA960C',
      policyName: 'Scenario-EmergencyAccess-Validation-DoNotEnable',
      persona: 'Admins',
      risk: 'critical',
      summary: 'Create a disabled/report-only validation policy for emergency accounts; do not enforce controls that could block break-glass access.',
      prerequisites: [
        'Confirm at least two cloud-only emergency accounts exist and are excluded from broad CA policies.',
        'Store credentials securely and test sign-in on a documented cadence.',
        'Alert on emergency account sign-ins outside the tool.'
      ],
      guidance: [
        'This scenario is primarily a validation checklist. Do not enable a policy that can lock out emergency access.',
        'Use monitoring and access review instead of normal enforcement for break-glass accounts.'
      ],
      validationOnly: true
    },
    {
      id: 'agentPilot',
      label: 'Agent Resource Pilot',
      desc: 'Pilot agent resource access with preview controls isolated.',
      groupName: 'CA-Scenario-AgentResourcePilot-Users',
      fields: { accountType: 'agentIdentity', resource: 'agentResources', deviceTrust: 'managed', platforms: 'any', location: 'any', riskTolerance: 'strict', authRequirement: 'standardMfa', session: 'standard', duration: 'temporary', sensitivity: 'sensitive' },
      controls: ['users_agent_resources_block', 'agent_risk', 'agent_compliant_device'],
      mitre: ['AGENT-RISK', 'AGENT-OBO', 'AGENT-RESOURCE', 'T1528'],
      policyId: 'CA970C',
      policyName: 'Scenario-AgentResourcePilot-Guardrails',
      persona: 'Agents',
      risk: 'critical',
      summary: 'Keep agent preview/beta guardrails isolated while piloting agent resource access.',
      prerequisites: [
        'Confirm tenant support for current Microsoft Graph beta/preview agent identity Conditional Access fields.',
        'Create the scenario group for pilot users and document approved agent resources.',
        'Review agent identities and delegated agent actions before enforcement.'
      ],
      guidance: [
        'Do not merge agent policies into normal user policies.',
        'Start in report-only or disabled mode until the pilot inventory is complete.'
      ],
      preview: true
    },
    {
      id: 'custom',
      label: 'Custom Access Scenario',
      desc: 'Build a policy visually from identity through rollout.',
      groupName: 'CA-Scenario-CustomAccess-Users',
      fields: { accountType: 'internalUser', resource: 'office365', deviceTrust: 'managed', platforms: 'any', location: 'any', riskTolerance: 'balanced', authRequirement: 'standardMfa', accessDecision: 'grant', riskResponse: 'none', session: 'short', duration: 'temporary', sensitivity: 'sensitive', rollout: 'reportOnly' },
      controls: [],
      mitre: [],
      policyId: 'CA990C',
      policyName: 'Scenario-Custom-StructuredAccess',
      persona: 'Internals',
      risk: 'medium',
      summary: 'Custom scenario policy generated from the selected structured inputs.',
      prerequisites: [
        'Create a dedicated scenario group with owner, purpose, expiry, and review cadence.',
        'Confirm app/resource permissions outside Conditional Access.'
      ],
      guidance: [
        'Use the generated policy as a starting point and review each manual build step before enabling.'
      ]
    }
  ];

  const MITRE_COVERAGE = [
    {
      id: 'T1078',
      name: 'Valid Accounts',
      tactic: 'Initial Access / Persistence',
      strongControls: ['mfa', 'phish_mfa', 'sign_in_risk', 'user_risk'],
      partialControls: ['legacy_auth', 'admin_mfa', 'guest_access', 'service_account_protection']
    },
    {
      id: 'T1110',
      name: 'Brute Force / Password Spray',
      tactic: 'Credential Access',
      strongControls: ['legacy_auth', 'sign_in_risk', 'mfa'],
      partialControls: ['phish_mfa']
    },
    {
      id: 'T1621',
      name: 'MFA Request Generation',
      tactic: 'Credential Access',
      strongControls: ['phish_mfa', 'sign_in_risk'],
      partialControls: ['mfa', 'admin_mfa']
    },
    {
      id: 'T1557',
      name: 'Adversary-in-the-Middle',
      tactic: 'Credential Access',
      strongControls: ['phish_mfa', 'auth_flows'],
      partialControls: ['sign_in_risk', 'session_controls']
    },
    {
      id: 'T1528',
      name: 'Steal Application Access Token',
      tactic: 'Credential Access',
      strongControls: ['device_compliance', 'app_protection', 'session_controls'],
      partialControls: ['agent_identity_block', 'persistent_browser']
    },
    {
      id: 'T1539',
      name: 'Steal Web Session Cookie',
      tactic: 'Credential Access',
      strongControls: ['session_controls', 'persistent_browser', 'device_compliance'],
      partialControls: ['app_protection']
    },
    {
      id: 'T1556',
      name: 'Modify Authentication Process',
      tactic: 'Credential Access',
      strongControls: ['phish_mfa', 'admin_mfa', 'user_risk'],
      partialControls: ['admin_session']
    },
    {
      id: 'T1484',
      name: 'Domain Policy Modification',
      tactic: 'Defense Evasion',
      strongControls: ['phish_mfa', 'admin_mfa', 'admin_session'],
      partialControls: ['user_risk']
    },
    {
      id: 'T1133',
      name: 'External Remote Services',
      tactic: 'Persistence',
      strongControls: ['legacy_auth', 'trusted_location', 'unknown_platforms'],
      partialControls: ['service_account_protection']
    },
    {
      id: 'T1199',
      name: 'Trusted Relationship',
      tactic: 'Initial Access',
      strongControls: ['guest_access', 'trusted_location'],
      partialControls: ['selected_app_block', 'mfa']
    },
    {
      id: 'AGENT-RISK',
      name: 'Risky Agent Identity',
      tactic: 'Agentic Identity',
      strongControls: ['agent_risk', 'agent_identity_block'],
      partialControls: ['agent_user_risk']
    },
    {
      id: 'AGENT-OBO',
      name: 'Agent Acting as User',
      tactic: 'Agentic Identity',
      strongControls: ['agent_user_risk', 'agent_compliant_device', 'agent_users_block'],
      partialControls: ['agent_compliant_network']
    },
    {
      id: 'AGENT-RESOURCE',
      name: 'Agent Resource Access',
      tactic: 'Agentic Identity',
      strongControls: ['users_agent_resources_block', 'agent_identity_block', 'agent_compliant_network'],
      partialControls: ['agent_risk']
    }
  ];

  const RESIDUAL_GAPS = [
    'Conditional Access cannot remove already-stolen tokens from every downstream workload; pair this with token protection, sign-in log review, and rapid revocation playbooks.',
    'Conditional Access does not replace Privileged Identity Management, role hygiene, or regular access reviews for administrator accounts.',
    'Device compliance decisions require accurate Intune compliance policy, device inventory, and platform governance outside this tool.',
    'Named-location controls are only as reliable as the IP/location inventory behind them.',
    'Agent identity protection is still preview/beta-shaped in places and needs tenant capability validation before enforcement.'
  ];

  const SESSION_STRICTNESS_HELP = {
    standard: {
      title: 'Standard',
      meaning: 'Keeps normal Entra session behaviour and avoids adding extra session restrictions.',
      recommended: 'Use for low-risk, managed, ongoing access where the user experience should stay familiar.'
    },
    short: {
      title: 'Short session',
      meaning: 'Adds sign-in frequency so access is rechecked more often and stale sessions age out faster.',
      recommended: 'Use for sensitive data, temporary access, external collaboration, elevated access, or untrusted devices.'
    },
    browserLocked: {
      title: 'Browser locked down',
      meaning: 'Prefers browser-based access, never persists browser sessions, and enables app-enforced restrictions where supported.',
      recommended: 'Use for unmanaged or untrusted devices, SharePoint/OneDrive browser access, and Exchange Online browser-only access.'
    }
  };

  const ACCESS_DURATION_HELP = {
    ongoing: {
      title: 'Ongoing',
      meaning: 'The access need is stable and expected to continue.',
      recommended: 'Use only when there is a named owner, documented business reason, membership review cadence, and no planned end date.'
    },
    temporary: {
      title: 'Temporary / time-boxed',
      meaning: 'The safest default for most scenario access because group membership should expire or be reviewed.',
      recommended: 'Use for collaboration, temporary elevated access, sensitive access windows, and any exception from normal device or location rules.'
    },
    emergency: {
      title: 'Emergency only',
      meaning: 'For validation of emergency access paths, not ordinary day-to-day access.',
      recommended: 'Keep disabled or report-only. Never enforce controls that could block emergency or break-glass sign-in.'
    }
  };

  const VISUAL_SCENARIO_NODES = [
    { id: 'identity', lane: 'if', step: 1, title: 'Identity', question: 'Who needs access?', fields: ['accountType', 'groupName'] },
    { id: 'resource', lane: 'if', step: 2, title: 'Target resource', question: 'What do they need to reach?', fields: ['resource'] },
    { id: 'device', lane: 'if', step: 3, title: 'Device and platform', question: 'What device context is acceptable?', fields: ['deviceTrust', 'platforms'] },
    { id: 'context', lane: 'if', step: 4, title: 'Context and risk', question: 'When should this access path apply?', fields: ['location', 'riskTolerance', 'sensitivity', 'duration'] },
    { id: 'grant', lane: 'then', step: 5, title: 'Access decision', question: 'What must happen before access is granted?', fields: ['accessDecision', 'authRequirement', 'riskResponse'] },
    { id: 'session', lane: 'then', step: 6, title: 'Session controls', question: 'How tightly should the session be controlled?', fields: ['session'] },
    { id: 'rollout', lane: 'then', step: 7, title: 'Rollout', question: 'How should the policy be introduced?', fields: ['rollout'] }
  ];

  const VISUAL_FIELD_OPTIONS = {
    accountType: {
      label: 'Identity type',
      options: [
        ['internalUser', 'Internal identity', 'A member account managed by this tenant.'],
        ['externalGuest', 'External identity', 'A B2B guest or partner account accessing tenant resources.'],
        ['admin', 'Privileged identity', 'An identity with elevated directory or service permissions.'],
        ['serviceAccount', 'Automation identity', 'A non-human account that should have a narrow access boundary.'],
        ['agentIdentity', 'Agent identity', 'A Copilot or agent identity using preview Conditional Access capabilities.']
      ]
    },
    resource: {
      label: 'Target resource',
      options: [
        ['sharepoint', 'SharePoint or OneDrive', 'Collaboration content; folder boundaries remain a SharePoint permission decision.'],
        ['exchange', 'Exchange Online', 'Mailbox and browser-based Microsoft 365 mail access.'],
        ['office365', 'Microsoft 365 core apps', 'The Office 365 resource set rather than every cloud application.'],
        ['adminPortals', 'Admin portals', 'Microsoft administrative interfaces and privileged operations.'],
        ['allApps', 'All cloud apps', 'Broadest resource coverage; review exclusions carefully.'],
        ['agentResources', 'Agent resources', 'Preview/beta agent resource targeting.']
      ]
    },
    deviceTrust: {
      label: 'Device trust',
      options: [
        ['managed', 'Managed and compliant', 'Require a device that reports compliant through the tenant device-management model.'],
        ['browserOnly', 'Browser-only limited access', 'Prefer a limited browser experience for unmanaged devices.'],
        ['unmanaged', 'Unmanaged device allowed', 'Allow an untrusted device with compensating authentication and session controls.'],
        ['trustedLocation', 'Trusted network boundary', 'Use a named location as an explicit access boundary.']
      ]
    },
    platforms: {
      label: 'Allowed platforms',
      options: [
        ['any', 'Any known platform', 'Do not limit the policy to one operating-system family.'],
        ['windows', 'Windows only', 'Apply this access path only to Windows.'],
        ['mobile', 'iOS and Android', 'Apply this access path to supported mobile platforms.'],
        ['unknownBlocked', 'Unknown platforms blocked', 'Create a strict platform boundary for unrecognised devices.']
      ]
    },
    location: {
      label: 'Network location',
      options: [
        ['any', 'Any network', 'Do not rely on source network as a trust signal.'],
        ['trustedOnly', 'Trusted locations only', 'Limit access to a maintained named-location boundary.'],
        ['excludeTrusted', 'Apply outside trusted locations', 'Use stronger controls whenever the sign-in is outside trusted locations.']
      ]
    },
    riskTolerance: {
      label: 'Risk tolerance',
      options: [
        ['low', 'Lower friction', 'Use fewer adaptive risk controls for this access path.'],
        ['balanced', 'Balanced', 'Add safeguards without making every risk signal a block.'],
        ['strict', 'Strict', 'Use separate risk guardrails where licensing and signals support them.']
      ]
    },
    sensitivity: {
      label: 'Data sensitivity',
      options: [
        ['standard', 'Standard business data', 'Normal organizational information.'],
        ['sensitive', 'Sensitive business data', 'Information requiring tighter authentication and session handling.'],
        ['highlySensitive', 'Highly sensitive or regulated', 'High-impact data requiring the strongest practical controls.']
      ]
    },
    duration: {
      label: 'Access duration',
      options: [
        ['ongoing', 'Ongoing', ACCESS_DURATION_HELP.ongoing.meaning],
        ['temporary', 'Temporary or time-boxed', ACCESS_DURATION_HELP.temporary.meaning],
        ['emergency', 'Emergency only', ACCESS_DURATION_HELP.emergency.meaning]
      ]
    },
    accessDecision: {
      label: 'Access result',
      options: [
        ['grant', 'Grant with controls', 'Allow access only after the selected authentication and device controls are satisfied.'],
        ['block', 'Block access', 'Prevent this identity and context from accessing the selected resource.']
      ]
    },
    authRequirement: {
      label: 'Authentication requirement',
      options: [
        ['standardMfa', 'Standard MFA', 'Require multifactor authentication without restricting the accepted method quality.'],
        ['passwordlessMfa', 'Passwordless MFA', 'Require a passwordless authentication strength.'],
        ['phishingResistantMfa', 'Phishing-resistant MFA', 'Require the strongest built-in authentication strength for high-value access.']
      ]
    },
    riskResponse: {
      label: 'Identity risk response',
      options: [
        ['none', 'No risk policy', 'Do not add an Identity Protection risk branch.'],
        ['signInRisk', 'Block high sign-in risk', 'Create a separate high sign-in-risk block policy.'],
        ['signInAndUserRisk', 'Block high sign-in and user risk', 'Create two separate risk policies so each signal remains independently supportable.']
      ]
    },
    session: {
      label: 'Session strictness',
      options: [
        ['standard', 'Standard session', SESSION_STRICTNESS_HELP.standard.meaning],
        ['short', 'Short session', SESSION_STRICTNESS_HELP.short.meaning],
        ['browserLocked', 'Browser locked down', SESSION_STRICTNESS_HELP.browserLocked.meaning]
      ]
    },
    rollout: {
      label: 'Initial rollout',
      options: [
        ['reportOnly', 'Report-only first', 'Evaluate policy impact in sign-in logs before enforcement.'],
        ['disabled', 'Leave disabled', 'Create the policy without evaluating or enforcing it.'],
        ['enabled', 'Enable immediately', 'Enforce immediately; use only after equivalent pilot and What If validation.']
      ]
    }
  };

  const state = {
    selectedIdentity: 'all_users',
    selectedTarget: 'all_resources',
    selectedThreats: new Set(),
    strategy: { ...STRATEGY_DEFAULTS },
    scenario: { ...SCENARIO_DEFAULTS },
    scenarioVisual: {
      activeNode: 'identity',
      completed: new Set(),
      history: [],
      flyout: null,
      threatOpen: false
    },
    appliedStrategy: null,
    guideOnly: null,
    consolidatedPolicies: [],
    activeTab: 'start',
    workflowStage: { strategy: 'requirements', scenario: 'template' },
    detailView: 'overview',
    reviewedPolicies: new Set(),
    expertMode: savedExpertMode(),
    selectedPersona: 'All',
    selectedId: null,
    search: '',
    policyView: 'recommended',
    decisions: {},
    touchedDecisions: new Set(),
    overrides: {},
    imported: [],
    objectCatalog: new Map(),
    compare: new Map(),
    extra: [],
    compareReport: null,
    importFilter: 'all',
    auditTarget: 'baseline'
  };

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clone = obj => JSON.parse(JSON.stringify(obj));
  const policyKey = item => item.sourceFile;
  let visualFlyoutOpener = null;

  function init() {
    applyTheme(savedTheme());
    applyExpertMode(state.expertMode);
    allPolicies().forEach(item => {
      state.decisions[policyKey(item)] = 'exclude';
    });
    wireEvents();
    syncRecommendations();
    renderAll();
    toast(`ConditionalAccessBaseline ${BASELINE.version} loaded locally`);
  }

  function setActiveTab(tabId) {
    if (!WORKFLOW_TABS.has(tabId)) return;
    state.activeTab = tabId;
    if (tabId === 'policy-recommendations' && state.detailView === 'export') state.detailView = 'overview';
    renderTabs();
  }

  function wireEvents() {
    $('themeToggle').addEventListener('click', () => {
      const nextTheme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      applyTheme(nextTheme, true);
    });
    $('expertModeToggle').addEventListener('click', () => applyExpertMode(!state.expertMode, true));
    document.querySelectorAll('button[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
    });
    $('strategyBuilderPanel').addEventListener('click', e => {
      const btn = e.target.closest('button[data-strategy-stage]');
      if (btn) setStrategyStage(btn.dataset.strategyStage);
    });
    $('scenarioPlannerPanel').addEventListener('click', e => {
      const btn = e.target.closest('button[data-scenario-stage]');
      if (btn) setScenarioStage(btn.dataset.scenarioStage);
      const node = e.target.closest('button[data-visual-node]');
      if (node) openVisualScenarioNode(node.dataset.visualNode, node);
      const choice = e.target.closest('button[data-visual-choice]');
      if (choice) updateVisualScenarioChoice(choice.dataset.visualField, choice.dataset.visualChoice);
      const close = e.target.closest('button[data-visual-close]');
      if (close) closeVisualFlyout(close.dataset.visualClose);
      const policy = e.target.closest('button[data-scenario-open]');
      if (policy) openScenarioBuildGuide(policy.dataset.scenarioOpen);
    });
    $('scenarioPlannerPanel').addEventListener('input', e => {
      if (e.target.id !== 'visualScenarioGroupName') return;
      updateVisualScenarioChoice('groupName', e.target.value, true);
    });
    $('scenarioPlannerPanel').addEventListener('change', e => {
      if (e.target.id !== 'visualScenarioGroupName') return;
      renderScenarioPlanner();
    });
    $('strategyContinueBtn').addEventListener('click', () => setStrategyStage('architecture'));
    $('strategyReviewBtn').addEventListener('click', () => applyBestPracticeStrategy());
    $('loadRecommendedBtn').addEventListener('click', loadRecommendedStrategy);
    $('resetBtn').addEventListener('click', clearStrategy);
    $('clearThreatsBtn').addEventListener('click', () => {
      state.selectedThreats = new Set();
      state.activeTab = 'strategy-builder';
      state.appliedStrategy = null;
      state.guideOnly = null;
      state.touchedDecisions.clear();
      syncRecommendations();
      selectFirstVisible();
      renderAll();
      toast('Threat selections cleared');
    });
    $('useSuggestedThreatsBtn').addEventListener('click', useSuggestedThreats);
    $('reviewPoliciesBtn').addEventListener('click', () => setActiveTab('policy-recommendations'));
    $('strategyProtection').addEventListener('change', e => {
      state.strategy.protection = e.target.value;
      state.appliedStrategy = null;
      state.guideOnly = null;
      renderStrategyBuilder();
    });
    $('strategyRollout').addEventListener('change', e => {
      state.strategy.rollout = e.target.value;
      state.appliedStrategy = null;
      state.guideOnly = null;
      renderStrategyBuilder();
    });
    document.querySelectorAll('[data-strategy-toggle]').forEach(input => {
      input.addEventListener('change', () => {
        state.strategy[input.dataset.strategyToggle] = input.checked;
        state.appliedStrategy = null;
        state.guideOnly = null;
        renderStrategyBuilder();
      });
    });
    $('scenarioTemplates').addEventListener('click', e => {
      const btn = e.target.closest('button[data-scenario-template]');
      if (!btn) return;
      selectScenarioTemplate(btn.dataset.scenarioTemplate);
    });
    ['scenarioGroupName', 'scenarioGroupId', 'scenarioLocationId'].forEach(id => {
      $(id).addEventListener('input', e => {
        const key = id.replace(/^scenario/, '');
        const stateKey = key.charAt(0).toLowerCase() + key.slice(1);
        state.scenario[stateKey] = e.target.value.trim();
        state.appliedStrategy = null;
        state.guideOnly = null;
        renderScenarioPlanner();
      });
    });
    ['scenarioAccountType', 'scenarioResource', 'scenarioDeviceTrust', 'scenarioPlatforms', 'scenarioLocation', 'scenarioRiskTolerance', 'scenarioAuthRequirement', 'scenarioSession', 'scenarioDuration', 'scenarioSensitivity'].forEach(id => {
      $(id).addEventListener('change', e => {
        const key = id.replace(/^scenario/, '');
        const stateKey = key.charAt(0).toLowerCase() + key.slice(1);
        state.scenario[stateKey] = e.target.value;
        state.appliedStrategy = null;
        state.guideOnly = null;
        renderScenarioPlanner();
      });
    });
    $('applyScenarioBtn').addEventListener('click', () => applyScenarioPlan());
    $('scenarioSettingsBtn').addEventListener('click', () => setScenarioStage('settings'));
    $('scenarioTemplateBackBtn').addEventListener('click', () => setScenarioStage('template'));
    $('scenarioPlanBtn').addEventListener('click', () => setScenarioStage('plan'));
    $('scenarioSettingsBackBtn').addEventListener('click', () => setScenarioStage('settings'));
    $('scenarioPrepareBtn').addEventListener('click', () => setScenarioStage('prepare'));
    $('scenarioPlanBackBtn').addEventListener('click', () => setScenarioStage('plan'));
    $('downloadScenarioBtn').addEventListener('click', downloadScenarioSummary);
    $('visualBackBtn').addEventListener('click', () => moveVisualScenarioNode(-1));
    $('visualContinueBtn').addEventListener('click', () => moveVisualScenarioNode(1, true));
    $('visualUndoBtn').addEventListener('click', undoVisualScenarioChange);
    $('visualResetBtn').addEventListener('click', resetVisualScenarioRecommendations);
    $('visualAcceptBtn').addEventListener('click', acceptVisualScenarioDecision);
    $('visualThreatImpactBtn').addEventListener('click', openVisualThreatFlyout);
    $('visualFlyoutBackdrop').addEventListener('click', () => closeVisualFlyout('control'));
    document.addEventListener('keydown', handleVisualFlyoutKeydown);
    $('strategySummary').addEventListener('click', e => {
      const btn = e.target.closest('button[data-strategy-open]');
      if (!btn) return;
      applyBestPracticeStrategy(btn.dataset.strategyOpen);
    });
    $('applyStrategyBtn').addEventListener('click', applyBestPracticeStrategy);
    $('downloadStrategyBtn').addEventListener('click', downloadStrategySummary);
    $('auditTarget').addEventListener('change', e => {
      state.auditTarget = e.target.value === 'rebuild' ? 'rebuild' : 'baseline';
      if (state.imported.length) compareImported();
      renderImport();
      renderPolicyPlanSummary();
    });
    $('policyDetailTabs').addEventListener('click', e => {
      const btn = e.target.closest('button[data-detail-view]');
      if (!btn) return;
      setPolicyDetailView(btn.dataset.detailView);
    });
    $('policyDetailTabs').addEventListener('keydown', e => {
      if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
      const buttons = [...$('policyDetailTabs').querySelectorAll('button[data-detail-view]')].filter(btn => !btn.hidden && getComputedStyle(btn).display !== 'none');
      const index = buttons.indexOf(e.target);
      if (index < 0) return;
      e.preventDefault();
      const next = e.key === 'ArrowRight' ? Math.min(buttons.length - 1, index + 1) : Math.max(0, index - 1);
      setPolicyDetailView(buttons[next].dataset.detailView);
      buttons[next].focus();
    });
    document.querySelectorAll('button[data-review-stage]').forEach(btn => {
      btn.addEventListener('click', () => setPolicyDetailView(btn.dataset.reviewStage === 'export' ? 'export' : 'overview'));
    });
    $('previousPolicyBtn').addEventListener('click', () => moveSelectedPolicy(-1));
    $('nextPolicyBtn').addEventListener('click', () => moveSelectedPolicy(1));
    $('markReviewedBtn').addEventListener('click', toggleSelectedPolicyReviewed);
    $('reviewExportBtn').addEventListener('click', () => setPolicyDetailView(state.detailView === 'export' ? 'overview' : 'export'));
    $('searchInput').addEventListener('input', e => {
      state.search = e.target.value.trim().toLowerCase();
      state.activeTab = 'policy-recommendations';
      renderPolicyPlanSummary();
      renderPolicyList();
      renderTabs();
    });
    $('policyViewControl').addEventListener('click', e => {
      const btn = e.target.closest('button[data-view]');
      if (!btn) return;
      state.policyView = btn.dataset.view;
      state.activeTab = 'policy-recommendations';
      renderPolicyPlanSummary();
      renderPolicyList();
      renderSegmented('policyViewControl', state.policyView, 'view');
      renderTabs();
    });
    $('decisionControl').addEventListener('click', e => {
      const btn = e.target.closest('button[data-decision]');
      if (!btn) return;
      const policy = selectedPolicy();
      if (!policy) return;
      state.decisions[policyKey(policy)] = btn.dataset.decision;
      state.activeTab = 'policy-recommendations';
      state.touchedDecisions.add(policyKey(policy));
      renderAll();
    });
    $('overrideGrid').addEventListener('input', e => {
      const field = e.target.closest('[data-override]');
      const policy = selectedPolicy();
      if (!field || !policy) return;
      state.activeTab = 'policy-recommendations';
      const override = ensureOverride(policyKey(policy));
      override[field.dataset.override] = field.value;
      renderSelected();
      renderMetrics();
      renderWarnings();
      renderTabs();
    });
    $('clearOverridesBtn').addEventListener('click', () => {
      const policy = selectedPolicy();
      if (!policy) return;
      state.activeTab = 'policy-recommendations';
      delete state.overrides[policyKey(policy)];
      renderSelected();
      renderWarnings();
      renderTabs();
      toast('Structured edits cleared for selected policy');
    });
    $('copyJsonBtn').addEventListener('click', copySelectedJson);
    $('copyPolicyNameBtn').addEventListener('click', copySelectedPolicyName);
    $('copyManualGuideBtn').addEventListener('click', copySelectedManualGuide);
    $('downloadPolicyBtn').addEventListener('click', () => {
      const policy = selectedPolicy();
      if (!policy) return;
      state.activeTab = 'policy-recommendations';
      if (isGuideOnlyPolicy(policy)) {
        toast('Add required scenario object IDs before downloading policy JSON');
        renderSelected();
        renderTabs();
        return;
      }
      downloadJson(exportPolicy(policy, 'configured'), `${safeFilename(policy.displayName)}.json`);
      renderTabs();
      toast('Policy JSON downloaded');
    });
    $('exportReportBtn').addEventListener('click', () => exportSet('report'));
    $('exportDisabledBtn').addEventListener('click', () => exportSet('disabled'));
    $('exportConfiguredBtn').addEventListener('click', () => exportSet('configured'));
    $('analyseBtn').addEventListener('click', () => analyseImportText());
    $('clearImportBtn').addEventListener('click', clearImport);
    $('importFilterControl').addEventListener('click', e => {
      const btn = e.target.closest('button[data-import-filter]');
      if (!btn || !IMPORT_FILTERS.has(btn.dataset.importFilter)) return;
      state.importFilter = btn.dataset.importFilter;
      renderImport();
    });

    const dropzone = $('dropzone');
    dropzone.addEventListener('click', () => $('fileInput').click());
    $('fileInput').addEventListener('change', e => handleFile(e.target.files[0]));
    ['dragenter', 'dragover'].forEach(ev => {
      dropzone.addEventListener(ev, e => {
        e.preventDefault();
        dropzone.classList.add('drag');
      });
    });
    ['dragleave', 'drop'].forEach(ev => {
      dropzone.addEventListener(ev, e => {
        e.preventDefault();
        dropzone.classList.remove('drag');
      });
    });
    dropzone.addEventListener('drop', e => handleFile(e.dataTransfer.files[0]));
  }

  function savedTheme() {
    try {
      const theme = localStorage.getItem(THEME_STORAGE_KEY);
      return theme === 'light' ? 'light' : 'dark';
    } catch (_) {
      return 'dark';
    }
  }

  function applyTheme(theme, persist = false) {
    const activeTheme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = activeTheme;
    const toggle = $('themeToggle');
    if (toggle) {
      const isLight = activeTheme === 'light';
      toggle.textContent = isLight ? 'Dark mode' : 'Light mode';
      toggle.setAttribute('aria-pressed', String(isLight));
      toggle.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
    }
    if (persist) {
      try {
        localStorage.setItem(THEME_STORAGE_KEY, activeTheme);
      } catch (_) {
        // Theme persistence is optional; the current session still updates.
      }
    }
  }

  function savedExpertMode() {
    try {
      return localStorage.getItem(EXPERT_STORAGE_KEY) === 'true';
    } catch (_) {
      return false;
    }
  }

  function applyExpertMode(enabled, persist = false) {
    state.expertMode = Boolean(enabled);
    document.documentElement.dataset.expert = state.expertMode ? 'on' : 'off';
    const toggle = $('expertModeToggle');
    if (toggle) {
      toggle.textContent = `Expert detail: ${state.expertMode ? 'on' : 'off'}`;
      toggle.setAttribute('aria-pressed', String(state.expertMode));
      toggle.setAttribute('aria-label', state.expertMode ? 'Hide expert detail' : 'Show expert detail');
    }
    if (!state.expertMode && ['adjust', 'json'].includes(state.detailView)) state.detailView = 'overview';
    if (persist) {
      try {
        localStorage.setItem(EXPERT_STORAGE_KEY, String(state.expertMode));
      } catch (_) {
        // Expert preference persistence is optional.
      }
    }
    if (document.readyState !== 'loading') renderAll();
  }

  function setStrategyStage(stage) {
    if (!['requirements', 'architecture'].includes(stage)) return;
    const plan = strategyPlan();
    if (stage === 'architecture' && plan.empty) {
      toast('Select at least one requirement before reviewing the architecture');
      return;
    }
    state.workflowStage.strategy = stage;
    state.activeTab = 'strategy-builder';
    renderStrategyBuilder();
    renderTabs();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setScenarioStage(stage) {
    if (!['template', 'settings', 'plan', 'prepare'].includes(stage)) return;
    state.workflowStage.scenario = stage;
    state.activeTab = 'scenario-planner';
    renderScenarioPlanner();
    renderTabs();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setPolicyDetailView(view) {
    const allowed = ['overview', 'build', 'adjust', 'json', 'export'];
    if (!allowed.includes(view)) return;
    if (!state.expertMode && ['adjust', 'json'].includes(view)) view = 'overview';
    state.detailView = view;
    state.activeTab = 'policy-recommendations';
    renderPolicyDetailView();
    renderTabs();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function reviewPolicyList() {
    const list = recommendedPolicies().length ? recommendedPolicies() : selectedPolicies();
    return groupedPolicies(list).flatMap(group => group.policies);
  }

  function moveSelectedPolicy(direction) {
    const list = reviewPolicyList();
    const index = list.findIndex(policy => policyKey(policy) === state.selectedId);
    if (!list.length || index < 0) return;
    const nextIndex = Math.max(0, Math.min(list.length - 1, index + direction));
    if (nextIndex === index) return;
    state.selectedId = policyKey(list[nextIndex]);
    state.detailView = 'overview';
    renderPolicyPlanSummary();
    renderPolicyList();
    renderSelected();
    renderPolicyReviewFooter();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function toggleSelectedPolicyReviewed() {
    const policy = selectedPolicy();
    if (!policy) return;
    const key = policyKey(policy);
    if (state.reviewedPolicies.has(key)) state.reviewedPolicies.delete(key);
    else state.reviewedPolicies.add(key);
    renderPolicyPlanSummary();
    renderPolicyList();
    renderPolicyReviewFooter();
  }

  function allPolicies() {
    return [
      ...BASELINE.policies,
      ...GENERATED_POLICIES,
      ...(state.appliedStrategy ? state.consolidatedPolicies : [])
    ];
  }

  function baselinePolicies() {
    return BASELINE.policies;
  }

  function selectedIdentity() {
    return IDENTITY_TYPES.find(item => item.id === state.selectedIdentity) || IDENTITY_TYPES[0];
  }

  function selectedTarget() {
    return TARGETS.find(item => item.id === state.selectedTarget) || TARGETS[0];
  }

  function strategyPlan() {
    const requirements = state.strategy;
    const level = STRATEGY_LEVELS[requirements.protection] || STRATEGY_LEVELS.maximum;
    const selectedRequirements = selectedStrategyRequirementKeys(requirements);
    const controlReasons = new Map();
    const threatReasons = new Map();
    const addControl = (controlId, reason) => {
      if (!CONTROLS[controlId]) return;
      if (!controlReasons.has(controlId)) controlReasons.set(controlId, []);
      if (!controlReasons.get(controlId).includes(reason)) controlReasons.get(controlId).push(reason);
    };
    const addThreat = (threatId, reason) => {
      if (!threatReasons.has(threatId)) threatReasons.set(threatId, []);
      if (!threatReasons.get(threatId).includes(reason)) threatReasons.get(threatId).push(reason);
    };

    selectedRequirements.forEach(key => {
      const requirement = STRATEGY_REQUIREMENTS[key];
      strategyControlsForRequirement(requirement, requirements.protection).forEach(controlId => addControl(controlId, requirement.label));
      requirement.threats.forEach(threatId => addThreat(threatId, requirement.label));
    });

    if (requirements.legacyExceptions && controlReasons.has('legacy_auth')) {
      addControl('legacy_auth', 'Legacy exceptions require a reviewed block policy with explicit exclusions');
      addThreat('T1110', 'Legacy-auth exception risk');
      addThreat('T1133', 'Legacy-auth exception risk');
    }

    const controls = [...controlReasons.keys()];
    const equivalentPolicies = policiesForControlSet(controls);
    const equivalentPolicyKeys = new Set(equivalentPolicies.map(policyKey));
    const consolidatedPolicies = consolidatedPoliciesForStrategy(requirements, controls, controlReasons);
    const policyKeys = new Set(consolidatedPolicies.map(policyKey));
    const optional = optionalStrategyItems(requirements, controls, equivalentPolicyKeys);
    const safety = strategySafetyItems(requirements, controls, consolidatedPolicies);
    const mitre = mitreCoverageForControls(controls);
    const score = strategyMitreScore(mitre, controls);
    const friction = strategyFrictionScore(requirements, controls, consolidatedPolicies);
    const rolloutRisk = strategyRolloutRisk(requirements, consolidatedPolicies);

    return {
      requirements: { ...requirements },
      level,
      selectedRequirements,
      empty: !selectedRequirements.length,
      controls,
      controlReasons,
      threats: [...threatReasons.keys()],
      threatReasons,
      policies: consolidatedPolicies,
      consolidatedPolicies,
      equivalentPolicies,
      equivalentPolicyKeys,
      policyKeys,
      optional,
      safety,
      mitre,
      score,
      friction,
      rolloutRisk
    };
  }

  function selectedStrategyRequirementKeys(requirements = state.strategy) {
    return Object.keys(STRATEGY_REQUIREMENTS)
      .filter(key => key !== 'legacyExceptions' && Boolean(requirements[key]));
  }

  function strategyControlsForRequirement(requirement, protection) {
    return requirement.controlsByLevel?.[protection] || requirement.controls || [];
  }

  function consolidatedPoliciesForStrategy(requirements, controls, controlReasons) {
    const policies = [];
    const has = controlId => controls.includes(controlId);
    const add = policy => {
      if (!policy) return;
      if (policies.some(item => policyKey(item) === policyKey(policy))) return;
      policies.push(policy);
    };

    if (requirements.admins && (has('admin_mfa') || has('phish_mfa') || has('admin_session'))) {
      add(consolidatedAdminCorePolicy(controls, controlReasons));
    }

    if (has('legacy_auth')) add(consolidatedClonePolicy('CA001C', 'Tenant-BlockLegacyAuthentication', 'CA002', ['legacy_auth'], 'Legacy authentication must stay as its own block policy.'));
    if (has('auth_flows')) add(consolidatedClonePolicy('CA002C', 'Tenant-BlockRiskyAuthenticationFlows', 'CA004', ['auth_flows'], 'Risky authentication flows stay separate so block logic remains explicit.'));
    if (has('sign_in_risk')) add(consolidatedClonePolicy('CA011C', 'Tenant-BlockHighRiskSignIns', 'CA210', ['sign_in_risk'], 'Sign-in risk remains separate from user risk per Microsoft guidance.'));
    if (has('user_risk')) add(consolidatedClonePolicy('CA012C', 'Tenant-BlockHighRiskUsers', 'CA201', ['user_risk'], 'User risk remains separate from sign-in risk per Microsoft guidance.'));

    if (requirements.internals) {
      add(consolidatedWorkforceCorePolicy(requirements, controls, controlReasons));
    }
    if (requirements.managedDevices && (has('device_compliance') || has('unknown_platforms'))) {
      add(consolidatedClonePolicy('CA201C', 'Workforce-ManagedDeviceCompliance', 'CA205', ['device_compliance', 'unknown_platforms'], 'Device compliance remains a clear device posture policy.'));
    }
    if (requirements.managedDevices && has('app_protection')) {
      add(consolidatedClonePolicy('CA202C', 'Workforce-AppProtection-Office365', 'CA005', ['app_protection'], 'App protection controls stay separate because their app and client targeting differs from core MFA/session controls.'));
    }

    if (requirements.guests || has('guest_access')) add(consolidatedGuestCorePolicy(controlReasons));
    if (requirements.serviceAccounts || has('service_account_protection')) add(consolidatedServiceAccountPolicy(controlReasons));
    if (requirements.trustedLocations && has('trusted_location')) add(consolidatedClonePolicy('CA301C', 'TrustedLocation-BlockUntrustedAccess', 'CA301', ['trusted_location'], 'Location block controls stay separate from grant controls.'));

    if (requirements.agents) {
      add(consolidatedClonePolicy('CA501C', 'Agents-BlockHighRiskAgentIdentities', 'CA501', ['agent_risk'], 'Agent preview/beta fields stay isolated from standard user policies.'));
      add(consolidatedClonePolicy('CA502C', 'Agents-BlockUnapprovedAgentIdentities', 'CA502', ['agent_identity_block'], 'Agent identity block remains a dedicated preview/beta policy.'));
      add(consolidatedClonePolicy('CA503C', 'Agents-RequireCompliantDevice', 'CA503', ['agent_compliant_device'], 'Agent user device posture remains a dedicated preview/beta policy.'));
      add(consolidatedClonePolicy('CA504C', 'Agents-BlockRiskyAgentUsers', 'CA504', ['agent_user_risk'], 'Agent user risk remains separate from standard user risk policies.'));
      add(consolidatedClonePolicy('CA505C', 'Agents-RequireCompliantNetwork', 'CA505', ['agent_compliant_network'], 'Agent network targeting remains a dedicated preview/beta policy.'));
      add(consolidatedClonePolicy('CA506C', 'Agents-BlockAllAgentUsers', 'CA506', ['agent_users_block'], 'Generated agent user block remains separate until inventory is complete.'));
      add(consolidatedClonePolicy('CA507C', 'Users-BlockAllAgentResources', 'CA507', ['users_agent_resources_block'], 'Agent resources use preview/beta targeting and stay isolated.'));
    }

    return sortPolicies(policies);
  }

  function consolidatedAdminCorePolicy(controls) {
    const representedIds = ['CA100', 'CA101'];
    if (controls.includes('admin_session') || controls.includes('session_controls')) representedIds.push('CA102');
    if (controls.includes('persistent_browser')) representedIds.push('CA103');
    if (controls.includes('phish_mfa')) representedIds.push('CA105');
    const represented = policiesByIds(representedIds);
    const roles = uniqueValues(represented.flatMap(policy => policy.policy.conditions?.users?.includeRoles || []));
    const usePhishingResistant = controls.includes('phish_mfa');
    const grantControls = usePhishingResistant
      ? { operator: 'OR', authenticationStrength: clone(policiesById('CA105')[0].policy.grantControls.authenticationStrength) }
      : clone(policiesById('CA101')[0].policy.grantControls);
    const sessionControls = {};
    if (controls.includes('admin_session') || controls.includes('session_controls')) {
      sessionControls.signInFrequency = clone(policiesById('CA102')[0].policy.sessionControls.signInFrequency);
    }
    if (controls.includes('persistent_browser')) {
      sessionControls.persistentBrowser = clone(policiesById('CA103')[0].policy.sessionControls.persistentBrowser);
    }
    const strengthLabel = usePhishingResistant ? 'PhishingResistantMFA' : 'MFA';
    const policy = {
      id: 'CA100C',
      persona: 'Admins',
      displayName: `CA100C-PrivilegedAdmins-Core-${strengthLabel}-SessionControls`,
      sourceFile: `Strategy/ConditionalAccess/CA100C-PrivilegedAdmins-Core-${strengthLabel}-SessionControls.json`,
      state: 'enabledForReportingButNotEnforced',
      risk: 'high',
      summary: usePhishingResistant
        ? 'Consolidated privileged administrator policy requiring phishing-resistant MFA with short admin sessions.'
        : 'Consolidated privileged administrator policy requiring MFA with admin session controls.',
      prerequisites: [
        ...GLOBAL_PREREQUISITES,
        'Privileged role inventory reviewed',
        'Break-glass accounts tested outside privileged role scope'
      ],
      requiredObjects: ['CA-BreakGlassAccounts-Exclude'],
      rolloutDefault: 'monitor',
      kind: 'consolidated',
      generated: true,
      consolidated: true,
      controls: ['admin_mfa', 'phish_mfa', 'admin_session', 'session_controls', 'persistent_browser'].filter(controlId => controls.includes(controlId)),
      represents: represented.map(policy => policy.id),
      mergeReason: 'Safe to merge because all represented admin policies target privileged roles and grant/session controls can coexist in one Conditional Access policy.',
      separateReason: 'Block, risk, agent, and CAE strict-location controls stay separate because they change evaluation semantics or rely on preview fields.',
      policy: {
        displayName: `CA100C-PrivilegedAdmins-Core-${strengthLabel}-SessionControls`,
        state: 'enabledForReportingButNotEnforced',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeRoles: roles,
            excludeGroups: ['2802b872-ccfb-4b29-a9a9-459808dfb11b']
          },
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls
      }
    };
    if (hasAny(Object.keys(sessionControls))) {
      policy.policy.sessionControls = sessionControls;
    }
    return policy;
  }

  function consolidatedWorkforceCorePolicy(requirements, controls) {
    const representedIds = ['CA000', 'CA200', 'CA202', 'CA206'];
    const signInFrequency = clone(policiesById('CA202')[0].policy.sessionControls.signInFrequency);
    const persistentBrowser = clone(policiesById('CA206')[0].policy.sessionControls.persistentBrowser);
    return {
      id: 'CA200C',
      persona: 'Internals',
      displayName: 'CA200C-Workforce-Core-MFA-SessionControls',
      sourceFile: 'Strategy/ConditionalAccess/CA200C-Workforce-Core-MFA-SessionControls.json',
      state: 'enabled',
      risk: 'medium',
      summary: 'Consolidated workforce policy for MFA and session lifetime controls.',
      prerequisites: GLOBAL_PREREQUISITES,
      requiredObjects: ['CA-BreakGlassAccounts-Exclude'],
      rolloutDefault: 'include',
      kind: 'consolidated',
      generated: true,
      consolidated: true,
      controls: ['mfa', 'session_controls', 'persistent_browser'].filter(controlId => controls.includes(controlId)),
      represents: representedIds,
      mergeReason: 'Safe to merge because workforce MFA and session controls share broad user and all-app scope.',
      separateReason: 'Device compliance, app protection, and block controls stay separate because their conditions and grant semantics differ.',
      policy: {
        displayName: 'CA200C-Workforce-Core-MFA-SessionControls',
        state: 'enabled',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeUsers: ['All'],
            excludeGroups: ['2802b872-ccfb-4b29-a9a9-459808dfb11b', '77c1ed37-10d0-4ef1-93dc-198e70abb166']
          },
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls: {
          operator: 'OR',
          builtInControls: ['mfa']
        },
        sessionControls: {
          signInFrequency,
          persistentBrowser
        }
      }
    };
  }

  function consolidatedGuestCorePolicy() {
    const represented = policiesByIds(['CA400', 'CA402', 'CA403']);
    return {
      id: 'CA400C',
      persona: 'Guests',
      displayName: 'CA400C-Guests-Core-MFA-SessionControls',
      sourceFile: 'Strategy/ConditionalAccess/CA400C-Guests-Core-MFA-SessionControls.json',
      state: 'enabled',
      risk: 'medium',
      summary: 'Consolidated guest and partner access policy requiring MFA and shorter sessions.',
      prerequisites: [...GLOBAL_PREREQUISITES, 'Guest and partner access model reviewed'],
      requiredObjects: ['CA-BreakGlassAccounts-Exclude'],
      rolloutDefault: 'include',
      kind: 'consolidated',
      generated: true,
      consolidated: true,
      controls: ['guest_access', 'mfa', 'session_controls', 'persistent_browser'],
      represents: represented.map(policy => policy.id),
      mergeReason: 'Safe to merge because guest MFA and session controls share external identity scope and all-app targeting.',
      separateReason: 'Guest block policies remain separate because they use block controls and selected-app restrictions.',
      policy: {
        displayName: 'CA400C-Guests-Core-MFA-SessionControls',
        state: 'enabled',
        conditions: {
          clientAppTypes: ['all'],
          users: clone(policiesById('CA400')[0].policy.conditions.users),
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls: clone(policiesById('CA400')[0].policy.grantControls),
        sessionControls: {
          signInFrequency: clone(policiesById('CA402')[0].policy.sessionControls.signInFrequency),
          persistentBrowser: clone(policiesById('CA403')[0].policy.sessionControls.persistentBrowser)
        }
      }
    };
  }

  function consolidatedServiceAccountPolicy() {
    const base = clone(policiesById('CA300')[0]);
    base.id = 'CA300C';
    base.displayName = 'CA300C-ServiceAccounts-Core-MFA';
    base.sourceFile = 'Strategy/ConditionalAccess/CA300C-ServiceAccounts-Core-MFA.json';
    base.kind = 'consolidated';
    base.generated = true;
    base.consolidated = true;
    base.controls = ['service_account_protection', 'mfa'];
    base.represents = ['CA300'];
    base.mergeReason = 'Kept as a focused service account policy because non-human identities need separate ownership and exclusions.';
    base.separateReason = 'Trusted-location block controls remain separate from MFA grant controls.';
    base.policy = clone(base.policy);
    base.policy.displayName = base.displayName;
    return base;
  }

  function consolidatedClonePolicy(newId, name, sourceId, controls, mergeReason) {
    const source = policiesById(sourceId)[0];
    if (!source) return null;
    const item = clone(source);
    item.id = newId;
    item.displayName = `${newId}-${name}`;
    item.sourceFile = `Strategy/ConditionalAccess/${item.displayName}.json`;
    item.kind = 'consolidated';
    item.generated = true;
    item.consolidated = true;
    item.controls = controls;
    item.represents = [sourceId];
    item.mergeReason = mergeReason;
    item.separateReason = mergeReason;
    item.policy.displayName = item.displayName;
    return item;
  }

  function uniqueValues(values) {
    return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
  }

  function policiesForControlSet(controlIds) {
    const seen = new Set();
    const policies = [];
    controlIds.forEach(controlId => {
      const control = CONTROLS[controlId];
      if (!control) return;
      control.policyIds.forEach(policyId => {
        policiesById(policyId).forEach(policy => {
          const key = policyKey(policy);
          if (seen.has(key)) return;
          seen.add(key);
          policies.push(policy);
        });
      });
    });
    return sortPolicies(policies);
  }

  function optionalStrategyItems(requirements, controls, policyKeys) {
    const items = [];
    const add = (title, body, controlIds = []) => {
      items.push({ title, body, controlIds });
    };
    if (!requirements.managedDevices) add('Managed device posture', 'Add compliant-device and app-protection policies when Intune compliance is mature enough for enforcement.', ['device_compliance', 'app_protection']);
    if (!requirements.trustedLocations) add('Trusted-location restrictions', 'Add named-location policies when country/IP inventory can be maintained safely.', ['trusted_location']);
    if (!requirements.guests) add('Guest access guardrails', 'Enable guest-specific policies when B2B collaboration is in use.', ['guest_access']);
    if (!requirements.serviceAccounts) add('Service account controls', 'Separate non-human identities before applying broad user MFA policies.', ['service_account_protection']);
    if (!requirements.agents) add('Agent identity preview controls', 'Add agent identity and agent resource policies when Copilot or custom agents are in scope.', ['agent_risk', 'agent_identity_block']);
    if (requirements.legacyExceptions) add('Legacy-auth exception clean-up', 'Every legacy exception should have an owner, expiry date, and service account/location boundary.', ['legacy_auth']);
    if (!items.length) add('No major optional gaps', 'Maximum protection inputs are enabled. Remaining optional work is tenant tuning, pilot rings, and exception governance.', []);
    return items.map(item => ({
      ...item,
      policies: item.controlIds.flatMap(controlId => CONTROLS[controlId]?.policyIds || []).flatMap(policiesById).filter(policy => !policyKeys.has(policyKey(policy)))
    }));
  }

  function strategySafetyItems(requirements, controls, consolidatedPolicies) {
    const items = [];
    const has = controlId => controls.includes(controlId);
    const byIds = ids => consolidatedPolicies.filter(policy => ids.includes(policy.id));
    if (has('sign_in_risk') && has('user_risk')) {
      items.push({
        title: 'Sign-in risk and user risk stay separate',
        body: 'Microsoft guidance warns against combining these risk conditions in one Conditional Access policy.',
        policies: byIds(['CA011C', 'CA012C'])
      });
    }
    if (has('legacy_auth')) {
      items.push({
        title: 'Legacy authentication stays as a block policy',
        body: 'Block controls should not be merged with grant controls such as MFA, compliant device, or app protection.',
        policies: byIds(['CA001C'])
      });
    }
    if (requirements.agents) {
      items.push({
        title: 'Agent policies stay isolated',
        body: 'Agent identity and agent user targeting uses preview/beta-shaped fields and must not be merged into standard user policies.',
        policies: byIds(['CA501C', 'CA502C', 'CA503C', 'CA504C', 'CA505C', 'CA506C', 'CA507C'])
      });
    }
    if (has('session_controls') || has('persistent_browser') || has('admin_session')) {
      items.push({
        title: 'Session controls remain readable',
        body: 'Compatible session controls are folded into consolidated core policies; CAE strict-location remains separate until target-resource behaviour is explicit.',
        policies: byIds(['CA100C', 'CA200C', 'CA400C'])
      });
    }
    items.push({
      title: 'Emergency exclusions remain visible',
      body: 'Broad MFA or block policies must keep break-glass exclusions reviewable before enforcement.',
      policies: consolidatedPolicies.filter(policy => hasAny(policy.policy?.conditions?.users?.excludeGroups))
    });
    return items.filter(item => item.policies.length || item.title === 'Emergency exclusions remain visible');
  }

  function policiesByIds(ids) {
    return ids.flatMap(policiesById);
  }

  function mitreCoverageForControls(controlIds) {
    return MITRE_COVERAGE.map(item => {
      const strongHits = item.strongControls.filter(controlId => controlIds.includes(controlId));
      const partialHits = item.partialControls.filter(controlId => controlIds.includes(controlId));
      let status = 'Not addressed by Conditional Access';
      if (strongHits.length >= Math.min(2, item.strongControls.length)) status = 'Strongly mitigated';
      else if (strongHits.length || partialHits.length) status = 'Partially mitigated';
      else if (['T1528', 'T1539', 'T1556', 'T1484'].includes(item.id)) status = 'Requires another control';
      return {
        ...item,
        status,
        controls: [...strongHits, ...partialHits].map(controlId => CONTROLS[controlId]?.label).filter(Boolean)
      };
    });
  }

  function strategyMitreScore(mitre, controls) {
    if (!controls.length || !mitre.length) return 0;
    const strong = mitre.filter(item => item.status === 'Strongly mitigated').length;
    const partial = mitre.filter(item => item.status === 'Partially mitigated').length;
    return Math.round((strong + (partial * 0.55)) / mitre.length * 100);
  }

  function strategyFrictionScore(requirements, controls, policies) {
    if (!controls.length && !policies.length) return 0;
    const deviceWeight = requirements.managedDevices ? 18 : 0;
    const guestWeight = requirements.guests ? 8 : 0;
    const agentWeight = requirements.agents ? 10 : 0;
    const blockWeight = policies.filter(isBlockPolicy).length * 3;
    return Math.min(100, 18 + deviceWeight + guestWeight + agentWeight + blockWeight + Math.round(controls.length * 1.8));
  }

  function strategyRolloutRisk(requirements, policies) {
    if (!policies.length) return 'None';
    const critical = policies.filter(policy => policy.risk === 'critical').length;
    const blocks = policies.filter(isBlockPolicy).length;
    if (requirements.rollout === 'fast' && (critical || blocks > 2)) return 'High';
    if (requirements.rollout === 'cautious') return 'Low';
    return critical || blocks > 3 ? 'Medium-high' : 'Medium';
  }

  function selectedPolicy() {
    return allPolicies().find(item => policyKey(item) === state.selectedId) || recommendedPolicies()[0] || allPolicies()[0];
  }

  function suggestedThreatDetails() {
    const details = new Map();
    const add = (threatId, reason) => {
      if (!details.has(threatId)) details.set(threatId, []);
      details.get(threatId).push(reason);
    };
    selectedIdentity().threats?.forEach(threatId => add(threatId, `Suggested for ${selectedIdentity().label.toLowerCase()}`));
    selectedTarget().threats?.forEach(threatId => add(threatId, `Suggested for ${selectedTarget().label.toLowerCase()}`));
    return details;
  }

  function suggestedThreatIds() {
    return [...suggestedThreatDetails().keys()].filter(threatId => THREATS.some(threat => threat.id === threatId));
  }

  function useSuggestedThreats() {
    const suggestions = suggestedThreatIds();
    if (!suggestions.length) {
      toast('No suggested threats for this scope');
      return;
    }
    state.selectedThreats = new Set([...state.selectedThreats, ...suggestions]);
    state.appliedStrategy = null;
    state.activeTab = 'strategy-builder';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    syncRecommendations();
    selectFirstVisible();
    renderAll();
    toast(`${suggestions.length} suggested threats selected`);
  }

  function loadRecommendedStrategy() {
    state.selectedIdentity = 'all_users';
    state.selectedTarget = 'all_resources';
    state.selectedThreats = new Set(RECOMMENDED_STRATEGY_THREATS);
    state.strategy = {
      ...STRATEGY_DEFAULTS,
      admins: true,
      internals: true,
      managedDevices: true,
      guests: true,
      serviceAccounts: true,
      agents: true,
      trustedLocations: true
    };
    state.appliedStrategy = null;
    state.guideOnly = null;
    state.activeTab = 'strategy-builder';
    state.workflowStage.strategy = 'architecture';
    state.selectedPersona = 'All';
    state.policyView = 'recommended';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    state.overrides = {};
    allPolicies().forEach(item => {
      state.decisions[policyKey(item)] = 'exclude';
    });
    syncRecommendations();
    selectFirstVisible();
    renderAll();
    toast('Recommended V2 strategy restored');
  }

  function clearStrategy() {
    state.selectedThreats = new Set();
    state.strategy = { ...STRATEGY_DEFAULTS };
    state.appliedStrategy = null;
    state.guideOnly = null;
    state.activeTab = 'strategy-builder';
    state.workflowStage.strategy = 'requirements';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    state.overrides = {};
    allPolicies().forEach(item => {
      state.decisions[policyKey(item)] = 'exclude';
    });
    syncRecommendations();
    selectFirstVisible();
    renderAll();
    toast('Strategy cleared');
  }

  function syncRecommendations() {
    const recommended = recommendedPolicies();
    const recommendedKeys = new Set(recommended.map(policyKey));
    allPolicies().forEach(item => {
      const key = policyKey(item);
      if (state.touchedDecisions.has(key)) return;
      state.decisions[key] = recommendedKeys.has(key) ? item.rolloutDefault || 'monitor' : 'exclude';
    });
    const current = allPolicies().some(item => policyKey(item) === state.selectedId);
    if (!current || (state.policyView !== 'all' && !visiblePolicies().some(item => policyKey(item) === state.selectedId))) {
      const next = visiblePolicies()[0] || recommended[0] || allPolicies()[0];
      state.selectedId = policyKey(next);
    }
    if (state.imported.length) compareImported();
  }

  function selectFirstVisible() {
    const next = visiblePolicies()[0] || recommendedPolicies()[0] || allPolicies()[0];
    state.selectedId = policyKey(next);
  }

  function controlsForStrategy() {
    if (state.appliedStrategy?.controls?.length) {
      return state.appliedStrategy.controls.filter(id => CONTROLS[id]);
    }
    const controls = new Set();
    selectedIdentity().controls.forEach(id => controls.add(id));
    selectedTarget().controls.forEach(id => controls.add(id));
    state.selectedThreats.forEach(threatId => {
      const threat = THREATS.find(item => item.id === threatId);
      if (!threat) return;
      threat.controls.forEach(id => controls.add(id));
    });
    return [...controls].filter(id => CONTROLS[id]);
  }

  function recommendedPolicies() {
    if (state.appliedStrategy?.policyKeys?.length) {
      const keys = new Set(state.appliedStrategy.policyKeys);
      return sortPolicies(allPolicies().filter(policy => keys.has(policyKey(policy))));
    }
    const controls = controlsForStrategy();
    const seen = new Set();
    const list = [];
    controls.forEach(controlId => {
      CONTROLS[controlId].policyIds.forEach(policyId => {
        policiesById(policyId).forEach(policy => {
          const key = policyKey(policy);
          if (seen.has(key)) return;
          if (!policyAllowedForScope(policy)) return;
          seen.add(key);
          list.push(policy);
        });
      });
    });
    return sortPolicies(list);
  }

  function policiesById(id) {
    return allPolicies().filter(policy => policy.id === id);
  }

  function policyAllowedForScope(policy) {
    const identity = selectedIdentity();
    if (identity.personas.includes(policy.persona)) return true;
    if (policy.persona === 'Global' && identity.id !== 'agent_identities' && identity.id !== 'agent_users') return true;
    if (policy.generated && identity.id === 'copilot_agents') return true;
    return false;
  }

  function sortPolicies(list) {
    return [...list].sort((a, b) => {
      const aPriority = policyScopePriority(a);
      const bPriority = policyScopePriority(b);
      if (aPriority !== bPriority) return aPriority - bPriority;
      const aGenerated = a.generated ? 1 : 0;
      const bGenerated = b.generated ? 1 : 0;
      if (aGenerated !== bGenerated) return aGenerated - bGenerated;
      return a.displayName.localeCompare(b.displayName);
    });
  }

  function policyScopePriority(policy) {
    const agentFocused = state.selectedIdentity.includes('agent') || state.selectedIdentity === 'copilot_agents' || state.selectedTarget === 'agent_resources';
    if (agentFocused && policy.persona === 'Agents') return 0;
    if (agentFocused && isPreviewPolicy(policy)) return 1;
    if (agentFocused && policy.persona === 'Global') return 2;
    if (policy.persona === 'Global') return 0;
    return 1;
  }

  function visiblePolicies() {
    let list;
    if (state.policyView === 'selected') {
      list = selectedPolicies();
    } else if (state.policyView === 'all') {
      list = allPolicies();
    } else {
      list = recommendedPolicies();
    }
    return sortPolicies(list).filter(matchesPersonaAndSearch);
  }

  function selectedPolicies() {
    return allPolicies().filter(item => state.decisions[policyKey(item)] !== 'exclude');
  }

  function matchesPersonaAndSearch(policy) {
    const personaOk = state.selectedPersona === 'All' || policy.persona === state.selectedPersona;
    const controls = recommendationControlsForPolicy(policy).join(' ');
    const haystack = [
      policy.id,
      policy.persona,
      policy.displayName,
      policy.summary,
      policy.kind,
      policy.risk,
      controls
    ].join(' ').toLowerCase();
    return personaOk && (!state.search || haystack.includes(state.search));
  }

  function recommendationControlsForPolicy(policy) {
    if (policy.controls?.length) {
      return policy.controls.map(controlId => CONTROLS[controlId]?.label).filter(Boolean);
    }
    return controlsForStrategy()
      .filter(controlId => CONTROLS[controlId].policyIds.includes(policy.id))
      .map(controlId => CONTROLS[controlId].label);
  }

  function recommendationReasonForPolicy(policy) {
    if (policy.kind === 'scenario') {
      return `Recommended because: ${policy.summary || 'specific scenario access requirement'}`;
    }
    if (policy.consolidated) {
      const controls = recommendationControlsForPolicy(policy).slice(0, 4);
      return `Recommended because: consolidated ${controls.join(' + ') || 'strategy controls'}`;
    }
    const controls = controlsForStrategy()
      .filter(controlId => CONTROLS[controlId].policyIds.includes(policy.id))
      .slice(0, 3)
      .map(controlId => {
        const control = CONTROLS[controlId];
        const sources = controlRecommendationSources(controlId);
        return sources.length ? `${control.label} from ${sources.join(', ')}` : control.label;
      });
    if (!controls.length) return 'Baseline library item: review only if it fits your design.';
    return `Recommended because: ${controls.join(' + ')}`;
  }

  function purposeForPolicy(policy) {
    if (policy.kind === 'scenario') return PURPOSE_GROUPS.find(group => group.id === 'scenarios');
    if (policy.consolidated) {
      if (policy.persona === 'Admins') return PURPOSE_GROUPS.find(group => group.id === 'admin-access');
      if (policy.persona === 'Agents' || isPreviewPolicy(policy)) return PURPOSE_GROUPS.find(group => group.id === 'agents-workloads');
      if (policy.persona === 'Guests') return PURPOSE_GROUPS.find(group => group.id === 'devices-apps');
      if (policy.persona === 'Service Accounts') return PURPOSE_GROUPS.find(group => group.id === 'devices-apps');
    }
    const policyControls = controlsForStrategy().filter(controlId => CONTROLS[controlId].policyIds.includes(policy.id));
    if (policyControls.length) {
      const match = PURPOSE_GROUPS.find(group => group.controls.some(controlId => policyControls.includes(controlId)));
      if (match) return match;
    }
    if (policy.persona === 'Admins') return PURPOSE_GROUPS.find(group => group.id === 'admin-access');
    if (policy.persona === 'Agents' || isPreviewPolicy(policy)) return PURPOSE_GROUPS.find(group => group.id === 'agents-workloads');
    return PURPOSE_GROUPS.find(group => group.id === 'library');
  }

  function groupedPolicies(list) {
    const buckets = new Map(PURPOSE_GROUPS.map(group => [group.id, { ...group, policies: [] }]));
    list.forEach(policy => {
      const group = purposeForPolicy(policy);
      buckets.get(group.id).policies.push(policy);
    });
    return PURPOSE_GROUPS
      .map(group => buckets.get(group.id))
      .filter(group => group.policies.length);
  }

  function decisionLabel(decision) {
    if (decision === 'include') return 'Enable';
    if (decision === 'monitor') return 'Report-only first';
    return 'Leave out';
  }

  function whatPolicyProtects(policy) {
    const controls = recommendationControlsForPolicy(policy);
    if (controls.length) return controls.slice(0, 3).join(', ');
    if (policy.persona === 'Global') return 'Tenant-wide baseline coverage';
    return `${policy.persona} baseline coverage`;
  }

  function beforeExportText(policy) {
    const prereqCount = policy.prerequisites?.length || 0;
    const objectCount = policy.requiredObjects?.length || 0;
    if (prereqCount || objectCount) {
      return `${prereqCount} prerequisite${prereqCount === 1 ? '' : 's'} and ${objectCount} required object${objectCount === 1 ? '' : 's'} to check before export.`;
    }
    return 'No extra prerequisites recorded. Review exclusions before export.';
  }

  function controlRecommendationSources(controlId) {
    if (state.appliedStrategy?.controls?.includes(controlId)) {
      return [state.appliedStrategy.type === 'scenario' ? 'scenario planner' : 'strategy builder'];
    }
    const sources = [];
    if (selectedIdentity().controls.includes(controlId)) sources.push('identity scope');
    if (selectedTarget().controls.includes(controlId)) sources.push('target scope');
    const threats = THREATS.filter(threat => state.selectedThreats.has(threat.id) && threat.controls.includes(controlId));
    if (threats.length) sources.push(`${threats.length} selected threat${threats.length === 1 ? '' : 's'}`);
    return sources;
  }

  function renderAll() {
    renderTabs();
    renderSource();
    renderScope();
    renderScopeSummary();
    renderThreats();
    renderCoverage();
    renderStrategyBuilder();
    renderScenarioPlanner();
    renderPersonaFilters();
    renderPolicyPlanSummary();
    renderPolicyList();
    renderSelected();
    renderMetrics();
    renderWarnings();
    renderImport();
    renderSegmented('policyViewControl', state.policyView, 'view');
  }

  function renderTabs() {
    const isStart = state.activeTab === 'start';
    $('introActions').hidden = isStart;
    $('workflowTabs').hidden = true;
    $('pathChangeBar').hidden = isStart;
    document.querySelectorAll('button[role="tab"][data-tab]').forEach(btn => {
      const active = btn.dataset.tab === state.activeTab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
      btn.setAttribute('tabindex', active ? '0' : '-1');
    });
    document.querySelectorAll('[data-tab-panel]').forEach(panel => {
      const active = panel.dataset.tabPanel === state.activeTab;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });
  }

  function renderSource() {
    const upstream = BASELINE.upstream || {};
    const overrides = BASELINE.approvedOverrides || [];
    $('baselineVersion').textContent = `Baseline ${BASELINE.version}`;
    $('sourceVersion').textContent = upstream.version || BASELINE.version;
    $('sourceUpstream').textContent = upstream.repo || 'j0eyv/ConditionalAccessBaseline';
    $('commitText').textContent = BASELINE.commit;
    $('sourceParity').textContent = `${BASELINE.policies.length - overrides.length}/${BASELINE.policies.length} exact, ${overrides.length} approved override`;
    $('sourceOverride').textContent = overrides.length
      ? overrides.map(item => `${item.id}: ${item.path} ${item.upstream} hours -> ${item.local} hours`).join('; ')
      : 'None';
    $('sourcePolicies').textContent = `${BASELINE.policies.length} baseline templates`;
    $('sourceGenerated').textContent = `${GENERATED_POLICIES.length} V2 preview variants`;
    $('sourceGroups').textContent = `${BASELINE.groups.length} group objects`;
    $('sourceLocations').textContent = `${BASELINE.namedLocations.length} named locations`;
  }

  function renderScope() {
    $('identityOptions').innerHTML = IDENTITY_TYPES.map(item => choiceButton(item, state.selectedIdentity, 'identity')).join('');
    $('targetOptions').innerHTML = TARGETS.map(item => choiceButton(item, state.selectedTarget, 'target')).join('');
    $('identityOptions').querySelectorAll('button[data-identity]').forEach(btn => {
      btn.addEventListener('click', () => {
        state.selectedIdentity = btn.dataset.identity;
        state.appliedStrategy = null;
        state.touchedDecisions.clear();
        syncRecommendations();
        selectFirstVisible();
        renderAll();
      });
    });
    $('targetOptions').querySelectorAll('button[data-target]').forEach(btn => {
      btn.addEventListener('click', () => {
        state.selectedTarget = btn.dataset.target;
        state.appliedStrategy = null;
        state.touchedDecisions.clear();
        syncRecommendations();
        selectFirstVisible();
        renderAll();
      });
    });
  }

  function renderScopeSummary() {
    const identity = selectedIdentity();
    const target = selectedTarget();
    const suggestions = suggestedThreatIds()
      .map(threatId => THREATS.find(threat => threat.id === threatId)?.name)
      .filter(Boolean)
      .slice(0, 5);
    const threatText = suggestions.length
      ? suggestions.join(', ')
      : 'no mapped threat suggestions yet';
    $('scopeSummary').textContent = `${identity.label} accessing ${target.label.toLowerCase()} commonly need protection against ${threatText}. Confirm the suggested threats below, then review the controls that will shape the policy set.`;
  }

  function choiceButton(item, activeId, type) {
    const active = item.id === activeId ? 'active' : '';
    const risk = riskLabel(item.baseRisk || Math.round(55 * item.riskMultiplier));
    return `<button class="choice-card ${active}" data-${type}="${esc(item.id)}">
      <span class="choice-title">${esc(item.label)}</span>
      <span class="choice-desc">${esc(item.desc)}</span>
      <span class="choice-risk ${risk.className}">${esc(risk.label)}</span>
    </button>`;
  }

  function riskLabel(score) {
    if (score >= 84) return { label: 'critical', className: 'critical' };
    if (score >= 70) return { label: 'high', className: 'high' };
    return { label: 'medium', className: 'medium' };
  }

  function renderThreats() {
    const suggestions = suggestedThreatDetails();
    $('threatList').innerHTML = THREATS.map(threat => {
      const selected = state.selectedThreats.has(threat.id);
      const suggested = suggestions.has(threat.id);
      const classes = [
        selected ? 'active' : '',
        suggested && !selected ? 'suggested' : ''
      ].filter(Boolean).join(' ');
      const status = selected
        ? 'Selected'
        : suggested
          ? 'Suggested'
          : 'Optional';
      const reason = suggested
        ? Array.from(new Set(suggestions.get(threat.id))).join(' + ')
        : 'Add this threat if it matches your environment.';
      const controls = threat.controls.map(id => CONTROLS[id]?.label).filter(Boolean).slice(0, 3).join(', ');
      return `<button class="threat-card ${classes}" data-threat="${esc(threat.id)}">
        <span class="threat-top">
          <span class="technique">${esc(threat.id)}</span>
          <span class="risk-pill ${threat.severity.toLowerCase()}">${esc(threat.severity)}</span>
        </span>
        <span class="threat-name">${esc(threat.name)}</span>
        <span class="threat-meta">${esc(threat.tactic)}</span>
        <span class="threat-desc">${esc(threat.desc)}</span>
        <span class="threat-reason">${esc(status)} - ${esc(reason)}</span>
        <span class="threat-controls">${esc(controls)}</span>
      </button>`;
    }).join('');
    $('threatList').querySelectorAll('button[data-threat]').forEach(btn => {
      btn.addEventListener('click', () => {
        toggleThreat(btn.dataset.threat);
      });
    });
  }

  function toggleThreat(threatId) {
    state.appliedStrategy = null;
    if (state.selectedThreats.has(threatId)) {
      state.selectedThreats.delete(threatId);
    } else {
      state.selectedThreats.add(threatId);
    }
    state.activeTab = 'strategy-builder';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    syncRecommendations();
    selectFirstVisible();
    renderAll();
  }

  function renderCoverage() {
    const controls = controlsForStrategy();
    const baseRisk = Math.min(96, Math.round(selectedIdentity().baseRisk * selectedTarget().riskMultiplier));
    const reduction = Math.min(86, controls.reduce((sum, id) => sum + CONTROLS[id].reduction, 0));
    const residual = Math.max(5, baseRisk - reduction);
    $('coverageSummary').innerHTML = `<div class="risk-strip">
      <div><span>Base risk</span><strong>${baseRisk}</strong></div>
      <div><span>Reduction</span><strong>${reduction}</strong></div>
      <div><span>Residual</span><strong>${residual}</strong></div>
    </div>
    <div class="coverage-note">${esc(recommendedPolicies().length)} baseline-first policies currently map to ${esc(controls.length)} controls. Scope-derived controls appear here; threat cards only highlight threats you choose.</div>`;
    $('controlList').innerHTML = controls.map(controlId => {
      const control = CONTROLS[controlId];
      const policies = control.policyIds.flatMap(id => policiesById(id)).filter(policyAllowedForScope);
      const policyCount = new Set(policies.map(policyKey)).size;
      const sources = controlRecommendationSources(controlId);
      const sourceText = sources.length ? `from ${sources.join(', ')}` : 'baseline mapped';
      return `<div class="control-row control-${esc(controlId)}">
        <span class="control-dot"></span>
        <div>
          <strong>${esc(control.label)}</strong>
          <span>${esc(control.category)} - ${policyCount} policy${policyCount === 1 ? '' : 'ies'} - ${esc(sourceText)}</span>
        </div>
      </div>`;
    }).join('') || '<div class="empty-state">No controls selected.</div>';
  }

  function renderStrategyBuilder() {
    const plan = strategyPlan();
    $('strategyProtection').value = state.strategy.protection;
    $('strategyRollout').value = state.strategy.rollout;
    document.querySelectorAll('[data-strategy-toggle]').forEach(input => {
      input.checked = Boolean(state.strategy[input.dataset.strategyToggle]);
    });
    $('applyStrategyBtn').disabled = plan.empty;
    $('downloadStrategyBtn').disabled = plan.empty;
    $('strategyContinueBtn').disabled = plan.empty;
    $('strategyReviewBtn').disabled = plan.empty;
    $('strategyRequirementHint').textContent = plan.empty
      ? 'Select at least one requirement to continue.'
      : `${plan.selectedRequirements.length} requirement${plan.selectedRequirements.length === 1 ? '' : 's'} selected. ${plan.consolidatedPolicies.length} policies will be proposed.`;
    renderGuidedStage('strategy', state.workflowStage.strategy);
    renderStrategyAttackVectors(plan);
    $('strategyMitreSummary').textContent = plan.empty
      ? 'Select requirements first'
      : `${plan.score}% coverage - ${strategyAttackVectors(plan).length} addressed - ${strategyUnaddressedMitre(plan).length} gaps`;

    $('strategySummary').innerHTML = `<div class="strategy-score-grid primary-metrics">
      <article><span>Managed policies</span><strong>${esc(plan.consolidatedPolicies.length)}</strong><em>${esc(policySavingsText(plan))}</em></article>
      <article><span>MITRE coverage</span><strong>${esc(plan.score)}%</strong><em>${esc(mitreSummaryText(plan))}</em></article>
    </div>
    <div class="strategy-context-line"><strong>${esc(frictionLabel(plan.friction))}</strong><span>Rollout risk: ${esc(plan.rolloutRisk)}. ${esc(rolloutLabel(plan.requirements.rollout, plan.empty))}</span></div>
    ${plan.empty ? strategyEmptyState(plan) : strategyBuildOrder(plan)}
    ${state.appliedStrategy ? '<div class="strategy-applied">This strategy is currently applied to the rebuild set.</div>' : ''}`;

    $('strategySafety').innerHTML = plan.empty ? '<div class="empty-state">Guardrails appear after you select a requirement.</div>' : plan.safety.map(strategySafetyCard).join('') || '<div class="empty-state">No separation warnings for this strategy.</div>';
    $('strategyBaselineRepresented').innerHTML = plan.empty ? '<div class="empty-state">Baseline traceability appears after the consolidated design is generated.</div>' : plan.consolidatedPolicies.map(strategyRepresentationCard).join('');
    $('mitreCoverage').innerHTML = plan.mitre.map(mitreCoverageRow).join('');
    $('strategyResidualGaps').innerHTML = RESIDUAL_GAPS.map(gap => `<div class="strategy-note">${esc(gap)}</div>`).join('');
  }

  function renderScenarioPlanner() {
    const plan = scenarioPlan();
    const custom = plan.template.id === 'custom';
    syncScenarioFields();
    if (!custom) renderScenarioRelevantFields(plan);
    syncScenarioObjectCatalog();
    $('scenarioTemplates').innerHTML = SCENARIO_TEMPLATES.map(template => `<button class="scenario-template-card ${template.id === state.scenario.template ? 'active' : ''}" type="button" data-scenario-template="${esc(template.id)}">
      <strong>${esc(template.label)}</strong>
      <span>${esc(template.desc)}</span>
    </button>`).join('');
    $('scenarioTitle').textContent = plan.template.label;
    $('applyScenarioBtn').disabled = !plan.canApply;
    $('downloadScenarioBtn').disabled = false;
    $('scenarioSummary').innerHTML = renderScenarioSummary(plan);
    $('scenarioPrepareSummary').innerHTML = renderScenarioPrepareSummary(plan);
    $('scenarioPrepareHint').textContent = plan.canApply
      ? 'Required objects are ready. Continue to policy review and export.'
      : `Add ${plan.missing.map(item => item.field).join(' and ')} to continue.`;
    $('scenarioLocationField').hidden = !plan.missing.some(item => item.type === 'location') && state.scenario.location === 'any' && state.scenario.deviceTrust !== 'trustedLocation';
    $('scenarioMitreSummary').textContent = `${plan.score}% coverage - ${scenarioAddressedMitre(plan).length} addressed - ${scenarioUnaddressedMitre(plan).length} gaps`;
    renderGuidedStage('scenario', state.workflowStage.scenario);
    $('scenarioSessionHelp').innerHTML = renderScenarioSessionHelp(plan);
    $('scenarioDurationHelp').innerHTML = renderScenarioDurationHelp(plan);
    $('scenarioMitre').innerHTML = renderScenarioMitre(plan);
    $('scenarioPolicyPack').innerHTML = renderScenarioPolicyPack(plan);
    $('scenarioPrerequisites').innerHTML = scenarioChecklist(plan.prerequisites);
    $('scenarioGuidance').innerHTML = scenarioChecklist([...plan.guidance, ...plan.warnings]);
    $('scenarioStandardEditor').hidden = custom;
    $('scenarioVisualDesigner').hidden = !custom;
    $('scenarioPlanBtn').textContent = custom ? 'Review visual policy plan' : 'Review policy plan';
    $('scenarioSettingsHint').textContent = custom
      ? 'Complete the visual path, then review the minimum safe policy set.'
      : 'Review the recommended defaults before continuing.';
    if (custom) renderVisualScenarioDesigner(plan);
    else closeVisualFlyout('control', false);
  }

  function renderScenarioRelevantFields(plan) {
    const custom = plan.template.id === 'custom';
    const accountType = plan.inputs.accountType;
    const show = new Set(['scenarioGroupName', 'scenarioDuration']);
    if (custom) {
      ['scenarioAccountType', 'scenarioResource', 'scenarioDeviceTrust', 'scenarioPlatforms', 'scenarioLocation', 'scenarioRiskTolerance', 'scenarioAuthRequirement', 'scenarioSession', 'scenarioSensitivity'].forEach(id => show.add(id));
    } else {
      if (!['serviceAccount', 'agentIdentity'].includes(accountType)) {
        ['scenarioDeviceTrust', 'scenarioPlatforms', 'scenarioAuthRequirement', 'scenarioSession', 'scenarioSensitivity'].forEach(id => show.add(id));
      }
      if (accountType === 'admin' || plan.inputs.sensitivity === 'highlySensitive') show.add('scenarioRiskTolerance');
      if (accountType === 'serviceAccount' || plan.inputs.location !== 'any' || plan.inputs.deviceTrust === 'trustedLocation') show.add('scenarioLocation');
      if (accountType === 'agentIdentity') show.add('scenarioRiskTolerance');
    }
    ['scenarioAccountType', 'scenarioResource', 'scenarioDeviceTrust', 'scenarioPlatforms', 'scenarioLocation', 'scenarioRiskTolerance', 'scenarioAuthRequirement', 'scenarioSession', 'scenarioDuration', 'scenarioSensitivity'].forEach(id => {
      const field = $(id)?.closest('label');
      if (field) field.hidden = !show.has(id);
    });
  }

  function renderVisualScenarioDesigner(plan) {
    const visual = state.scenarioVisual;
    const addressed = scenarioAddressedMitre(plan);
    const gaps = scenarioUnaddressedMitre(plan);
    const readiness = plan.missing.length ? `${plan.missing.length} tenant object${plan.missing.length === 1 ? '' : 's'} needed later` : 'Ready to apply';
    $('scenarioVisualOutcome').innerHTML = [
      ['Policies required', plan.policies.length, plan.policies.length > 1 ? 'Safe branches included' : 'One focused policy'],
      ['Threats addressed', addressed.length, `${plan.score}% identity coverage`],
      ['Remaining gaps', gaps.length, gaps.length ? 'Other controls still required' : 'No mapped CA gaps'],
      ['User friction', visualScenarioFriction(plan.inputs), visualScenarioFrictionHelp(plan.inputs)],
      ['Export readiness', readiness, plan.missing.length ? 'Guidance remains available' : 'Required IDs supplied']
    ].map(([label, value, help]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(help)}</small></article>`).join('');

    const lanes = [
      { id: 'if', eyebrow: 'IF this access happens', title: 'Assignments and conditions' },
      { id: 'then', eyebrow: 'THEN apply', title: 'Access and session controls' }
    ];
    $('scenarioVisualMap').innerHTML = lanes.map(lane => `<section class="visual-map-lane visual-lane-${lane.id}" aria-label="${esc(lane.eyebrow)}">
      <div class="visual-lane-label"><span>${esc(lane.eyebrow)}</span><strong>${esc(lane.title)}</strong></div>
      <div class="visual-node-track">${VISUAL_SCENARIO_NODES.filter(node => node.lane === lane.id).map(node => visualScenarioNode(node, plan)).join('')}</div>
    </section>`).join('<div class="visual-if-then-bridge" aria-hidden="true"><span>THEN</span></div>');

    const activeIndex = Math.max(0, VISUAL_SCENARIO_NODES.findIndex(node => node.id === visual.activeNode));
    $('visualBackBtn').disabled = activeIndex === 0;
    $('visualContinueBtn').textContent = activeIndex === VISUAL_SCENARIO_NODES.length - 1 ? 'Review policy plan' : 'Continue';
    $('visualNodeProgress').innerHTML = `<strong>Decision ${activeIndex + 1} of ${VISUAL_SCENARIO_NODES.length}</strong><span>${esc(VISUAL_SCENARIO_NODES[activeIndex].question)}</span>`;
    $('visualUndoBtn').disabled = visual.history.length === 0;
    $('scenarioVisualBlueprint').innerHTML = renderVisualPolicyBlueprint(plan);
    if (visual.flyout) renderVisualControlFlyout(plan);
    if (visual.threatOpen) renderVisualThreatFlyout(plan);
  }

  function visualScenarioNode(node, plan) {
    const status = visualScenarioNodeStatus(node, plan);
    const summary = visualScenarioNodeSummary(node);
    return `<button class="visual-policy-node status-${esc(status.id)} ${state.scenarioVisual.activeNode === node.id ? 'active' : ''}" type="button" data-visual-node="${esc(node.id)}" aria-haspopup="dialog" aria-expanded="${state.scenarioVisual.flyout === node.id ? 'true' : 'false'}">
      <span class="visual-node-step">${String(node.step).padStart(2, '0')}</span>
      <span class="visual-node-copy"><small>${esc(status.label)}</small><strong>${esc(node.title)}</strong><em>${esc(summary)}</em></span>
      <span class="visual-node-arrow" aria-hidden="true">›</span>
    </button>`;
  }

  function visualScenarioNodeStatus(node, plan) {
    if (node.fields.some(field => field === 'groupName' && !String(state.scenario.groupName || '').trim())) return { id: 'needs-input', label: 'Needs input' };
    if (plan.policies.length > 1 && ['context', 'grant'].includes(node.id) && state.scenarioVisual.completed.has(node.id)) return { id: 'split', label: 'Separate policy required' };
    if (state.scenarioVisual.completed.has(node.id)) {
      const modified = node.fields.some(field => state.scenario[field] !== visualRecommendedValue(field, state.scenario));
      return modified ? { id: 'modified', label: 'Modified' } : { id: 'selected', label: 'Selected' };
    }
    return { id: 'recommended', label: 'Recommended' };
  }

  function visualScenarioNodeSummary(node) {
    return node.fields.map(field => visualFieldValueLabel(field, state.scenario[field])).filter(Boolean).join(' · ');
  }

  function visualFieldValueLabel(field, value) {
    if (field === 'groupName') return value || 'Group name required';
    const option = VISUAL_FIELD_OPTIONS[field]?.options.find(item => item[0] === value);
    return option?.[1] || value || 'Choose an option';
  }

  function renderVisualPolicyBlueprint(plan) {
    if (!plan.policies.length) return '<div class="empty-state">Complete the policy path to generate a blueprint.</div>';
    const split = plan.policies.length > 1
      ? `<div class="visual-split-explanation"><strong>${plan.policies.length} policies are required</strong><span>${esc(visualPolicySplitSummary(plan))}</span></div>`
      : '<div class="visual-merge-explanation"><strong>One policy is enough</strong><span>The selected assignments, grant controls, and session controls can coexist without changing the intended logic.</span></div>';
    return `${split}<div class="visual-blueprint-cards">${renderScenarioPolicyPack(plan)}</div>`;
  }

  function visualPolicySplitSummary(plan) {
    const reasons = [];
    if (plan.controls.includes('sign_in_risk')) reasons.push('High sign-in risk is kept as an independent block policy');
    if (plan.controls.includes('user_risk')) reasons.push('High user risk is evaluated independently from sign-in risk');
    if (state.scenario.accessDecision === 'block' && plan.controls.some(control => ['mfa', 'phish_mfa', 'device_compliance'].includes(control))) reasons.push('Block and grant requirements cannot share one access decision');
    if (state.scenario.accountType === 'agentIdentity') reasons.push('Preview agent targeting remains isolated from ordinary user controls');
    return `${reasons.join('. ')}. This is the minimum set that preserves the intended Conditional Access evaluation.`;
  }

  function openVisualScenarioNode(nodeId, opener) {
    if (!VISUAL_SCENARIO_NODES.some(node => node.id === nodeId)) return;
    state.scenarioVisual.activeNode = nodeId;
    state.scenarioVisual.flyout = nodeId;
    state.scenarioVisual.threatOpen = false;
    visualFlyoutOpener = opener || document.activeElement;
    renderScenarioPlanner();
    $('visualFlyoutBackdrop').hidden = false;
    $('visualControlFlyout').hidden = false;
    $('visualThreatFlyout').hidden = true;
    requestAnimationFrame(() => $('visualControlFlyout').focus());
  }

  function renderVisualControlFlyout(plan) {
    const node = VISUAL_SCENARIO_NODES.find(item => item.id === state.scenarioVisual.flyout);
    if (!node) return;
    $('visualFlyoutStep').textContent = `Decision ${node.step} of ${VISUAL_SCENARIO_NODES.length}`;
    $('visualFlyoutTitle').textContent = node.question;
    $('visualFlyoutContent').innerHTML = `<div class="visual-recommendation-banner">
      <span>Recommended configuration</span>
      <strong>${esc(node.fields.map(field => visualFieldValueLabel(field, visualRecommendedValue(field, state.scenario))).join(' · '))}</strong>
      <p>${esc(visualNodeRecommendationReason(node, state.scenario))}</p>
    </div>
    <div class="visual-option-groups">${node.fields.map(field => renderVisualFieldOptions(field)).join('')}</div>
    ${renderVisualDecisionImpact(node, plan)}`;
    $('visualFlyoutBackdrop').hidden = false;
    $('visualControlFlyout').hidden = false;
  }

  function renderVisualFieldOptions(field) {
    if (field === 'groupName') {
      return `<label class="visual-text-option"><span>Scenario security group</span><input id="visualScenarioGroupName" type="text" value="${esc(state.scenario.groupName || '')}" placeholder="CA-Scenario-CustomAccess-Users"><small>Use a dedicated group so ownership, expiry, and removal remain obvious. The object ID is requested later.</small></label>`;
    }
    const config = VISUAL_FIELD_OPTIONS[field];
    if (!config) return '';
    const recommended = visualRecommendedValue(field, state.scenario);
    return `<fieldset class="visual-option-group"><legend>${esc(config.label)}</legend>${config.options.map(([value, label, desc]) => `<button class="visual-choice ${state.scenario[field] === value ? 'selected' : ''}" type="button" data-visual-field="${esc(field)}" data-visual-choice="${esc(value)}" aria-pressed="${state.scenario[field] === value ? 'true' : 'false'}">
      <span><strong>${esc(label)}</strong>${value === recommended ? '<em>Recommended</em>' : ''}</span><small>${esc(desc)}</small>
    </button>`).join('')}</fieldset>`;
  }

  function renderVisualDecisionImpact(node, plan) {
    const impacts = visualDecisionImpact(node, plan);
    return `<section class="visual-decision-impact"><h4>What this decision changes</h4><dl>
      <dt>Security</dt><dd>${esc(impacts.security)}</dd>
      <dt>User experience</dt><dd>${esc(impacts.user)}</dd>
      <dt>Entra configuration</dt><dd>${esc(impacts.entra)}</dd>
      <dt>Prerequisites</dt><dd>${esc(impacts.prerequisite)}</dd>
    </dl></section>`;
  }

  function visualDecisionImpact(node, plan) {
    const inputs = plan.inputs;
    if (node.id === 'identity') return {
      security: 'Limits the policy to a dedicated scenario population instead of changing access for everyone.',
      user: 'Only members of the scenario group receive the selected prompts and restrictions.',
      entra: `Assignments > Users or workload identities: ${visualFieldValueLabel('accountType', inputs.accountType)} via ${inputs.groupName || 'a dedicated group'}.`,
      prerequisite: 'Create the group, assign an owner, and add its object ID only when preparing the export.'
    };
    if (node.id === 'resource') return {
      security: 'Reduces blast radius by targeting only the resource required for the access pattern.',
      user: `The controls apply when accessing ${scenarioApplications(inputs.resource).map(scenarioApplicationLabel).join(', ')}.`,
      entra: `Target resources: ${scenarioApplications(inputs.resource).map(scenarioApplicationLabel).join(', ')}.`,
      prerequisite: scenarioKnownLimitation(inputs)
    };
    if (node.id === 'device') return {
      security: inputs.deviceTrust === 'managed' ? 'Uses device compliance as a strong access signal.' : 'Compensates for weaker device trust with browser or session restrictions.',
      user: inputs.deviceTrust === 'managed' ? 'Users need a compliant managed device.' : 'Desktop clients or downloads may be restricted.',
      entra: `${visualFieldValueLabel('deviceTrust', inputs.deviceTrust)}; ${visualFieldValueLabel('platforms', inputs.platforms)}.`,
      prerequisite: inputs.deviceTrust === 'managed' ? 'Requires a working Intune compliance policy and accurate device inventory.' : 'Confirm supported app-enforced restrictions for the target resource.'
    };
    if (node.id === 'context') return {
      security: `${visualFieldValueLabel('riskTolerance', inputs.riskTolerance)} risk posture for ${visualFieldValueLabel('sensitivity', inputs.sensitivity).toLowerCase()}.`,
      user: `${visualFieldValueLabel('duration', inputs.duration)} access from ${visualFieldValueLabel('location', inputs.location).toLowerCase()}.`,
      entra: 'Conditions are combined with AND, so every configured condition must match before this policy applies.',
      prerequisite: inputs.location === 'any' ? 'No named location required.' : 'A maintained named-location object ID is required before export.'
    };
    if (node.id === 'grant') return {
      security: inputs.accessDecision === 'block' ? 'Matching access is denied.' : `${scenarioAuthRequirementLabel(inputs.authRequirement)} is required before access.`,
      user: inputs.accessDecision === 'block' ? 'The selected access path cannot be completed.' : 'Users must satisfy the selected authentication and device controls.',
      entra: `${visualFieldValueLabel('accessDecision', inputs.accessDecision)}; ${visualFieldValueLabel('riskResponse', inputs.riskResponse)}.`,
      prerequisite: inputs.riskResponse === 'none' ? 'No Entra ID Protection risk branch.' : 'Microsoft Entra ID P2 is required for risk conditions.'
    };
    if (node.id === 'session') return {
      security: SESSION_STRICTNESS_HELP[inputs.session]?.meaning || 'Uses standard session behaviour.',
      user: SESSION_STRICTNESS_HELP[inputs.session]?.recommended || 'Normal session behaviour.',
      entra: scenarioSessionSettingsSummary(inputs, plan.controls),
      prerequisite: inputs.session === 'browserLocked' ? 'App-enforced restrictions must be supported and configured by the target application.' : 'No additional application integration required.'
    };
    return {
      security: inputs.rollout === 'enabled' ? 'The policy enforces immediately.' : 'The policy can be validated before enforcement.',
      user: inputs.rollout === 'enabled' ? 'Affected users experience the controls immediately.' : 'No enforcement occurs until the rollout decision changes.',
      entra: visualFieldValueLabel('rollout', inputs.rollout),
      prerequisite: 'Validate with a pilot identity, the What If tool, and sign-in logs before enabling.'
    };
  }

  function visualNodeRecommendationReason(node, inputs) {
    if (node.id === 'identity') return 'A dedicated scenario group keeps targeting reversible and easy to review.';
    if (node.id === 'resource') return 'Target only the resource needed; broader targeting increases impact without improving this scenario.';
    if (node.id === 'device') return inputs.sensitivity === 'highlySensitive' ? 'Highly sensitive access should prefer managed and compliant devices.' : 'Device trust determines whether compliance or browser restrictions are the safer control.';
    if (node.id === 'context') return 'Time-boxed access and explicit risk boundaries reduce persistent exception risk.';
    if (node.id === 'grant') return inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive' ? 'High-value access should use phishing-resistant authentication and separate risk guardrails.' : 'Standard MFA gives broad protection while keeping the access path supportable.';
    if (node.id === 'session') return SESSION_STRICTNESS_HELP[visualRecommendedValue('session', inputs)]?.recommended || 'Use session controls proportionate to device and data risk.';
    return 'Microsoft recommends validating Conditional Access impact before enforcing a new policy.';
  }

  function visualRecommendedValue(field, inputs) {
    if (field === 'accountType') return 'internalUser';
    if (field === 'groupName') return visualScenarioGroupName(inputs);
    if (field === 'resource') return 'office365';
    if (field === 'deviceTrust') {
      if (inputs.accountType === 'externalGuest') return 'browserOnly';
      if (inputs.accountType === 'serviceAccount') return 'trustedLocation';
      if (inputs.accountType === 'agentIdentity' || inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive') return 'managed';
      return 'managed';
    }
    if (field === 'platforms') return 'any';
    if (field === 'location') return inputs.accountType === 'serviceAccount' ? 'trustedOnly' : 'any';
    if (field === 'riskTolerance') return inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive' ? 'strict' : 'balanced';
    if (field === 'sensitivity') return 'sensitive';
    if (field === 'duration') return inputs.accountType === 'serviceAccount' ? 'ongoing' : 'temporary';
    if (field === 'accessDecision') return inputs.accountType === 'serviceAccount' ? 'block' : 'grant';
    if (field === 'authRequirement') return inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive' ? 'phishingResistantMfa' : 'standardMfa';
    if (field === 'riskResponse') return inputs.riskTolerance === 'strict' ? (inputs.sensitivity === 'highlySensitive' || inputs.accountType === 'admin' ? 'signInAndUserRisk' : 'signInRisk') : 'none';
    if (field === 'session') return recommendedScenarioSession(inputs);
    if (field === 'rollout') return 'reportOnly';
    return inputs[field];
  }

  function visualScenarioGroupName(inputs) {
    const identity = { internalUser: 'Internal', externalGuest: 'External', admin: 'Privileged', serviceAccount: 'Automation', agentIdentity: 'Agent' }[inputs.accountType] || 'Custom';
    const resource = { sharepoint: 'SharePoint', exchange: 'Exchange', office365: 'M365', adminPortals: 'AdminPortals', allApps: 'AllApps', agentResources: 'AgentResources' }[inputs.resource] || 'Access';
    return `CA-Scenario-${identity}-${resource}-Users`;
  }

  function updateVisualScenarioChoice(field, value, live = false) {
    if (!Object.prototype.hasOwnProperty.call(state.scenario, field) || state.scenario[field] === value) return;
    if (!live) state.scenarioVisual.history.push(visualScenarioSnapshot());
    state.scenario[field] = value;
    state.appliedStrategy = null;
    state.guideOnly = null;
    if (live) return;
    renderScenarioPlanner();
    requestAnimationFrame(() => {
      const selected = document.querySelector(`button[data-visual-field="${field}"][data-visual-choice="${value}"]`);
      if (selected) selected.focus();
    });
  }

  function visualScenarioSnapshot() {
    return {
      scenario: clone(state.scenario),
      activeNode: state.scenarioVisual.activeNode,
      completed: [...state.scenarioVisual.completed]
    };
  }

  function undoVisualScenarioChange() {
    const snapshot = state.scenarioVisual.history.pop();
    if (!snapshot) return;
    state.scenario = snapshot.scenario;
    state.scenarioVisual.activeNode = snapshot.activeNode;
    state.scenarioVisual.completed = new Set(snapshot.completed);
    renderScenarioPlanner();
    toast('Last scenario change undone');
  }

  function resetVisualScenarioRecommendations() {
    state.scenarioVisual.history.push(visualScenarioSnapshot());
    const custom = SCENARIO_TEMPLATES.find(item => item.id === 'custom');
    const preserved = { groupId: state.scenario.groupId, locationId: state.scenario.locationId };
    const next = { ...SCENARIO_DEFAULTS, template: 'custom', ...custom.fields };
    next.groupName = visualScenarioGroupName(next);
    ['deviceTrust', 'platforms', 'location', 'riskTolerance', 'sensitivity', 'duration', 'accessDecision', 'authRequirement', 'riskResponse', 'session', 'rollout'].forEach(field => {
      next[field] = visualRecommendedValue(field, next);
    });
    state.scenario = { ...next, ...preserved };
    state.scenarioVisual.activeNode = 'identity';
    state.scenarioVisual.completed = new Set();
    state.scenarioVisual.flyout = null;
    state.scenarioVisual.threatOpen = false;
    renderScenarioPlanner();
    toast('Recommended visual scenario restored');
  }

  function moveVisualScenarioNode(delta, complete = false) {
    const current = Math.max(0, VISUAL_SCENARIO_NODES.findIndex(node => node.id === state.scenarioVisual.activeNode));
    if (complete) state.scenarioVisual.completed.add(VISUAL_SCENARIO_NODES[current].id);
    const next = current + delta;
    if (next >= VISUAL_SCENARIO_NODES.length) {
      closeVisualFlyout('control', false);
      setScenarioStage('plan');
      return;
    }
    if (next < 0) return;
    state.scenarioVisual.activeNode = VISUAL_SCENARIO_NODES[next].id;
    state.scenarioVisual.flyout = null;
    state.scenarioVisual.threatOpen = false;
    renderScenarioPlanner();
  }

  function acceptVisualScenarioDecision() {
    const current = state.scenarioVisual.activeNode;
    state.scenarioVisual.completed.add(current);
    closeVisualFlyout('control', false);
    moveVisualScenarioNode(1);
  }

  function openVisualThreatFlyout() {
    state.scenarioVisual.threatOpen = true;
    renderVisualThreatFlyout(scenarioPlan());
    $('visualThreatFlyout').hidden = false;
    requestAnimationFrame(() => $('visualThreatFlyout').focus());
  }

  function renderVisualThreatFlyout(plan) {
    const node = VISUAL_SCENARIO_NODES.find(item => item.id === state.scenarioVisual.activeNode);
    if (!node) return;
    const controls = visualNodeControlIds(node, plan);
    const coverage = mitreCoverageForControls(controls);
    const addressed = coverage.filter(item => ['Strongly mitigated', 'Partially mitigated'].includes(item.status));
    const gaps = coverage.filter(item => !['Strongly mitigated', 'Partially mitigated'].includes(item.status));
    $('visualThreatTitle').textContent = `${node.title}: threat impact`;
    $('visualThreatContent').innerHTML = `<div class="visual-threat-summary"><strong>${addressed.length} addressed</strong><span>${gaps.length} remain outside or beyond this decision</span></div>
      <section class="visual-threat-section"><h4>Addressed by this decision</h4>${addressed.length ? addressed.map(item => visualThreatCard(item, controls)).join('') : '<p class="empty-state">This decision shapes scope or rollout and does not directly mitigate a mapped technique.</p>'}</section>
      <section class="visual-threat-section visual-threat-gaps"><h4>Not fully addressed</h4>${gaps.map(item => visualThreatCard(item, controls)).join('')}</section>`;
  }

  function visualNodeControlIds(node, plan) {
    const identityControls = {
      internalUser: ['mfa', 'sign_in_risk', 'user_risk', 'device_compliance'],
      externalGuest: ['guest_access', 'mfa', 'app_protection'],
      admin: ['admin_mfa', 'phish_mfa', 'admin_session', 'sign_in_risk', 'user_risk'],
      serviceAccount: ['service_account_protection', 'trusted_location'],
      agentIdentity: ['agent_risk', 'agent_identity_block', 'users_agent_resources_block']
    }[plan.inputs.accountType] || [];
    const map = {
      identity: identityControls,
      resource: ['selected_app_block', 'users_agent_resources_block', 'app_protection'],
      device: ['device_compliance', 'app_protection', 'unknown_platforms', 'trusted_location'],
      context: ['trusted_location', 'sign_in_risk', 'user_risk'],
      grant: ['mfa', 'phish_mfa', 'admin_mfa', 'device_compliance', 'sign_in_risk', 'user_risk'],
      session: ['session_controls', 'persistent_browser', 'app_protection'],
      rollout: []
    };
    return (map[node.id] || []).filter(control => plan.controls.includes(control));
  }

  function visualThreatCard(item, controls) {
    const matched = [...(item.strongControls || []), ...(item.partialControls || [])].filter(control => controls.includes(control));
    const explanation = item.status === 'Strongly mitigated'
      ? 'The selected controls directly influence this identity attack path.'
      : item.status === 'Partially mitigated'
        ? 'Conditional Access reduces opportunity but cannot remove the attack path completely.'
        : 'This decision does not provide a direct Conditional Access mitigation; use the additional controls described in the final readiness review.';
    return `<article class="visual-threat-card status-${esc(item.status.toLowerCase().replace(/[^a-z0-9]+/g, '-'))}">
      <div><span>${esc(item.id)}</span><strong>${esc(item.name)}</strong></div>
      <em>${esc(item.status)}</em><p>${esc(explanation)}</p>
      ${matched.length ? `<small>Related controls: ${esc(matched.map(id => CONTROLS[id]?.label || id).join(', '))}</small>` : '<small>Requires another security control outside this decision.</small>'}
    </article>`;
  }

  function closeVisualFlyout(layer = 'control', restoreFocus = true) {
    if (!$('visualControlFlyout')) return;
    if (layer === 'threat') {
      state.scenarioVisual.threatOpen = false;
      $('visualThreatFlyout').hidden = true;
      if (restoreFocus && !$('visualControlFlyout').hidden) $('visualThreatImpactBtn').focus();
      return;
    }
    state.scenarioVisual.flyout = null;
    state.scenarioVisual.threatOpen = false;
    $('visualControlFlyout').hidden = true;
    $('visualThreatFlyout').hidden = true;
    $('visualFlyoutBackdrop').hidden = true;
    if (restoreFocus && visualFlyoutOpener?.isConnected) visualFlyoutOpener.focus();
    visualFlyoutOpener = null;
  }

  function handleVisualFlyoutKeydown(event) {
    const top = !$('visualThreatFlyout')?.hidden ? $('visualThreatFlyout') : !$('visualControlFlyout')?.hidden ? $('visualControlFlyout') : null;
    if (!top) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      closeVisualFlyout(top === $('visualThreatFlyout') ? 'threat' : 'control');
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = [...top.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])')].filter(item => !item.hidden);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function visualScenarioFriction(inputs) {
    if (inputs.accessDecision === 'block') return 'Low';
    let score = 1;
    if (inputs.authRequirement === 'passwordlessMfa') score += 1;
    if (inputs.authRequirement === 'phishingResistantMfa') score += 2;
    if (inputs.deviceTrust === 'managed') score += 2;
    if (inputs.deviceTrust === 'browserOnly') score += 2;
    if (inputs.session === 'short') score += 1;
    if (inputs.session === 'browserLocked') score += 2;
    if (inputs.location !== 'any') score += 1;
    return score <= 2 ? 'Low' : score <= 5 ? 'Moderate' : 'High';
  }

  function visualScenarioFrictionHelp(inputs) {
    const friction = visualScenarioFriction(inputs);
    if (friction === 'High') return 'Strong controls; communicate user impact';
    if (friction === 'Moderate') return 'Balanced prompts and restrictions';
    return 'Minimal additional interaction';
  }

  function renderGuidedStage(flow, stage) {
    document.querySelectorAll(`[data-${flow}-stage-panel]`).forEach(panel => {
      panel.hidden = panel.dataset[`${flow}StagePanel`] !== stage;
    });
    const order = flow === 'strategy'
      ? ['requirements', 'architecture']
      : ['template', 'settings', 'plan', 'prepare'];
    const activeIndex = order.indexOf(stage);
    document.querySelectorAll(`button[data-${flow}-stage]`).forEach(btn => {
      const index = order.indexOf(btn.dataset[`${flow}Stage`]);
      btn.classList.toggle('active', index === activeIndex);
      btn.classList.toggle('complete', index >= 0 && index < activeIndex);
      btn.setAttribute('aria-current', index === activeIndex ? 'step' : 'false');
      if (flow === 'scenario' && btn.closest('.guided-progress')) btn.disabled = index > activeIndex + 1;
    });
  }

  function syncScenarioFields() {
    $('scenarioGroupName').value = state.scenario.groupName || '';
    $('scenarioGroupId').value = state.scenario.groupId || '';
    $('scenarioLocationId').value = state.scenario.locationId || '';
    ['AccountType', 'Resource', 'DeviceTrust', 'Platforms', 'Location', 'RiskTolerance', 'AuthRequirement', 'Session', 'Duration', 'Sensitivity'].forEach(name => {
      const id = `scenario${name}`;
      const stateKey = name.charAt(0).toLowerCase() + name.slice(1);
      $(id).value = state.scenario[stateKey];
    });
  }

  function selectScenarioTemplate(templateId) {
    const template = SCENARIO_TEMPLATES.find(item => item.id === templateId) || SCENARIO_TEMPLATES[0];
    state.scenario = {
      ...SCENARIO_DEFAULTS,
      template: template.id,
      groupName: template.groupName,
      groupId: '',
      locationId: '',
      ...template.fields
    };
    if (template.id === 'custom') state.scenario.groupName = visualScenarioGroupName(state.scenario);
    state.scenarioVisual = {
      activeNode: 'identity',
      completed: new Set(),
      history: [],
      flyout: null,
      threatOpen: false
    };
    state.appliedStrategy = null;
    state.guideOnly = null;
    state.activeTab = 'scenario-planner';
    renderAll();
  }

  function scenarioPlan() {
    const template = SCENARIO_TEMPLATES.find(item => item.id === state.scenario.template) || SCENARIO_TEMPLATES[0];
    const inputs = { ...state.scenario };
    const custom = template.id === 'custom';
    const controls = uniqueValues(custom
      ? scenarioControlsFromInputs(inputs)
      : [...scenarioTemplateControls(template, inputs), ...scenarioModifierControls(inputs)]);
    const mitreIds = uniqueValues(custom
      ? scenarioMitreIdsFromControls(controls)
      : [...(template.mitre || []), ...scenarioMitreIdsFromControls(scenarioModifierControls(inputs))]);
    const missing = scenarioMissingObjects(template, inputs);
    const policies = scenarioPolicies(template, inputs, controls, missing);
    const fullMitre = mitreCoverageForControls(controls);
    const mitre = mitreIds.map(id => scenarioMitreItem(id, controls)).filter(Boolean);
    const score = controls.length ? strategyMitreScore(fullMitre, controls) : 0;
    const warnings = scenarioWarnings(template, inputs, missing);
    return {
      template,
      inputs,
      controls,
      mitre,
      fullMitre,
      score,
      missing,
      policies,
      canApply: policies.length > 0 && missing.length === 0,
      prerequisites: [...(template.prerequisites || []), ...scenarioDynamicPrerequisites(template, inputs, missing)],
      guidance: [...(template.guidance || []), ...scenarioDynamicGuidance(template, inputs)],
      warnings
    };
  }

  function scenarioControlsFromInputs(inputs) {
    const grantAccess = inputs.accessDecision !== 'block';
    const controls = new Set(grantAccess ? ['mfa'] : ['selected_app_block']);
    if (grantAccess && inputs.accountType === 'admin') ['phish_mfa', 'admin_mfa', 'admin_session', 'persistent_browser'].forEach(id => controls.add(id));
    if (inputs.accountType === 'externalGuest') controls.add('guest_access');
    if (inputs.accountType === 'serviceAccount') ['service_account_protection', 'trusted_location'].forEach(id => controls.add(id));
    if (inputs.accountType === 'agentIdentity') ['agent_risk', 'users_agent_resources_block'].forEach(id => controls.add(id));
    if (grantAccess && inputs.deviceTrust === 'managed') controls.add('device_compliance');
    if (grantAccess && (inputs.deviceTrust === 'browserOnly' || inputs.deviceTrust === 'unmanaged')) ['app_protection', 'session_controls', 'persistent_browser'].forEach(id => controls.add(id));
    if (inputs.deviceTrust === 'trustedLocation' || inputs.location !== 'any') controls.add('trusted_location');
    if (inputs.platforms === 'unknownBlocked') controls.add('unknown_platforms');
    if (inputs.riskResponse === 'signInRisk' || inputs.riskResponse === 'signInAndUserRisk') controls.add('sign_in_risk');
    if (inputs.riskResponse === 'signInAndUserRisk') controls.add('user_risk');
    if (grantAccess && (inputs.session === 'short' || inputs.session === 'browserLocked')) controls.add('session_controls');
    if (grantAccess && inputs.session === 'browserLocked') controls.add('persistent_browser');
    if (grantAccess && inputs.authRequirement === 'phishingResistantMfa') controls.add('phish_mfa');
    if (grantAccess && inputs.sensitivity === 'highlySensitive') controls.add(inputs.accountType === 'externalGuest' ? 'mfa' : 'phish_mfa');
    return [...controls].filter(id => CONTROLS[id]);
  }

  function scenarioTemplateControls(template, inputs) {
    const controls = new Set((template.controls || []).filter(id => !['mfa', 'phish_mfa'].includes(id)));
    if (inputs.authRequirement === 'phishingResistantMfa') controls.add('phish_mfa');
    else controls.add('mfa');
    return [...controls].filter(id => CONTROLS[id]);
  }

  function scenarioModifierControls(inputs) {
    const controls = [];
    if (inputs.platforms === 'unknownBlocked') controls.push('unknown_platforms');
    if (inputs.deviceTrust === 'managed') controls.push('device_compliance');
    if (inputs.location !== 'any') controls.push('trusted_location');
    if (inputs.riskTolerance === 'strict' && inputs.accountType !== 'externalGuest') controls.push('sign_in_risk');
    if (inputs.session === 'short' || inputs.session === 'browserLocked') controls.push('session_controls');
    if (inputs.session === 'browserLocked') controls.push('persistent_browser');
    return controls.filter(id => CONTROLS[id]);
  }

  function scenarioMitreIdsFromControls(controlIds) {
    const ids = new Set();
    MITRE_COVERAGE.forEach(item => {
      if ([...item.strongControls, ...item.partialControls].some(controlId => controlIds.includes(controlId))) ids.add(item.id);
    });
    return [...ids];
  }

  function scenarioMitreItem(id, controls) {
    const threat = THREATS.find(item => item.id === id);
    const coverage = mitreCoverageForControls(controls).find(item => item.id === id) || MITRE_COVERAGE.find(item => item.id === id);
    if (!threat && !coverage) return null;
    return {
      id,
      name: threat?.name || coverage.name,
      tactic: threat?.tactic || coverage.tactic,
      severity: threat?.severity || 'High',
      desc: threat?.desc || 'Mapped identity attack path influenced by the selected scenario controls.',
      status: coverage?.status || 'Partially mitigated',
      controls: coverage?.controls || []
    };
  }

  function scenarioMissingObjects(template, inputs) {
    const missing = [];
    if (!isGuid(inputs.groupId)) {
      missing.push({
        type: 'group',
        field: 'Target group object ID',
        name: inputs.groupName || template.groupName,
        help: 'Create the scenario security group, add the person, then paste the group object ID.'
      });
    }
    if ((template.requiresLocation || inputs.location !== 'any' || inputs.deviceTrust === 'trustedLocation') && !isGuid(inputs.locationId)) {
      missing.push({
        type: 'location',
        field: 'Trusted named location object ID',
        name: 'Trusted location for this scenario',
        help: 'Paste the named location object ID used for the trusted network boundary.'
      });
    }
    return missing;
  }

  function scenarioPolicies(template, inputs, controls, missing) {
    if (template.validationOnly) return [scenarioCorePolicy(template, inputs, controls, 'disabled')];
    const policies = [scenarioCorePolicy(template, inputs, controls, scenarioPolicyState(inputs))];
    if (controls.includes('sign_in_risk') && inputs.accountType !== 'externalGuest') {
      policies.push(scenarioRiskPolicy(template, inputs));
    }
    if (controls.includes('user_risk') && inputs.accountType !== 'externalGuest') {
      policies.push(scenarioUserRiskPolicy(template, inputs));
    }
    return policies.filter(Boolean).map((policy, index) => ({
      ...policy,
      sourceFile: `Scenario/ConditionalAccess/${policy.displayName}.json`,
      generated: true,
      consolidated: true,
      kind: 'scenario',
      represents: [],
      scenarioTemplate: template.id,
      scenarioMissingObjects: missing,
      rolloutDefault: scenarioRolloutDecision(inputs),
      order: index + 1
    }));
  }

  function scenarioCorePolicy(template, inputs, controls, stateValue) {
    const apps = scenarioApplications(inputs.resource);
    const groupId = inputs.groupId || scenarioPlaceholderId(inputs.groupName || template.groupName);
    const grantControls = scenarioGrantControls(template, inputs, controls);
    const policy = {
      id: template.policyId,
      persona: template.id === 'custom' ? scenarioPersona(inputs.accountType) : template.persona || scenarioPersona(inputs.accountType),
      displayName: `${template.policyId}-${template.policyName}`,
      risk: template.id === 'custom' ? scenarioRisk(inputs) : template.risk || scenarioRisk(inputs),
      summary: template.summary,
      prerequisites: [...GLOBAL_PREREQUISITES, ...(template.prerequisites || [])],
      requiredObjects: [inputs.groupName || template.groupName],
      controls: controls.filter(control => !['sign_in_risk', 'user_risk'].includes(control)),
      mergeReason: 'Generated as a focused scenario policy so the access path stays easy to review and remove.',
      separateReason: 'Risk/block controls stay separate when combining would change Conditional Access evaluation semantics.',
      preview: template.preview || inputs.resource === 'agentResources',
      policy: {
        displayName: `${template.policyId}-${template.policyName}`,
        state: stateValue,
        conditions: {
          clientAppTypes: scenarioClientApps(inputs),
          users: {
            includeGroups: [groupId],
            excludeGroups: ['2802b872-ccfb-4b29-a9a9-459808dfb11b']
          },
          applications: {
            includeApplications: apps
          }
        },
        grantControls
      }
    };
    scenarioApplyConditions(policy.policy.conditions, inputs);
    const session = scenarioSessionControls(inputs, controls);
    if (hasAny(Object.keys(session))) policy.policy.sessionControls = session;
    return policy;
  }

  function scenarioRiskPolicy(template, inputs) {
    const groupId = inputs.groupId || scenarioPlaceholderId(inputs.groupName || template.groupName);
    return {
      id: `${template.policyId}R`,
      persona: template.id === 'custom' ? scenarioPersona(inputs.accountType) : template.persona || scenarioPersona(inputs.accountType),
      displayName: `${template.policyId}R-${template.policyName}-HighSignInRisk`,
      risk: 'high',
      summary: 'Separate high sign-in risk guardrail for the scenario group.',
      prerequisites: [...GLOBAL_PREREQUISITES, 'Microsoft Entra ID Protection risk events reviewed'],
      requiredObjects: [inputs.groupName || template.groupName],
      controls: ['sign_in_risk'],
      mergeReason: 'Sign-in risk remains separate so risk response is clear and supportable.',
      separateReason: 'Risk controls should not be hidden inside the main grant/session policy.',
      policy: {
        displayName: `${template.policyId}R-${template.policyName}-HighSignInRisk`,
        state: scenarioPolicyState(inputs),
        conditions: {
          clientAppTypes: ['all'],
          signInRiskLevels: ['high'],
          users: {
            includeGroups: [groupId],
            excludeGroups: ['2802b872-ccfb-4b29-a9a9-459808dfb11b']
          },
          applications: {
            includeApplications: scenarioApplications(inputs.resource)
          }
        },
        grantControls: {
          operator: 'AND',
          builtInControls: ['block']
        }
      }
    };
  }

  function scenarioUserRiskPolicy(template, inputs) {
    const groupId = inputs.groupId || scenarioPlaceholderId(inputs.groupName || template.groupName);
    return {
      id: `${template.policyId}U`,
      persona: template.id === 'custom' ? scenarioPersona(inputs.accountType) : template.persona || scenarioPersona(inputs.accountType),
      displayName: `${template.policyId}U-${template.policyName}-HighUserRisk`,
      risk: 'high',
      summary: 'Separate high user-risk guardrail for the scenario group.',
      prerequisites: [...GLOBAL_PREREQUISITES, 'Microsoft Entra ID Protection user-risk detections reviewed'],
      requiredObjects: [inputs.groupName || template.groupName],
      controls: ['user_risk'],
      mergeReason: 'User risk remains separate so compromised-user response is independently testable.',
      separateReason: 'User risk and sign-in risk use different signals and should remain separate policies.',
      policy: {
        displayName: `${template.policyId}U-${template.policyName}-HighUserRisk`,
        state: scenarioPolicyState(inputs),
        conditions: {
          clientAppTypes: ['all'],
          userRiskLevels: ['high'],
          users: {
            includeGroups: [groupId],
            excludeGroups: ['2802b872-ccfb-4b29-a9a9-459808dfb11b']
          },
          applications: {
            includeApplications: scenarioApplications(inputs.resource)
          }
        },
        grantControls: {
          operator: 'AND',
          builtInControls: ['block']
        }
      }
    };
  }

  function scenarioPolicyState(inputs) {
    if (inputs.rollout === 'enabled') return 'enabled';
    if (inputs.rollout === 'disabled') return 'disabled';
    return 'enabledForReportingButNotEnforced';
  }

  function scenarioRolloutDecision(inputs) {
    if (inputs.rollout === 'enabled') return 'include';
    if (inputs.rollout === 'disabled') return 'exclude';
    return 'monitor';
  }

  function scenarioGrantControls(template, inputs, controls) {
    if (inputs.accessDecision === 'block') {
      return { operator: 'AND', builtInControls: ['block'] };
    }
    if (inputs.accountType === 'serviceAccount' && controls.includes('trusted_location')) {
      return { operator: 'AND', builtInControls: ['block'] };
    }
    if (scenarioUsesAuthenticationStrength(inputs, controls)) {
      const grant = { operator: controls.includes('device_compliance') ? 'AND' : 'OR', authenticationStrength: scenarioAuthenticationStrength(inputs, controls) };
      if (controls.includes('device_compliance')) grant.builtInControls = ['compliantDevice'];
      return grant;
    }
    const builtInControls = [];
    if (controls.includes('mfa') || controls.includes('guest_access') || controls.includes('admin_mfa')) builtInControls.push('mfa');
    if (controls.includes('device_compliance')) builtInControls.push('compliantDevice');
    if (!builtInControls.length) builtInControls.push('mfa');
    return { operator: builtInControls.length > 1 ? 'AND' : 'OR', builtInControls };
  }

  function scenarioUsesAuthenticationStrength(inputs, controls) {
    return inputs.authRequirement === 'passwordlessMfa' || inputs.authRequirement === 'phishingResistantMfa' || controls.includes('phish_mfa');
  }

  function scenarioAuthenticationStrength(inputs, controls) {
    if (inputs.authRequirement === 'passwordlessMfa' && !controls.includes('phish_mfa')) {
      return {
        displayName: 'Passwordless MFA',
        description: 'Passwordless authentication methods such as Windows Hello for Business, FIDO2 security keys, or certificate-based authentication.',
        policyType: 'builtIn',
        requirementsSatisfied: 'mfa',
        allowedCombinations: [
          'windowsHelloForBusiness',
          'fido2',
          'x509CertificateMultiFactor',
          'microsoftAuthenticatorPush'
        ]
      };
    }
    return clone(policiesById('CA105')[0].policy.grantControls.authenticationStrength);
  }

  function scenarioApplyConditions(conditions, inputs) {
    if (inputs.platforms === 'windows') conditions.platforms = { includePlatforms: ['windows'] };
    if (inputs.platforms === 'mobile') conditions.platforms = { includePlatforms: ['iOS', 'android'] };
    if (inputs.platforms === 'unknownBlocked') conditions.platforms = { includePlatforms: ['all'], excludePlatforms: ['windows', 'macOS', 'iOS', 'android', 'linux'] };
    if (inputs.location === 'trustedOnly' || inputs.deviceTrust === 'trustedLocation') {
      conditions.locations = { includeLocations: ['All'], excludeLocations: [inputs.locationId || scenarioPlaceholderId('Trusted named location')] };
    } else if (inputs.location === 'excludeTrusted') {
      conditions.locations = { includeLocations: ['All'], excludeLocations: [inputs.locationId || scenarioPlaceholderId('Trusted named location')] };
    }
    if (inputs.resource === 'agentResources') {
      conditions.applications = { includeApplications: ['AllAgentIdResources'] };
    }
  }

  function scenarioSessionControls(inputs, controls) {
    const session = {};
    if (inputs.accessDecision === 'block') return session;
    if (controls.includes('session_controls') || inputs.session === 'short' || inputs.session === 'browserLocked') {
      session.signInFrequency = {
        value: inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive' ? 4 : 8,
        type: 'hours',
        authenticationType: 'primaryAndSecondaryAuthentication',
        frequencyInterval: 'timeBased',
        isEnabled: true
      };
    }
    if (controls.includes('persistent_browser') || inputs.session === 'browserLocked') {
      session.persistentBrowser = { mode: 'never', isEnabled: true };
    }
    if (inputs.deviceTrust === 'browserOnly' || inputs.session === 'browserLocked') {
      session.applicationEnforcedRestrictions = { isEnabled: true };
    }
    return session;
  }

  function scenarioClientApps(inputs) {
    if (inputs.deviceTrust === 'browserOnly' || inputs.session === 'browserLocked') return ['browser'];
    if (inputs.resource === 'exchange' && inputs.deviceTrust === 'unmanaged') return ['browser', 'mobileAppsAndDesktopClients'];
    return ['all'];
  }

  function scenarioApplications(resource) {
    if (resource === 'sharepoint') return ['00000003-0000-0ff1-ce00-000000000000'];
    if (resource === 'exchange') return ['00000002-0000-0ff1-ce00-000000000000'];
    if (resource === 'office365') return ['Office365'];
    if (resource === 'adminPortals') return ['MicrosoftAdminPortals'];
    if (resource === 'agentResources') return ['AllAgentIdResources'];
    return ['All'];
  }

  function scenarioApplicationLabel(value) {
    const entry = manualTokenEntry(value, 'applications', null);
    return entry.name || entry.text || value;
  }

  function scenarioDynamicPrerequisites(template, inputs, missing) {
    const items = [];
    if (missing.length) items.push(...missing.map(item => `${item.field}: ${item.help}`));
    if (inputs.duration === 'temporary') items.push('Set an expiry date and access-review owner for the scenario group.');
    if (inputs.duration === 'ongoing') items.push('Document the scenario group owner, business reason, and membership review cadence for ongoing access.');
    if (inputs.duration === 'emergency') items.push('Confirm this is validation-only emergency access and does not enforce controls that could block break-glass sign-in.');
    if (inputs.resource === 'sharepoint') items.push('Use SharePoint permissions, sensitivity labels, and sharing settings to scope the actual folder or site.');
    if (inputs.resource === 'exchange' && inputs.deviceTrust === 'browserOnly') items.push('Confirm browser-based Microsoft 365 mail access is acceptable before blocking or discouraging desktop app use.');
    return items;
  }

  function scenarioDynamicGuidance(template, inputs) {
    const items = [];
    const recommendedSession = recommendedScenarioSession(inputs);
    const recommendedDuration = recommendedScenarioDuration(template, inputs);
    if (inputs.session !== recommendedSession) items.push(`Session strictness recommendation: consider ${SESSION_STRICTNESS_HELP[recommendedSession].title} for this scenario.`);
    if (inputs.duration !== recommendedDuration) items.push(`Access duration recommendation: consider ${ACCESS_DURATION_HELP[recommendedDuration].title} for this scenario.`);
    if (inputs.accountType === 'externalGuest') items.push('Resource tenant MFA is responsible for external guest access unless cross-tenant trust is explicitly configured.');
    if (inputs.accountType === 'externalGuest' && inputs.deviceTrust === 'managed') items.push('Only require compliant device for guests when you have a proven device trust model for that guest population.');
    if (inputs.deviceTrust === 'unmanaged') items.push('Treat unmanaged device access as an exception and prefer browser/app protection controls over full desktop client access.');
    if (inputs.sensitivity === 'highlySensitive') items.push('Use stricter authentication, shorter sessions, and an explicit owner for exception removal.');
    return items;
  }

  function scenarioWarnings(template, inputs, missing) {
    const warnings = [];
    if (missing.length) warnings.push(`Apply/export is blocked until ${missing.map(item => item.field).join(', ')} is supplied.`);
    if (inputs.resource === 'sharepoint') warnings.push('Conditional Access cannot target a specific SharePoint folder. Use SharePoint permissions and site controls for the folder boundary.');
    if (inputs.resource === 'exchange' && inputs.deviceTrust === 'unmanaged') warnings.push('Unmanaged desktop app access is weaker than browser-only access unless app protection or device compliance is available.');
    if (template.preview || inputs.resource === 'agentResources') warnings.push('Agent scenarios use preview/beta-shaped Conditional Access fields and require tenant capability validation.');
    if (template.validationOnly) warnings.push('Break-glass validation policies should remain disabled or report-only and must not block emergency access.');
    return warnings;
  }

  function renderScenarioSessionHelp(plan) {
    const inputs = plan.inputs;
    const selected = SESSION_STRICTNESS_HELP[inputs.session] || SESSION_STRICTNESS_HELP.standard;
    const recommended = recommendedScenarioSession(inputs);
    const recommendedHelp = SESSION_STRICTNESS_HELP[recommended] || SESSION_STRICTNESS_HELP.standard;
    const settings = scenarioSessionSettingsSummary(inputs, plan.controls);
    return renderScenarioChoiceHelp({
      selected: selected.title,
      meaning: selected.meaning,
      recommended: selected.recommended,
      isRecommended: inputs.session === recommended,
      recommendation: recommendedHelp.title,
      effectTitle: 'Conditional Access effect',
      effects: settings
    });
  }

  function renderScenarioDurationHelp(plan) {
    const inputs = plan.inputs;
    const selected = ACCESS_DURATION_HELP[inputs.duration] || ACCESS_DURATION_HELP.temporary;
    const recommended = recommendedScenarioDuration(plan.template, inputs);
    const recommendedHelp = ACCESS_DURATION_HELP[recommended] || ACCESS_DURATION_HELP.temporary;
    return renderScenarioChoiceHelp({
      selected: selected.title,
      meaning: selected.meaning,
      recommended: selected.recommended,
      isRecommended: inputs.duration === recommended,
      recommendation: recommendedHelp.title,
      effectTitle: 'Operational effect',
      effects: scenarioDurationEffectSummary(plan.template, inputs)
    });
  }

  function renderScenarioChoiceHelp({ selected, meaning, recommended, isRecommended, recommendation, effectTitle, effects }) {
    return `<div class="scenario-choice-help-head">
      <strong>${esc(selected)}</strong>
      <span class="status-chip ${isRecommended ? 'generated' : 'monitor'}">${esc(isRecommended ? 'Recommended for this scenario' : `Consider ${recommendation}`)}</span>
    </div>
    <p>${esc(meaning)}</p>
    <dl>
      <dt>Recommended when</dt><dd>${esc(recommended)}</dd>
      <dt>${esc(effectTitle)}</dt><dd>${esc(effects)}</dd>
    </dl>`;
  }

  function recommendedScenarioSession(inputs) {
    if (inputs.deviceTrust === 'browserOnly') return 'browserLocked';
    if (inputs.deviceTrust === 'unmanaged' && ['sharepoint', 'exchange', 'office365'].includes(inputs.resource)) return 'browserLocked';
    if (inputs.accountType === 'admin' || inputs.sensitivity === 'highlySensitive' || inputs.duration === 'temporary' || inputs.accountType === 'externalGuest') return 'short';
    return 'standard';
  }

  function recommendedScenarioDuration(template, inputs) {
    if (template.validationOnly || inputs.duration === 'emergency') return 'emergency';
    if (inputs.accountType === 'serviceAccount') return 'ongoing';
    if (inputs.accountType === 'externalGuest' || inputs.accountType === 'admin' || inputs.sensitivity !== 'standard' || inputs.deviceTrust === 'unmanaged' || inputs.deviceTrust === 'browserOnly') return 'temporary';
    return 'ongoing';
  }

  function scenarioSessionSettingsSummary(inputs, controls) {
    const session = scenarioSessionControls(inputs, controls);
    const settings = [];
    if (session.signInFrequency) settings.push(`Sign-in frequency: ${formatSignInFrequency(session.signInFrequency).replace(/\n/g, '; ')}`);
    if (session.persistentBrowser) settings.push(`Persistent browser: ${formatPersistentBrowser(session.persistentBrowser).replace(/\n/g, '; ')}`);
    if (session.applicationEnforcedRestrictions?.isEnabled) settings.push('App-enforced restrictions: enabled for supported browser apps');
    if (!settings.length) return 'No additional session control is generated; leave session controls unchanged unless another requirement demands them.';
    return settings.join('. ');
  }

  function scenarioDurationEffectSummary(template, inputs) {
    if (template.validationOnly || inputs.duration === 'emergency') {
      return 'Do not use this as normal access. Keep validation disabled or report-only, test emergency sign-in separately, and alert on use.';
    }
    if (inputs.duration === 'temporary') {
      return 'Not a Graph Conditional Access field. Add group expiry, named owner, ticket/change reference, review date, and removal criteria before enabling.';
    }
    return 'Not a Graph Conditional Access field. Document owner, business reason, membership review cadence, and evidence that access remains required.';
  }

  function renderScenarioSummary(plan) {
    return `<div class="strategy-score-grid primary-metrics">
      <article><span>Policies to manage</span><strong>${esc(plan.policies.length)}</strong><em>${esc(plan.policies.length === 1 ? 'One focused access policy' : 'Controls kept separate where required')}</em></article>
      <article><span>MITRE coverage</span><strong>${esc(plan.score)}%</strong><em>${esc(scenarioAddressedMitre(plan).length)}/${esc((plan.fullMitre || []).length)} addressed</em></article>
    </div>
    <div class="strategy-context-line"><strong>${esc(plan.template.risk || scenarioRisk(plan.inputs))} risk</strong><span>${esc(plan.inputs.sensitivity)} data - ${esc(ACCESS_DURATION_HELP[plan.inputs.duration]?.title || plan.inputs.duration)}</span></div>
    <p>${esc(plan.template.summary)} Scenario groups keep the access path easy to review, expire, and remove.</p>`;
  }

  function renderScenarioPrepareSummary(plan) {
    const objectState = plan.canApply
      ? '<div class="strategy-applied">All required tenant objects are present. The scenario is ready for policy review and Graph export.</div>'
      : `<div class="scenario-object-warning">${plan.missing.map(item => `<strong>${esc(item.field)}</strong><span>${esc(item.help)}</span>`).join('')}</div>`;
    return `<div class="prepare-summary-head"><strong>${esc(plan.policies.length)} polic${plan.policies.length === 1 ? 'y' : 'ies'} ready for review</strong><span>${esc(plan.inputs.groupName || plan.template.groupName)}</span></div>${objectState}`;
  }

  function renderScenarioMitre(plan) {
    const addressed = scenarioAddressedMitre(plan);
    const gaps = scenarioUnaddressedMitre(plan);
    const chips = addressed.map(item => `<article class="attack-vector-card attack-${esc(item.status.toLowerCase().replace(/[^a-z0-9]+/g, '-'))}">
      <div class="attack-vector-top">
        <span class="technique">${esc(item.id)}</span>
        <span class="risk-pill ${esc(item.severity.toLowerCase())}">${esc(item.severity)}</span>
      </div>
      <strong>${esc(item.name)}</strong>
      <span>${esc(item.tactic)}</span>
      <p>${esc(item.desc)}</p>
      <div class="attack-vector-meta">
        <em>${esc(item.status)}</em>
        <small>${esc((item.controls || []).join(', ') || 'Scenario guidance')}</small>
      </div>
    </article>`).join('');
    const gapCards = gaps.map(item => mitreGapCard(
      item,
      item.status === 'Requires another control'
        ? 'Needs supporting controls outside this scenario policy.'
        : 'No selected scenario control maps to this technique.'
    )).join('');
    return `<div class="attack-vector-summary">
      <span class="metric-label">Scenario MITRE score</span>
      <strong>${esc(plan.score)}%</strong>
      <p>${esc(addressed.length)} addressed and ${esc(gaps.length)} not addressed across the curated identity-focused ATT&CK set. Conditional Access does not solve every technique alone.</p>
    </div>
    <div class="mitre-coverage-split">
      <section>
        <div class="mitre-split-head"><strong>Addressed by this policy pack</strong><span>${esc(addressed.length)}</span></div>
        <div class="attack-vector-list">${chips || '<div class="empty-state">No MITRE techniques are currently addressed by this scenario.</div>'}</div>
      </section>
      <section>
        <div class="mitre-split-head"><strong>Not addressed by this policy pack</strong><span>${esc(gaps.length)}</span></div>
        <div class="mitre-gap-list">${gapCards || '<div class="empty-state">No uncovered techniques in the curated identity set.</div>'}</div>
      </section>
    </div>`;
  }

  function scenarioAddressedMitre(plan) {
    const full = plan.fullMitre || mitreCoverageForControls(plan.controls || []);
    return full
      .filter(item => item.status === 'Strongly mitigated' || item.status === 'Partially mitigated')
      .map(item => scenarioMitreItem(item.id, plan.controls) || item);
  }

  function scenarioUnaddressedMitre(plan) {
    const full = plan.fullMitre || mitreCoverageForControls(plan.controls || []);
    return full
      .filter(item => item.status === 'Requires another control' || item.status === 'Not addressed by Conditional Access')
      .map(item => scenarioMitreItem(item.id, plan.controls) || item);
  }

  function mitreGapCard(item, fallback) {
    return `<article class="mitre-gap-card attack-${esc(item.status.toLowerCase().replace(/[^a-z0-9]+/g, '-'))}">
      <div>
        <span class="technique">${esc(item.id)}</span>
        <strong>${esc(item.name)}</strong>
      </div>
      <span>${esc(item.tactic || 'Identity threat')}</span>
      <p>${esc(fallback)}</p>
    </article>`;
  }

  function renderScenarioPolicyPack(plan) {
    if (!plan.policies.length) return '<div class="empty-state">This scenario is guidance-only and does not generate an exportable policy.</div>';
    return plan.policies.map((policy, index) => `<div class="strategy-policy-card scenario-policy-card">
      <div class="strategy-policy-top">
        <div>
          <span class="strategy-step-label">Step ${esc(index + 1)}</span>
          <strong>${esc(policy.displayName)}</strong>
        </div>
        <span class="status-chip ${isPreviewPolicy(policy) ? 'beta' : 'generated'}">${esc(isPreviewPolicy(policy) ? 'Preview/beta' : 'Scenario')}</span>
      </div>
      <dl>
        <dt>Purpose</dt><dd>${esc(policy.summary)}</dd>
        <dt>Target group</dt><dd>${esc(plan.inputs.groupName || plan.template.groupName)}${plan.inputs.groupId ? ' - ready for export' : ' - object ID required later'}</dd>
        <dt>Apps/resources</dt><dd>${esc(scenarioApplications(plan.inputs.resource).map(scenarioApplicationLabel).join(', '))}</dd>
        <dt>Access control</dt><dd>${esc(scenarioGrantSummary(policy.policy?.grantControls || {}))}</dd>
        <dt>Controls</dt><dd>${esc(policy.controls.map(id => CONTROLS[id]?.label).filter(Boolean).join(', ') || 'Scenario controls')}</dd>
        <dt>Why separate</dt><dd>${esc(policy.separateReason || 'Kept focused so this access path remains easy to review and remove.')}</dd>
        <dt>Rollout</dt><dd>${esc(decisionLabel(policy.rolloutDefault || 'monitor'))}</dd>
        <dt class="expert-only">Build note</dt><dd class="expert-only">${esc(buildStepSummary(policy))}</dd>
      </dl>
      <div class="expert-only">${scenarioPolicySettings(policy, plan)}</div>
      <button class="btn tiny" type="button" data-scenario-open="${esc(policyKey(policy))}">Open build guide</button>
    </div>`).join('');
  }

  function scenarioPolicySettings(policy, plan) {
    const shape = policy.policy || {};
    const conditions = shape.conditions || {};
    const grant = shape.grantControls || {};
    const session = shape.sessionControls || {};
    const users = conditions.users || {};
    const apps = conditions.applications || {};
    const blockers = scenarioPolicyBlockers(policy, plan);
    return `<div class="scenario-settings-grid">
      ${scenarioSettingCard('Assignments', [
        ['Include groups', scenarioEntryList(users.includeGroups, 'groups')],
        ['Exclude groups', scenarioEntryList(users.excludeGroups, 'groups')],
        ['Roles/users', scenarioAssignmentScope(users)]
      ])}
      ${scenarioSettingCard('Target resources', [
        ['Include resources', scenarioEntryList(apps.includeApplications, 'applications')],
        ['Exclude resources', scenarioEntryList(apps.excludeApplications, 'applications')]
      ])}
      ${scenarioSettingCard('Conditions', [
        ['Client apps', scenarioEntryList(conditions.clientAppTypes, 'clientApps')],
        ['Platforms', scenarioPlatformSummary(conditions.platforms)],
        ['Locations', scenarioLocationSummary(conditions.locations)],
        ['Risk', scenarioRiskConditionSummary(conditions)]
      ])}
      ${scenarioSettingCard('Grant controls', [
        ['Access result', grantAccessResult(grant)],
        ['Operator', grant.operator ? grantOperatorLabel(grant.operator) : 'Not configured'],
        ['MFA strength', scenarioGrantSummary(grant)],
        ['Device/app grant', scenarioDeviceGrantSummary(grant)]
      ])}
      ${scenarioSettingCard('Session controls', [
        ['Sign-in frequency', session.signInFrequency ? formatSignInFrequency(session.signInFrequency) : 'Not configured'],
        ['Persistent browser', session.persistentBrowser ? formatPersistentBrowser(session.persistentBrowser) : 'Not configured'],
        ['App restrictions', session.applicationEnforcedRestrictions?.isEnabled ? 'App-enforced restrictions enabled' : 'Not configured']
      ])}
      ${scenarioSettingCard('Prerequisites and blockers', [
        ['Object status', blockers.length ? blockers.join('; ') : 'Required object IDs supplied'],
        ['Known limitation', scenarioKnownLimitation(plan.inputs)]
      ])}
    </div>`;
  }

  function scenarioSettingCard(title, rows) {
    return `<section class="scenario-setting-card">
      <strong>${esc(title)}</strong>
      <dl>${rows.map(([label, value]) => `<dt>${esc(label)}</dt><dd>${esc(value || 'Not configured')}</dd>`).join('')}</dl>
    </section>`;
  }

  function scenarioEntryList(values, context) {
    if (!Array.isArray(values) || !values.length) return 'Not configured';
    return values.map(value => {
      const entry = manualTokenEntry(value, context, null);
      return entry.name ? `${entry.name} (${entry.id})` : entry.text || value;
    }).join(', ');
  }

  function scenarioAssignmentScope(users) {
    const roles = scenarioEntryList(users.includeRoles, 'roles');
    const usersText = scenarioEntryList(users.includeUsers, 'users');
    return roles !== 'Not configured' ? roles : usersText;
  }

  function scenarioPlatformSummary(platforms = {}) {
    const include = scenarioEntryList(platforms.includePlatforms, 'platforms');
    const exclude = scenarioEntryList(platforms.excludePlatforms, 'platforms');
    if (include === 'Not configured' && exclude === 'Not configured') return 'Any platform';
    return `Include: ${include}; Exclude: ${exclude}`;
  }

  function scenarioLocationSummary(locations = {}) {
    const include = scenarioEntryList(locations.includeLocations, 'locations');
    const exclude = scenarioEntryList(locations.excludeLocations, 'locations');
    if (include === 'Not configured' && exclude === 'Not configured') return 'Any location';
    return `Include: ${include}; Exclude: ${exclude}`;
  }

  function scenarioRiskConditionSummary(conditions) {
    const signIn = scenarioEntryList(conditions.signInRiskLevels, 'riskLevels');
    const user = scenarioEntryList(conditions.userRiskLevels, 'riskLevels');
    const agent = scenarioEntryList(conditions.agentIdRiskLevels, 'riskLevels');
    const configured = [
      signIn !== 'Not configured' ? `Sign-in: ${signIn}` : '',
      user !== 'Not configured' ? `User: ${user}` : '',
      agent !== 'Not configured' ? `Agent: ${agent}` : ''
    ].filter(Boolean);
    return configured.join('; ') || 'Not configured';
  }

  function scenarioGrantSummary(grant) {
    if (grant.authenticationStrength) return formatAuthenticationStrength(grant.authenticationStrength).split('\n')[0];
    if (grant.builtInControls?.includes('mfa')) return 'Require multifactor authentication';
    if (grant.builtInControls?.includes('block')) return 'Block access';
    return 'Not configured';
  }

  function scenarioDeviceGrantSummary(grant) {
    const controls = grant.builtInControls || [];
    const labels = controls
      .filter(control => control !== 'mfa' && control !== 'block')
      .map(control => manualLiteralTokenLabel(String(control).toLowerCase(), control, 'grantControls'));
    return labels.join(', ') || 'Not configured';
  }

  function scenarioPolicyBlockers(policy, plan) {
    const blockers = [];
    if (plan.missing.length) blockers.push(...plan.missing.map(item => `${item.field} required`));
    if (policy.policy?.conditions?.applications?.includeApplications?.includes('AllAgentIdResources')) blockers.push('Preview/beta agent resource targeting');
    return blockers;
  }

  function scenarioKnownLimitation(inputs) {
    if (inputs.resource === 'sharepoint') return 'Conditional Access cannot target one SharePoint folder; use SharePoint permissions for the folder boundary.';
    if (inputs.resource === 'exchange' && inputs.deviceTrust !== 'managed') return 'Unmanaged desktop app access is weaker than browser/app-restricted access.';
    if (inputs.resource === 'agentResources') return 'Agent resource controls may require Microsoft Graph beta/preview support.';
    return 'No scenario-specific limitation recorded.';
  }

  function scenarioAuthRequirementLabel(value) {
    if (value === 'phishingResistantMfa') return 'Phishing-resistant MFA strength';
    if (value === 'passwordlessMfa') return 'Passwordless MFA strength';
    return 'Standard MFA';
  }

  function scenarioChecklist(items) {
    return items.length
      ? `<ul class="check-list">${items.map(item => `<li>${esc(item)}</li>`).join('')}</ul>`
      : '<div class="empty-state">No additional items for this scenario.</div>';
  }

  function scenarioPersona(accountType) {
    if (accountType === 'admin') return 'Admins';
    if (accountType === 'externalGuest') return 'Guests';
    if (accountType === 'serviceAccount') return 'Service Accounts';
    if (accountType === 'agentIdentity') return 'Agents';
    return 'Internals';
  }

  function scenarioRisk(inputs) {
    if (inputs.sensitivity === 'highlySensitive' || inputs.accountType === 'admin' || inputs.accountType === 'agentIdentity') return 'critical';
    if (inputs.deviceTrust === 'unmanaged' || inputs.accountType === 'externalGuest') return 'high';
    return 'medium';
  }

  function scenarioPlaceholderId(label) {
    return `REPLACE-${String(label || 'SCENARIO-OBJECT').toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
  }

  function isGuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || '').trim());
  }

  function syncScenarioObjectCatalog() {
    if (isGuid(state.scenario.groupId) && state.scenario.groupName) {
      state.objectCatalog.set(objectCatalogKey(state.scenario.groupId, 'group'), {
        id: state.scenario.groupId,
        type: 'group',
        name: state.scenario.groupName,
        source: 'scenario'
      });
    }
    if (isGuid(state.scenario.locationId)) {
      state.objectCatalog.set(objectCatalogKey(state.scenario.locationId, 'location'), {
        id: state.scenario.locationId,
        type: 'location',
        name: 'Scenario trusted named location',
        source: 'scenario'
      });
    }
  }

  function renderStrategyAttackVectors(plan) {
    const threats = strategyAttackVectors(plan);
    const gaps = plan.empty ? [] : strategyUnaddressedMitre(plan);
    const summary = plan.empty
      ? threats.length
        ? `${threats.length} advanced threat${threats.length === 1 ? '' : 's'} selected. Choose a requirement to convert these attack paths into a consolidated policy design.`
        : 'Select one or more requirements to see the attack vectors this consolidated strategy is designed to reduce.'
      : `${threats.length} attack vector${threats.length === 1 ? '' : 's'} mapped from ${plan.selectedRequirements.length} selected requirement${plan.selectedRequirements.length === 1 ? '' : 's'}. MITRE coverage scores the curated identity-focused ATT&CK set, including gaps not covered by the selected policies.`;
    const chips = threats.map(item => `<article class="attack-vector-card attack-${esc(item.statusClass)}">
      <div class="attack-vector-top">
        <span class="technique">${esc(item.id)}</span>
        <span class="risk-pill ${esc(item.severity.toLowerCase())}">${esc(item.severity)}</span>
      </div>
      <strong>${esc(item.name)}</strong>
      <span>${esc(item.tactic)}</span>
      <p>${esc(item.desc)}</p>
      <div class="attack-vector-meta">
        <em>${esc(item.status)}</em>
        <small>${esc(item.sources.join(' + '))}</small>
      </div>
    </article>`).join('');
    const gapCards = gaps.map(item => mitreGapCard(item, 'Not covered by the selected strategy controls.')).join('');
    $('strategyAttackVectors').innerHTML = `<div class="attack-vector-summary">
      <span class="metric-label">MITRE coverage</span>
      <strong>${esc(plan.score)}%</strong>
      <p>${esc(summary)}</p>
    </div>
    <div class="mitre-coverage-split">
      <section>
        <div class="mitre-split-head"><strong>Addressed by selected policies</strong><span>${esc(threats.length)}</span></div>
        <div class="attack-vector-list">${chips || '<div class="empty-state">No attack vectors selected yet. Tick a requirement such as Privileged admin hardening to see the MITRE-relevant threats it addresses.</div>'}</div>
      </section>
      <section>
        <div class="mitre-split-head"><strong>Not addressed by selected policies</strong><span>${esc(gaps.length)}</span></div>
        <div class="mitre-gap-list">${gapCards || '<div class="empty-state">No uncovered techniques in the curated identity set.</div>'}</div>
      </section>
    </div>`;
  }

  function strategyAttackVectors(plan) {
    const details = new Map();
    const add = (threatId, source) => {
      if (!details.has(threatId)) details.set(threatId, new Set());
      details.get(threatId).add(source);
    };
    plan.selectedRequirements.forEach(key => {
      const requirement = STRATEGY_REQUIREMENTS[key];
      requirement?.threats?.forEach(threatId => add(threatId, requirement.label));
    });
    state.selectedThreats.forEach(threatId => add(threatId, 'Advanced threat model'));
    return [...details.entries()].map(([threatId, sources]) => {
      const threat = THREATS.find(item => item.id === threatId);
      const coverage = plan.mitre.find(item => item.id === threatId);
      const status = coverage?.status || 'Requires another control';
      return {
        id: threatId,
        name: threat?.name || coverage?.name || threatId,
        tactic: threat?.tactic || coverage?.tactic || 'Identity threat',
        severity: threat?.severity || (status === 'Strongly mitigated' ? 'Medium' : 'High'),
        desc: threat?.desc || 'Mapped identity attack path influenced by the selected Conditional Access strategy.',
        status,
        statusClass: status.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        sources: [...sources]
      };
    }).sort((a, b) => a.id.localeCompare(b.id));
  }

  function strategyUnaddressedMitre(plan) {
    return (plan.mitre || [])
      .filter(item => item.status === 'Requires another control' || item.status === 'Not addressed by Conditional Access')
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  function strategyEmptyState(plan) {
    const legacyText = plan.requirements.legacyExceptions
      ? '<span>Legacy-auth exceptions are noted, but they do not create a policy until a real access requirement is selected.</span>'
      : '<span>Choose the identity and access areas you actually want to protect. Strictness only tunes those choices.</span>';
    return `<div class="strategy-empty-callout">
      <strong>Select a requirement to design policies</strong>
      ${legacyText}
    </div>`;
  }

  function strategyBuildOrder(plan) {
    const policies = plan.consolidatedPolicies;
    if (!policies.length) return '';
    const items = policies.map((policy, index) => strategyPolicyCard(policy, plan, index)).join('');
    return `<div class="strategy-build-order">
      <strong>Build these policies in order</strong>
      <div class="strategy-build-list">${items}</div>
    </div>`;
  }

  function policySavingsText(plan) {
    if (plan.empty) return 'Select requirements to generate policies';
    const savings = Math.max(0, plan.equivalentPolicies.length - plan.consolidatedPolicies.length);
    if (!savings) return `${plan.equivalentPolicies.length} baseline policies represented`;
    return `${plan.equivalentPolicies.length} baseline policies represented, ${savings} fewer to manage`;
  }

  function mitreSummaryText(plan) {
    if (plan.empty) return 'No requirements selected';
    const strong = plan.mitre.filter(item => item.status === 'Strongly mitigated').length;
    return `${strong}/${plan.mitre.length} strong or better`;
  }

  function frictionLabel(score) {
    if (score === 0) return 'No selected policy impact';
    if (score >= 75) return 'High user and operations impact';
    if (score >= 48) return 'Moderate rollout impact';
    return 'Lower rollout impact';
  }

  function rolloutLabel(value, empty = false) {
    if (empty) return 'No rollout until requirements are selected';
    if (value === 'fast') return 'Enable core controls after validation';
    if (value === 'cautious') return 'Report-only before enforcement';
    return 'Report-only for high-impact controls';
  }

  function strategyPolicyCard(policy, plan, index = 0) {
    const policyControls = strategyControlsForPolicy(policy, plan);
    const mitre = plan.mitre
      .filter(item => item.controls.some(label => policyControls.includes(label)))
      .slice(0, 3)
      .map(item => item.id)
      .join(', ') || 'Coverage support';
    const represented = representedPolicyText(policy);
    const key = policyKey(policy);
    const guideAction = policy.consolidated
      ? `<button class="btn tiny" type="button" data-strategy-open="${esc(key)}">Open build guide</button>`
      : '';
    const rollout = decisionLabel(strategyDecisionForPolicy(policy, plan));
    return `<div class="strategy-policy-card">
      <div class="strategy-policy-top">
        <div>
          <span class="strategy-step-label">Step ${esc(index + 1)}</span>
          <strong>${esc(policy.displayName)}</strong>
        </div>
        <span class="status-chip">${esc(policy.consolidated ? 'Consolidated' : isPreviewPolicy(policy) ? 'Preview/beta' : 'Baseline')}</span>
      </div>
      <dl class="strategy-policy-essentials">
        <dt>Purpose</dt><dd>${esc(strategyReasonForPolicy(policy, plan))}</dd>
        <dt>Target</dt><dd>${esc(strategyPolicyTarget(policy))}</dd>
        <dt>Controls</dt><dd>${esc(policyControls.join(', ') || 'Policy-specific controls')}</dd>
        <dt>Why separate</dt><dd>${esc(strategyMergeDecision(policy))}</dd>
        <dt>Rollout</dt><dd>${esc(rollout)}</dd>
      </dl>
      <dl class="strategy-policy-trace expert-only">
        <dt>Manual build</dt><dd>${esc(buildStepSummary(policy))}</dd>
        <dt>Requirement</dt><dd>${esc(strategyRequirementForPolicy(policy, plan))}</dd>
        <dt>Represents</dt><dd>${esc(represented)}</dd>
        <dt>MITRE</dt><dd>${esc(mitre)}</dd>
      </dl>
      ${guideAction}
    </div>`;
  }

  function strategyPolicyTarget(policy) {
    const conditions = policy.policy?.conditions || {};
    const apps = conditions.applications?.includeApplications || [];
    const appText = apps.length
      ? apps.map(value => scenarioApplicationLabel(value)).join(', ')
      : 'Configured target resources';
    return `${policy.persona || 'Selected identities'} - ${appText}`;
  }

  function buildStepSummary(policy) {
    if (policy.kind === 'scenario') return policy.summary || 'Create this focused scenario policy, confirm object IDs, then validate with What If and sign-in logs.';
    if (policy.controls?.includes('sign_in_risk')) return 'Create this as a separate sign-in risk policy so Microsoft risk evaluation stays clear and supportable.';
    if (policy.controls?.includes('user_risk')) return 'Create this as a separate user risk policy so compromised-user response remains independent from sign-in risk.';
    if (isBlockPolicy(policy)) return 'Create this as a separate Block access policy, validate exclusions in report-only, then enable after sign-in log review.';
    if (policy.persona === 'Admins') return 'Create the admin assignment, require the selected MFA strength, add session controls, then confirm break-glass exclusions.';
    if (policy.persona === 'Agents') return 'Validate preview/beta support, configure agent identity targeting, then test with representative agent resources.';
    if (policy.persona === 'Internals') return 'Create the broad workforce policy, add exclusions, configure grant/session controls, then pilot by group.';
    if (policy.persona === 'Guests') return 'Target guest or external users, configure MFA/session controls, then test partner collaboration paths.';
    if (policy.persona === 'Service Accounts') return 'Target the service account population, confirm owner and exception boundaries, then monitor before enforcement.';
    return 'Create assignments, target resources, conditions, access controls, session controls, exclusions, then validate with What If.';
  }

  function strategyControlsForPolicy(policy, plan) {
    if (policy.controls?.length) {
      return policy.controls.map(controlId => CONTROLS[controlId]?.label).filter(Boolean);
    }
    return plan.controls
      .filter(controlId => CONTROLS[controlId]?.policyIds.includes(policy.id))
      .map(controlId => CONTROLS[controlId].label);
  }

  function strategyReasonForPolicy(policy, plan) {
    const controls = strategyControlsForPolicy(policy, plan);
    if (controls.length) return controls.slice(0, 4).join(', ');
    return policy.summary || 'Baseline policy selected for this strategy.';
  }

  function strategyRequirementForPolicy(policy, plan) {
    if (policy.controls?.length) {
      const reasons = new Set();
      policy.controls.forEach(controlId => {
        (plan.controlReasons.get(controlId) || []).forEach(reason => reasons.add(reason));
      });
      return [...reasons].slice(0, 3).join(', ') || plan.level.label;
    }
    const reasons = new Set();
    plan.controls
      .filter(controlId => CONTROLS[controlId]?.policyIds.includes(policy.id))
      .forEach(controlId => {
        (plan.controlReasons.get(controlId) || []).forEach(reason => reasons.add(reason));
      });
    return [...reasons].slice(0, 3).join(', ') || plan.level.label;
  }

  function strategyMergeDecision(policy) {
    if (policy.consolidated) return policy.mergeReason || 'Consolidated strategy policy generated from compatible baseline controls.';
    if (isPreviewPolicy(policy)) return 'Kept separate because it uses agent preview/beta targeting.';
    if (isBlockPolicy(policy)) return 'Kept separate because block policies should not be merged into grant policies.';
    if (policy.sessionControls) return 'Kept readable because session controls differ by target and rollout risk.';
    return 'Baseline policy reused; no extra generated merge needed.';
  }

  function representedPolicyText(policy) {
    const represented = policy.represents || [];
    if (!represented.length) return 'No baseline policy mapping recorded.';
    return represented.join(', ');
  }

  function strategyRepresentationCard(policy) {
    const represented = (policy.represents || []).flatMap(id => policiesById(id));
    const representedList = represented.length
      ? represented.map(item => `<li><strong>${esc(item.id)}</strong><span>${esc(item.displayName)}</span></li>`).join('')
      : '<li><span>No represented baseline policies recorded.</span></li>';
    return `<div class="strategy-note">
      <strong>${esc(policy.displayName)}</strong>
      <p>${esc(policy.mergeReason || 'Generated consolidated strategy policy.')}</p>
      <span>${esc(policy.separateReason || 'No additional separation note.')}</span>
      <ul class="represented-list">${representedList}</ul>
    </div>`;
  }

  function strategySafetyCard(item) {
    const policies = item.policies.length
      ? `<span>${esc(item.policies.map(policy => policy.id).join(', '))}</span>`
      : '<span>Applies across the strategy</span>';
    return `<div class="strategy-note important">
      <strong>${esc(item.title)}</strong>
      <p>${esc(item.body)}</p>
      ${policies}
    </div>`;
  }

  function strategyOptionalCard(item) {
    const policyText = item.policies.length
      ? `Available policies: ${item.policies.map(policy => policy.id).join(', ')}`
      : 'No additional baseline policy required.';
    return `<div class="strategy-note">
      <strong>${esc(item.title)}</strong>
      <p>${esc(item.body)}</p>
      <span>${esc(policyText)}</span>
    </div>`;
  }

  function mitreCoverageRow(item) {
    const statusClass = item.status.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const controls = item.controls.length ? item.controls.join(', ') : 'No direct Conditional Access control selected';
    return `<div class="mitre-row mitre-${esc(statusClass)}">
      <div>
        <strong>${esc(item.id)} - ${esc(item.name)}</strong>
        <span>${esc(item.tactic)}</span>
      </div>
      <em>${esc(item.status)}</em>
      <p>${esc(controls)}</p>
    </div>`;
  }

  function applyBestPracticeStrategy(preferredKey = null) {
    if (preferredKey?.target) preferredKey = null;
    const plan = strategyPlan();
    if (plan.empty) {
      toast('Select at least one requirement before applying a strategy');
      renderStrategyBuilder();
      return;
    }
    state.guideOnly = null;
    state.consolidatedPolicies = clone(plan.consolidatedPolicies);
    state.appliedStrategy = {
      controls: plan.controls,
      policyKeys: [...plan.policyKeys],
      threats: plan.threats,
      equivalentPolicyKeys: [...plan.equivalentPolicyKeys]
    };
    state.selectedThreats = new Set(plan.threats);
    state.selectedIdentity = 'all_users';
    state.selectedTarget = plan.requirements.agents && !plan.requirements.internals ? 'agent_resources' : 'all_resources';
    state.selectedPersona = 'All';
    state.search = '';
    state.policyView = 'recommended';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    allPolicies().forEach(item => {
      const key = policyKey(item);
      state.decisions[key] = plan.policyKeys.has(key) ? strategyDecisionForPolicy(item, plan) : 'exclude';
    });
    const preferred = preferredKey
      ? state.consolidatedPolicies.find(policy => policyKey(policy) === preferredKey)
      : state.consolidatedPolicies.find(policy => policy.id === 'CA100C') || state.consolidatedPolicies[0];
    if (preferred) state.selectedId = policyKey(preferred);
    else selectFirstVisible();
    if (state.imported.length) compareImported();
    state.activeTab = 'policy-recommendations';
    state.detailView = preferredKey ? 'build' : 'overview';
    state.auditTarget = 'rebuild';
    renderAll();
    toast(`Applied ${plan.consolidatedPolicies.length} consolidated strategy policies`);
  }

  function strategyDecisionForPolicy(policy, plan) {
    if (plan.requirements.rollout === 'cautious') return 'monitor';
    if (plan.requirements.rollout === 'fast') return policy.rolloutDefault || 'include';
    if (policy.risk === 'critical' || isPreviewPolicy(policy)) return 'monitor';
    return policy.rolloutDefault || 'include';
  }

  function downloadStrategySummary() {
    const plan = strategyPlan();
    if (plan.empty) {
      toast('Select at least one requirement before downloading a strategy');
      renderStrategyBuilder();
      return;
    }
    const payload = {
      generatedAt: new Date().toISOString(),
      requirements: plan.requirements,
      summary: {
        policyCount: plan.consolidatedPolicies.length,
        baselineEquivalentPolicyCount: plan.equivalentPolicies.length,
        mitreCoverage: plan.score,
        frictionScore: plan.friction,
        rolloutRisk: plan.rolloutRisk
      },
      controls: plan.controls.map(controlId => ({ id: controlId, label: CONTROLS[controlId].label })),
      policies: plan.consolidatedPolicies.map(policy => ({
        id: policy.id,
        displayName: policy.displayName,
        sourceFile: policy.sourceFile,
        type: policy.consolidated ? 'consolidated' : isPreviewPolicy(policy) ? 'preview/beta' : 'baseline',
        recommendedDecision: strategyDecisionForPolicy(policy, plan),
        represents: policy.represents || []
      })),
      baselineEquivalent: plan.equivalentPolicies.map(policy => ({ id: policy.id, displayName: policy.displayName, sourceFile: policy.sourceFile })),
      keptSeparateForSafety: plan.safety.map(item => ({
        title: item.title,
        reason: item.body,
        policies: item.policies.map(policy => policy.id)
      })),
      mitreCoverage: plan.mitre.map(item => ({
        id: item.id,
        name: item.name,
        status: item.status,
        controls: item.controls
      })),
      residualGaps: RESIDUAL_GAPS
    };
    downloadJson(payload, `ca-architect-strategy-${new Date().toISOString().slice(0, 10)}.json`);
    toast('Strategy summary downloaded');
  }

  function applyScenarioPlan(preferredKey = null) {
    if (preferredKey?.target) preferredKey = null;
    const plan = scenarioPlan();
    if (!plan.canApply) {
      toast('Add required scenario object IDs before applying');
      renderScenarioPlanner();
      return;
    }
    state.guideOnly = null;
    syncScenarioObjectCatalog();
    const keys = new Set(plan.policies.map(policyKey));
    state.consolidatedPolicies = clone(plan.policies);
    state.appliedStrategy = {
      type: 'scenario',
      scenarioId: plan.template.id,
      controls: plan.controls,
      policyKeys: [...keys],
      threats: plan.mitre.map(item => item.id),
      equivalentPolicyKeys: []
    };
    state.selectedThreats = new Set(plan.mitre.map(item => item.id).filter(id => THREATS.some(threat => threat.id === id)));
    state.selectedIdentity = scenarioIdentityForInputs(plan.inputs);
    state.selectedTarget = scenarioTargetForInputs(plan.inputs);
    state.selectedPersona = 'All';
    state.search = '';
    state.policyView = 'recommended';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    allPolicies().forEach(item => {
      const key = policyKey(item);
      state.decisions[key] = keys.has(key) ? item.rolloutDefault || 'monitor' : 'exclude';
    });
    const preferred = preferredKey
      ? state.consolidatedPolicies.find(policy => policyKey(policy) === preferredKey)
      : state.consolidatedPolicies[0];
    if (preferred) state.selectedId = policyKey(preferred);
    else selectFirstVisible();
    if (state.imported.length) compareImported();
    state.activeTab = 'policy-recommendations';
    state.detailView = 'overview';
    state.auditTarget = 'rebuild';
    renderAll();
    toast(`Applied ${plan.policies.length} scenario polic${plan.policies.length === 1 ? 'y' : 'ies'}`);
  }

  function openScenarioBuildGuide(preferredKey = null) {
    const plan = scenarioPlan();
    if (!plan.policies.length) {
      toast('This scenario does not generate a build guide policy');
      renderScenarioPlanner();
      return;
    }
    syncScenarioObjectCatalog();
    const keys = new Set(plan.policies.map(policyKey));
    state.consolidatedPolicies = clone(plan.policies);
    state.appliedStrategy = {
      type: plan.canApply ? 'scenario' : 'scenario-guide',
      scenarioId: plan.template.id,
      controls: plan.controls,
      policyKeys: [...keys],
      threats: plan.mitre.map(item => item.id),
      equivalentPolicyKeys: [],
      guideOnly: !plan.canApply
    };
    state.guideOnly = plan.canApply
      ? null
      : {
        type: 'scenario',
        policyKeys: [...keys],
        missing: plan.missing,
        message: 'Object IDs required before export'
      };
    state.selectedThreats = new Set(plan.mitre.map(item => item.id).filter(id => THREATS.some(threat => threat.id === id)));
    state.selectedIdentity = scenarioIdentityForInputs(plan.inputs);
    state.selectedTarget = scenarioTargetForInputs(plan.inputs);
    state.selectedPersona = 'All';
    state.search = '';
    state.policyView = 'recommended';
    state.touchedDecisions.clear();
    state.reviewedPolicies.clear();
    allPolicies().forEach(item => {
      const key = policyKey(item);
      state.decisions[key] = keys.has(key) ? item.rolloutDefault || 'monitor' : 'exclude';
    });
    const preferred = preferredKey
      ? state.consolidatedPolicies.find(policy => policyKey(policy) === preferredKey)
      : state.consolidatedPolicies[0];
    if (preferred) state.selectedId = policyKey(preferred);
    else selectFirstVisible();
    if (state.imported.length) compareImported();
    state.activeTab = 'policy-recommendations';
    state.detailView = 'build';
    state.auditTarget = 'rebuild';
    renderAll();
    toast(plan.canApply ? 'Scenario build guide opened' : 'Scenario build guide opened. Add object IDs before export.');
  }

  function downloadScenarioSummary() {
    const plan = scenarioPlan();
    const payload = {
      generatedAt: new Date().toISOString(),
      template: {
        id: plan.template.id,
        label: plan.template.label,
        description: plan.template.desc
      },
      inputs: plan.inputs,
      canApply: plan.canApply,
      missingObjects: plan.missing,
      controls: plan.controls.map(controlId => ({ id: controlId, label: CONTROLS[controlId]?.label || controlId })),
      mitreCoverage: {
        score: plan.score,
        techniques: plan.mitre.map(item => ({ id: item.id, name: item.name, status: item.status, controls: item.controls })),
        addressed: scenarioAddressedMitre(plan).map(item => ({ id: item.id, name: item.name, status: item.status, controls: item.controls })),
        notAddressed: scenarioUnaddressedMitre(plan).map(item => ({ id: item.id, name: item.name, status: item.status, controls: item.controls }))
      },
      prerequisites: plan.prerequisites,
      guidance: plan.guidance,
      warnings: plan.warnings,
      policies: plan.policies.map(policy => ({
        id: policy.id,
        displayName: policy.displayName,
        sourceFile: policy.sourceFile,
        recommendedDecision: policy.rolloutDefault || 'monitor',
        graphPreview: sanitizePolicy(policy.policy)
      }))
    };
    downloadJson(payload, `ca-architect-scenario-${plan.template.id}-${new Date().toISOString().slice(0, 10)}.json`);
    toast('Scenario summary downloaded');
  }

  function scenarioIdentityForInputs(inputs) {
    if (inputs.accountType === 'admin') return 'admins';
    if (inputs.accountType === 'externalGuest') return 'guests';
    if (inputs.accountType === 'serviceAccount') return 'service_accounts';
    if (inputs.accountType === 'agentIdentity') return 'copilot_agents';
    return 'internals';
  }

  function scenarioTargetForInputs(inputs) {
    if (inputs.resource === 'adminPortals') return 'admin_portals';
    if (inputs.resource === 'agentResources') return 'agent_resources';
    if (inputs.resource === 'sharepoint' || inputs.resource === 'exchange' || inputs.resource === 'office365') return 'office365';
    return 'all_resources';
  }

  function renderPersonaFilters() {
    const personas = ['All', ...Array.from(new Set(allPolicies().map(policy => policy.persona)))];
    $('personaFilters').innerHTML = personas.map(persona => {
      const active = persona === state.selectedPersona ? 'active' : '';
      return `<button class="filter-chip ${active}" data-persona="${esc(persona)}">${esc(persona)}</button>`;
    }).join('');
    $('personaFilters').querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        state.selectedPersona = btn.dataset.persona;
        renderPersonaFilters();
        renderPolicyPlanSummary();
        renderPolicyList();
      });
    });
  }

  function renderPolicyPlanSummary() {
    const list = visiblePolicies();
    const selected = selectedPolicies();
    const viewLabel = state.policyView === 'all'
      ? 'Baseline library'
      : state.policyView === 'selected'
        ? 'Included in export'
        : 'Recommended build plan';
    const reviewList = reviewPolicyList();
    const currentIndex = reviewList.findIndex(policy => policyKey(policy) === state.selectedId);
    const reviewedCount = reviewList.filter(policy => state.reviewedPolicies.has(policyKey(policy))).length;
    $('policyPlanSummary').innerHTML = `<div class="plan-summary-title">
      <strong>${esc(viewLabel)}</strong>
      <span>${esc(selectedIdentity().label)} -> ${esc(selectedTarget().label)}</span>
    </div>
    <div class="plan-summary-grid">
      <span><strong>${esc(reviewList.length)}</strong> policies in this plan</span>
      <span><strong>${esc(reviewedCount)}</strong> reviewed</span>
    </div>
    <p>${esc(state.guideOnly ? `${guideOnlyText()} Use the build guide now, then return to Scenario Planner before export.` : currentIndex >= 0 ? `Reviewing policy ${currentIndex + 1} of ${reviewList.length}.` : `${selected.length} policies are currently included in export.`)}</p>`;
    $('appliedSourceBanner').textContent = appliedSourceText();
    $('auditComparisonTarget').textContent = `Comparison target: ${state.auditTarget === 'baseline' ? 'full baseline library' : appliedSourceText().replace(/^Current rebuild set: /, '')}.`;
  }

  function renderPolicyList() {
    const list = visiblePolicies();
    const reviewList = reviewPolicyList();
    const currentIndex = reviewList.findIndex(policy => policyKey(policy) === state.selectedId);
    $('policyCount').textContent = reviewList.length ? `${Math.max(1, currentIndex + 1)} of ${reviewList.length}` : '0 policies';
    $('policyList').innerHTML = groupedPolicies(list).map(group => `<section class="policy-purpose-group">
      <div class="purpose-head">
        <div>
          <h4>${esc(group.title)}</h4>
          <p>${esc(group.desc)}</p>
        </div>
        <span class="count-pill">${esc(group.policies.length)}</span>
      </div>
      <div class="purpose-policy-list">
        ${group.policies.map(policyCard).join('')}
      </div>
    </section>`).join('') || '<div class="empty-state">No policies match this view.</div>';
    $('policyList').querySelectorAll('.policy-card').forEach(btn => {
      btn.addEventListener('click', () => {
        state.selectedId = btn.dataset.key;
        state.detailView = 'overview';
        renderPolicyList();
        renderSelected();
      });
    });
  }

  function policyCard(policy) {
      const decision = state.decisions[policyKey(policy)] || 'exclude';
      const comp = state.compare.get(policyKey(policy));
      const compClass = comp ? `import-${comp.status}` : 'import-missing';
      const compLabel = comp ? comp.label : 'not imported';
      const active = policyKey(policy) === state.selectedId ? 'active' : '';
      const reviewed = state.reviewedPolicies.has(policyKey(policy)) ? '<span class="status-chip reviewed">reviewed</span>' : '';
      const preview = isPreviewPolicy(policy) ? '<span class="status-chip beta">preview</span>' : '';
      const generated = policy.generated ? '<span class="status-chip generated">generated</span>' : '';
      const reason = recommendationReasonForPolicy(policy);
      return `<button class="policy-card ${active}" data-key="${esc(policyKey(policy))}">
        <span class="policy-card-top">
          <span class="eyebrow">${esc(policy.id)} - ${esc(policy.persona)}</span>
          <span class="status-chip ${esc(decision)}">${esc(decisionLabel(decision))}</span>
        </span>
        <span class="policy-title">${esc(shortName(policy.displayName))}</span>
        <span class="policy-answer"><strong>Why this is recommended</strong>${esc(reason)}</span>
        <span class="policy-answer"><strong>What it protects</strong>${esc(whatPolicyProtects(policy))}</span>
        <span class="policy-answer"><strong>Current rollout decision</strong>${esc(decisionLabel(decision))}</span>
        <span class="policy-meta">
          <span class="status-chip ${compClass}">${esc(compLabel)}</span>
          <span class="risk-pill ${esc(policy.risk)}">${esc(policy.risk)}</span>
          ${reviewed}
          ${preview}${generated}
        </span>
      </button>`;
  }

  function renderSelected() {
    const policy = selectedPolicy();
    if (!policy) return;
    state.selectedId = policyKey(policy);
    const decision = state.decisions[policyKey(policy)] || 'exclude';
    const controls = recommendationControlsForPolicy(policy);
    $('selectedPersona').textContent = 'Policy detail';
    $('selectedTitle').textContent = policyDisplayLine(policy);
    $('selectedRisk').className = `risk-pill ${policy.risk}`;
    $('selectedRisk').textContent = policy.risk;
    $('selectedSummary').textContent = selectedSummaryText(policy, controls);
    const guideOnly = isGuideOnlyPolicy(policy);
    $('selectedGuidance').innerHTML = `<article>
      <span>Why this policy is here</span>
      <strong>${esc(recommendationReasonForPolicy(policy))}</strong>
    </article>
    <article>
      <span>Recommended rollout</span>
      <strong>${esc(decisionLabel(decision))}</strong>
    </article>
    <article>
      <span>Before export</span>
      <strong>${esc(beforeExportText(policy))}</strong>
    </article>
    ${guideOnly ? `<article class="guide-only-guidance">
      <span>Guide-only status</span>
      <strong>${esc(guideOnlyText())}</strong>
    </article>` : ''}`;
    $('prereqList').innerHTML = listItems(prerequisitesForPolicy(policy), 'No special prerequisites recorded.');
    $('objectList').innerHTML = listItems(policy.requiredObjects, 'No extra baseline object required.');
    renderSegmented('decisionControl', decision, 'decision');
    $('decisionHint').textContent = decisionText(policy, decision);
    renderOverrides(policy);
    renderCompare(policy);
    const exported = exportPolicy(policy, 'configured');
    renderManualGuide(policy, exported, decision);
    $('jsonPreview').textContent = JSON.stringify(exported, null, 2);
    $('jsonModeLabel').textContent = guideOnly
      ? 'Guide-only preview - object IDs required before JSON export'
      : isPreviewPolicy(policy) ? 'Graph beta/preview policy shape' : 'Graph v1.0 policy shape';
    $('copyJsonBtn').disabled = guideOnly;
    $('downloadPolicyBtn').disabled = guideOnly;
    renderPolicyDetailView();
    renderPolicyReviewFooter();
  }

  function appliedSourceText() {
    if (!state.appliedStrategy) return 'Current rebuild set: baseline recommendations';
    if (state.appliedStrategy.type === 'scenario' || state.appliedStrategy.type === 'scenario-guide') {
      const template = SCENARIO_TEMPLATES.find(item => item.id === state.appliedStrategy.scenarioId);
      return `Current rebuild set: scenario - ${template?.label || 'custom access scenario'}`;
    }
    return 'Current rebuild set: consolidated strategy';
  }

  function renderPolicyDetailView() {
    const view = state.detailView || 'overview';
    const reviewGrid = document.querySelector('.guided-review-grid');
    const policyNav = document.querySelector('.policy-nav');
    const detailPanel = document.querySelector('.detail-panel');
    const exportPanel = document.querySelector('.review-export-panel');
    const reviewFooter = $('policyReviewFooter');
    const exportMode = view === 'export';
    reviewGrid?.classList.toggle('export-mode', exportMode);
    if (policyNav) policyNav.hidden = exportMode;
    if (detailPanel) detailPanel.hidden = exportMode;
    if (exportPanel) exportPanel.hidden = !exportMode;
    reviewFooter?.classList.toggle('export-mode', exportMode);
    document.querySelectorAll('[data-detail-view-panel]:not(.review-export-panel)').forEach(panel => {
      panel.hidden = panel.dataset.detailViewPanel !== view;
    });
    document.querySelectorAll('#policyDetailTabs button[data-detail-view]').forEach(btn => {
      const active = btn.dataset.detailView === view;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
      btn.setAttribute('tabindex', active ? '0' : '-1');
    });
    document.querySelectorAll('button[data-review-stage]').forEach(btn => {
      btn.classList.toggle('active', exportMode ? btn.dataset.reviewStage === 'export' : btn.dataset.reviewStage === 'policies');
    });
    $('reviewExportBtn').textContent = exportMode ? 'Back to policy review' : 'Review export readiness';
  }

  function renderPolicyReviewFooter() {
    const list = reviewPolicyList();
    const index = list.findIndex(policy => policyKey(policy) === state.selectedId);
    const policy = selectedPolicy();
    $('policyProgressText').textContent = index >= 0 ? `Policy ${index + 1} of ${list.length}` : 'No policy selected';
    $('previousPolicyBtn').disabled = index <= 0;
    $('nextPolicyBtn').disabled = index < 0 || index >= list.length - 1;
    $('markReviewedBtn').disabled = !policy;
    $('markReviewedBtn').textContent = policy && state.reviewedPolicies.has(policyKey(policy)) ? 'Reviewed' : 'Mark reviewed';
    $('markReviewedBtn').classList.toggle('reviewed', Boolean(policy && state.reviewedPolicies.has(policyKey(policy))));
  }

  function selectedSummaryText(policy, controls) {
    if (!controls.length) return policy.summary;
    return `${policy.summary} Recommended by: ${controls.join(', ')}.`;
  }

  function listItems(items, fallback) {
    if (!items || !items.length) return `<li>${esc(fallback)}</li>`;
    return items.map(item => `<li>${esc(item)}</li>`).join('');
  }

  function prerequisitesForPolicy(policy) {
    return [...new Set([...GLOBAL_PREREQUISITES, ...(policy.prerequisites || [])])];
  }

  function renderOverrides(policy) {
    const override = state.overrides[policyKey(policy)] || {};
    $('overrideGrid').innerHTML = OVERRIDE_FIELDS.map(field => {
      const value = override[field.id] || '';
      return `<label class="override-field ${esc(field.className)}">
        <span>${esc(field.label)}</span>
        <textarea data-override="${esc(field.id)}" spellcheck="false" rows="3" placeholder="GUID, token, or object id per line">${esc(value)}</textarea>
      </label>`;
    }).join('');
  }

  function renderCompare(policy) {
    const comp = state.compare.get(policyKey(policy));
    const box = $('compareBox');
    if (comp) {
      box.className = 'compare-box show';
      const diffText = comp.diffs?.length
        ? `<ul>${comp.diffs.slice(0, 5).map(diff => `<li>${esc(diff.label)} differs: expected ${esc(formatCompareValue(diff.expected))}, tenant has ${esc(formatCompareValue(diff.actual))}</li>`).join('')}</ul>`
        : '';
      box.innerHTML = `<strong>Import comparison: ${esc(comp.label)}</strong><br>${esc(comp.reason)}${diffText}`;
      return;
    }
    if (state.imported.length) {
      box.className = 'compare-box show';
      box.innerHTML = '<strong>Import comparison: missing</strong><br>No imported policy has the same baseline id or a close policy fingerprint.';
      return;
    }
    box.className = 'compare-box';
    box.textContent = '';
  }

  function renderManualGuide(item, exported, decision) {
    const sections = manualGuideSections(item, exported, decision);
    const visibleSections = sections
      .map(section => ({ ...section, rows: state.expertMode ? section.rows : section.rows.filter(row => !row.empty) }))
      .filter(section => section.rows.length);
    const guideOnly = isGuideOnlyPolicy(item)
      ? `<div class="manual-callout guide-only"><strong>Object IDs required before export</strong><span>${esc(guideOnlyText())} The checklist below is safe to use for manual planning, but Graph JSON copy/download is disabled until the required scenario objects are supplied.</span></div>`
      : '';
    const preview = isPreviewPolicy(item)
      ? `<div class="manual-callout beta"><strong>Preview/beta policy fields</strong><span>This policy includes agent identity or agent resource targeting. Build manually only in tenants where the current Entra and Microsoft Graph beta/preview capabilities are available.</span></div>`
      : '';
    const simpleNote = state.expertMode ? '' : '<div class="manual-callout simple"><strong>Configured settings only</strong><span>Turn on Expert detail to show raw object IDs and every unconfigured Entra section.</span></div>';
    $('manualGuide').innerHTML = `${guideOnly}${preview}${simpleNote}<div class="manual-section-grid">${visibleSections.map(renderManualSection).join('')}</div>`;
  }

  function renderManualSection(section) {
    return `<details class="manual-section" ${section.step === '01' ? 'open' : ''}>
      <summary class="manual-section-head">
        <span>${esc(section.step)}</span>
        <div>
          <h5>${esc(section.title)}</h5>
          <p>${esc(section.desc)}</p>
        </div>
      </summary>
      <dl class="manual-rows">
        ${section.rows.map(renderManualRow).join('')}
      </dl>
    </details>`;
  }

  function renderManualRow(row) {
    const empty = row.empty ? ' empty' : '';
    const help = row.help ? `<em>${esc(row.help)}</em>` : '';
    const value = row.entries ? renderManualEntries(row.entries) : `<span>${esc(row.value)}</span>`;
    return `<div class="manual-row${empty}">
      <dt>${esc(row.label)}</dt>
      <dd>${value}${help}</dd>
    </div>`;
  }

  function renderManualEntries(entries) {
    return entries.map(entry => {
      if (entry.lookup) return `<span class="manual-lookup-required">${esc(entry.text)}</span>`;
      if (entry.id) return `<span class="manual-object"><strong>${esc(entry.name)}</strong>${state.expertMode ? `<small>Object ID: ${esc(entry.id)}</small>` : ''}</span>`;
      return `<span>${esc(entry.text || entry.name || '')}</span>`;
    }).join('');
  }

  function manualGuideSections(item, exported, decision) {
    const guide = { unresolved: [] };
    const conditions = exported.conditions || {};
    const users = conditions.users || {};
    const apps = conditions.applications || {};
    const clientApplications = conditions.clientApplications || {};
    const platforms = conditions.platforms || {};
    const locations = conditions.locations || {};
    const devices = conditions.devices || {};
    const grant = exported.grantControls || {};
    const session = exported.sessionControls || {};
    const agentFields = manualAgentFieldSummary(conditions);
    const exclusionSummary = manualExclusionSummary(conditions);
    const previewText = isPreviewPolicy(item)
      ? 'Uses preview/beta agent identity or agent resource fields.'
      : 'Uses Microsoft Graph v1.0 Conditional Access policy fields.';

    const sections = [
      {
        step: '01',
        title: 'Policy basics',
        desc: 'Create the policy shell and set the initial rollout state.',
        rows: [
          manualRow('Name', exported.displayName, 'Paste this into the Entra policy Name field.'),
          manualRow('State', portalStateLabel(exported.state), 'Set this at the end after assignments and controls are reviewed.'),
          manualRow('Rollout decision', decisionLabel(decision), decisionText(item, decision)),
          manualRow('Policy group', item.persona || 'Baseline', 'Use this only as build context; it is not an Entra setting.'),
          manualRow('Risk level', item.risk || 'Not tagged', 'Use this to decide peer review and rollout scrutiny.'),
          manualRow('Graph shape', previewText)
        ]
      },
      {
        step: '02',
        title: 'Assignments - identities',
        desc: 'Configure who the policy applies to, then add exclusions before enabling.',
        rows: [
          manualListRow('Include users', users.includeUsers, 'users', item, guide),
          manualListRow('Exclude users', users.excludeUsers, 'users', item, guide),
          manualListRow('Include groups', users.includeGroups, 'groups', item, guide),
          manualListRow('Exclude groups', users.excludeGroups, 'groups', item, guide),
          manualListRow('Include directory roles', users.includeRoles, 'roles', item, guide),
          manualListRow('Exclude directory roles', users.excludeRoles, 'roles', item, guide),
          manualListRow('Include service principals', clientApplications.includeServicePrincipals, 'servicePrincipals', item, guide),
          manualListRow('Exclude service principals', clientApplications.excludeServicePrincipals, 'servicePrincipals', item, guide),
          manualListRow('Include agent identities', clientApplications.includeAgentIdServicePrincipals, 'agentIdentities', item, guide),
          manualListRow('Exclude agent identities', clientApplications.excludeAgentIdServicePrincipals, 'agentIdentities', item, guide),
          manualValueRow('Agent service principal filter', clientApplications.agentIdServicePrincipalFilter, 'Preview/beta agent identity filter when present.'),
          manualValueRow('Agent user assignments', conditions.agents, 'Preview/beta agent user assignment block when present.'),
          manualAdditionalRow('Other identity assignment fields', users, ['includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles'])
        ]
      },
      {
        step: '03',
        title: 'Assignments - target resources',
        desc: 'Choose what the policy applies to in Target resources.',
        rows: [
          manualListRow('Include cloud apps/resources', apps.includeApplications, 'applications', item, guide),
          manualListRow('Exclude cloud apps/resources', apps.excludeApplications, 'applications', item, guide),
          manualListRow('User actions', apps.includeUserActions, 'userActions', item, guide),
          manualListRow('Authentication contexts', apps.includeAuthenticationContextClassReferences, 'authContexts', item, guide),
          manualValueRow('Application filter', apps.applicationFilter, 'Use this only when an application filter appears in the source policy.'),
          manualAdditionalRow('Other target resource fields', apps, ['includeApplications', 'excludeApplications', 'includeUserActions', 'includeAuthenticationContextClassReferences', 'applicationFilter'])
        ]
      },
      {
        step: '04',
        title: 'Conditions',
        desc: 'Configure signals that narrow when the policy applies.',
        rows: [
          manualListRow('Client apps', conditions.clientAppTypes, 'clientApps', item, guide),
          manualListRow('Include device platforms', platforms.includePlatforms, 'platforms', item, guide),
          manualListRow('Exclude device platforms', platforms.excludePlatforms, 'platforms', item, guide),
          manualListRow('Include locations', locations.includeLocations, 'locations', item, guide),
          manualListRow('Exclude locations', locations.excludeLocations, 'locations', item, guide),
          manualListRow('Sign-in risk', conditions.signInRiskLevels, 'riskLevels', item, guide),
          manualListRow('User risk', conditions.userRiskLevels, 'riskLevels', item, guide),
          manualListRow('Agent risk', conditions.agentIdRiskLevels, 'riskLevels', item, guide),
          manualValueRow('Authentication flows', conditions.authenticationFlows, 'Configure only when transfer methods or authentication flow controls are present.'),
          manualValueRow('Device filter', devices.deviceFilter || devices.filter, 'Configure under Conditions > Filter for devices when present.'),
          manualAdditionalRow('Other condition fields', conditions, ['users', 'applications', 'clientApplications', 'clientAppTypes', 'platforms', 'locations', 'signInRiskLevels', 'userRiskLevels', 'agentIdRiskLevels', 'authenticationFlows', 'devices', 'agents'])
        ]
      },
      {
        step: '05',
        title: 'Access controls - grant',
        desc: 'Set whether access is blocked or granted with required controls.',
        rows: [
          manualRow('Access result', grantAccessResult(grant), 'Choose Block access or Grant access in Entra.'),
          manualRow('Control operator', grant.operator ? grantOperatorLabel(grant.operator) : notConfigured(), 'Use Require all selected controls for AND, or Require one selected control for OR.', !grant.operator),
          manualListRow('Built-in grant controls', grant.builtInControls, 'grantControls', item, guide),
          manualValueRow('Authentication strength', grant.authenticationStrength, 'In Entra, go to Grant > Require authentication strength and choose this named strength.', formatAuthenticationStrength),
          manualListRow('Terms of use', grant.termsOfUse, 'termsOfUse', item, guide),
          manualListRow('Custom authentication factors', grant.customAuthenticationFactors, 'customControls', item, guide),
          manualAdditionalRow('Other grant settings', grant, ['operator', 'builtInControls', 'authenticationStrength', 'termsOfUse', 'customAuthenticationFactors'])
        ]
      },
      {
        step: '06',
        title: 'Session controls',
        desc: 'Configure session lifetime, browser persistence, and app/session restrictions.',
        rows: [
          manualValueRow('Sign-in frequency', session.signInFrequency, 'Configure under Session > Sign-in frequency when present.', formatSignInFrequency),
          manualValueRow('Persistent browser session', session.persistentBrowser, 'Configure under Session > Persistent browser session when present.', formatPersistentBrowser),
          manualValueRow('Continuous access evaluation', session.continuousAccessEvaluation, 'Configure under Session > Continuous access evaluation when present.', formatContinuousAccessEvaluation),
          manualValueRow('App enforced restrictions', session.applicationEnforcedRestrictions, 'Configure only for supported apps such as Exchange Online and SharePoint Online.'),
          manualValueRow('Conditional Access App Control', session.cloudAppSecurity, 'Configure Defender for Cloud Apps session control when present.'),
          manualValueRow('Disable resilience defaults', session.disableResilienceDefaults, 'Configure only when explicitly present.'),
          manualAdditionalRow('Other session settings', session, ['signInFrequency', 'persistentBrowser', 'continuousAccessEvaluation', 'applicationEnforcedRestrictions', 'cloudAppSecurity', 'disableResilienceDefaults'])
        ]
      },
      {
        step: '07',
        title: 'Before enabling',
        desc: 'Use this final check to avoid lockout and rollout surprises.',
        rows: [
          manualRow('Break-glass group', 'Create and validate CA-BreakGlassAccounts-Exclude before enabling broad policies.'),
          manualRow('Visible exclusions', exclusionSummary, hasVisibleExclusions(conditions) ? 'Confirm these exclusions contain the intended emergency/access accounts.' : 'Add emergency access exclusions before enabling broad controls.'),
          manualListRow('Prerequisites', prerequisitesForPolicy(item), 'plain', item, guide),
          manualListRow('Required objects', item.requiredObjects, 'plain', item, guide),
          manualRow('Report-only validation', 'Run in report-only where supported and review sign-in logs plus Conditional Access Insights.'),
          manualRow('What If validation', 'Use the Entra Conditional Access What If tool for representative users, admin roles, apps, platforms, locations, and agent identities.'),
          manualRow('Known limitations', manualKnownLimitations(item, exported, agentFields))
        ]
      }
    ];
    const unresolvedSection = manualUnresolvedSection(guide.unresolved);
    return unresolvedSection ? [...sections.slice(0, 2), unresolvedSection, ...sections.slice(2)] : sections;
  }

  function manualRow(label, value, help = '', empty = false) {
    const text = value === undefined || value === null || value === '' ? notConfigured() : String(value);
    return { label, value: text, help, empty: empty || text === notConfigured() };
  }

  function manualListRow(label, values, context, item, guide, help = '') {
    if (!Array.isArray(values) || !values.length) return manualRow(label, notConfigured(), help, true);
    const formatted = formatManualEntries(values, context, item, guide, label);
    if (!formatted.entries.length) return manualRow(label, notConfigured(), help, true);
    return { label, entries: formatted.entries, help, empty: false };
  }

  function manualValueRow(label, value, help = '', formatter = formatManualValue) {
    const formatted = formatter(value);
    return manualRow(label, formatted, help, formatted === notConfigured());
  }

  function manualAdditionalRow(label, obj, knownKeys) {
    const extra = Object.keys(obj || {})
      .filter(key => !knownKeys.includes(key) && !isEmptyManualValue(obj[key]))
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    if (!extra.length) return manualRow(label, notConfigured(), '', true);
    const value = extra.map(key => `${key}: ${formatManualValue(obj[key])}`).join('\n');
    return manualRow(label, value);
  }

  function notConfigured() {
    return 'Not configured - leave this section unchanged in Entra';
  }

  function formatManualValue(value) {
    if (isEmptyManualValue(value)) return notConfigured();
    if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled';
    if (typeof value === 'string' || typeof value === 'number') return String(value);
    return JSON.stringify(value, null, 2);
  }

  function isEmptyManualValue(value) {
    if (value === undefined || value === null || value === '') return true;
    if (Array.isArray(value) && !value.length) return true;
    return Boolean(value && typeof value === 'object' && !Array.isArray(value) && !Object.keys(value).length);
  }

  function formatManualEntries(values, context, item, guide, field) {
    const entries = [];
    const unresolved = [];
    values.forEach(value => {
      if (value && typeof value === 'object') {
        entries.push({ text: formatManualValue(value) });
        return;
      }
      const entry = manualTokenEntry(value, context, item);
      if (entry.unresolved) {
        const ref = { ...entry, field, context };
        unresolved.push(ref);
        addUnresolvedReference(guide, ref);
        return;
      }
      entries.push(entry);
    });
    const sortedEntries = sortManualEntries(entries, context);
    if (unresolved.length) {
      sortedEntries.push({
        lookup: true,
        text: `${unresolved.length} ${pluralObjectLabel(context, unresolved.length)} require object lookup before manual build`
      });
    }
    return { entries: sortedEntries };
  }

  function sortManualEntries(entries, context) {
    if (!shouldSortManualContext(context)) return entries;
    return [...entries].sort((a, b) => manualEntrySortLabel(a).localeCompare(manualEntrySortLabel(b), undefined, { sensitivity: 'base' }));
  }

  function shouldSortManualContext(context) {
    return !new Set(['riskLevels']).has(context);
  }

  function manualEntrySortLabel(entry) {
    return entry.name || entry.text || '';
  }

  function manualTokenEntry(value, context, item) {
    const raw = String(value);
    const lower = raw.toLowerCase();
    if (isGuid(raw)) return resolveObjectReference(raw, context, item);
    return { text: manualLiteralTokenLabel(lower, raw, context) };
  }

  function manualLiteralTokenLabel(lower, raw, context) {
    const labels = {
      users: { all: 'All users', none: 'No users', allagentidusers: 'All agent ID users' },
      applications: { all: 'All cloud apps', office365: 'Office 365', allagentidresources: 'All agent ID resources' },
      clientApps: {
        all: 'All client apps',
        browser: 'Browser',
        mobileappsanddesktopclients: 'Mobile apps and desktop clients',
        exchangeactivesync: 'Exchange ActiveSync clients',
        other: 'Other clients'
      },
      platforms: {
        all: 'Any device platform',
        windows: 'Windows',
        macos: 'macOS',
        ios: 'iOS',
        android: 'Android',
        linux: 'Linux',
        windowsphone: 'Windows Phone'
      },
      locations: { all: 'Any location', alltrusted: 'All trusted locations' },
      riskLevels: { low: 'Low', medium: 'Medium', high: 'High', none: 'None' },
      grantControls: {
        block: 'Block access',
        mfa: 'Require multifactor authentication',
        compliantdevice: 'Require device to be marked as compliant',
        domainjoineddevice: 'Require Microsoft Entra hybrid joined device',
        approvedapplication: 'Require approved client app',
        compliantapplication: 'Require app protection policy',
        passwordchange: 'Require password change'
      },
      userActions: {
        urn_user_registersecurityinfo: 'Register security information',
        urn_user_registerdevice: 'Register or join devices'
      }
    };
    const contextLabels = labels[context] || {};
    return contextLabels[lower] || raw;
  }

  function resolveObjectReference(value, context) {
    const lower = value.toLowerCase();
    const type = objectTypeForContext(context);
    const imported = lookupObjectCatalog(lower, type, state.objectCatalog);
    const known = imported || lookupObjectCatalog(lower, type, STATIC_OBJECT_LOOKUP);
    if (known) return { name: known.name, id: value, type: known.type, source: known.source };
    return { id: value, type, unresolved: true };
  }

  function lookupObjectCatalog(id, type, catalog) {
    return catalog.get(objectCatalogKey(id, type)) || catalog.get(objectCatalogKey(id, 'object'));
  }

  function objectCatalogKey(id, type) {
    return `${type}:${String(id).toLowerCase()}`;
  }

  function objectTypeForContext(context) {
    return {
      roles: 'role',
      groups: 'group',
      applications: 'application',
      locations: 'location',
      servicePrincipals: 'servicePrincipal',
      agentIdentities: 'agentIdentity',
      termsOfUse: 'termsOfUse',
      authContexts: 'authContext',
      customControls: 'customControl',
      users: 'user'
    }[context] || 'object';
  }

  function addUnresolvedReference(guide, ref) {
    const key = `${ref.context}|${ref.field}|${ref.id}`;
    if (guide.unresolved.some(item => item.key === key)) return;
    guide.unresolved.push({ ...ref, key });
  }

  function manualUnresolvedSection(unresolved) {
    if (!unresolved.length) return null;
    const byField = new Map();
    unresolved.forEach(ref => {
      const key = `${ref.context}|${ref.field}`;
      if (!byField.has(key)) byField.set(key, []);
      byField.get(key).push(ref);
    });
    const rows = [...byField.values()]
      .map(refs => refs.sort((a, b) => a.id.localeCompare(b.id, undefined, { sensitivity: 'base' })))
      .sort((a, b) => a[0].field.localeCompare(b[0].field, undefined, { sensitivity: 'base' }));
    return {
      step: '!',
      title: 'Objects to resolve before manual build',
      desc: 'These tenant-specific IDs need a display name from Entra or an imported object catalog before an engineer can build the policy manually.',
      rows: rows.map(refs => manualRow(
        refs[0].field,
        refs.map(ref => `${objectContextLabel(ref.context)}: ${ref.id}`).join('\n'),
        'Look this up in Entra, or import JSON containing id and displayName for this object.'
      ))
    };
  }

  function objectContextLabel(context) {
    return {
      users: 'user object',
      groups: 'group object',
      roles: 'directory role',
      applications: 'cloud app/resource',
      locations: 'named location',
      servicePrincipals: 'service principal',
      agentIdentities: 'agent identity',
      termsOfUse: 'terms of use object',
      authContexts: 'authentication context',
      customControls: 'custom control'
    }[context] || 'object ID';
  }

  function pluralObjectLabel(context, count) {
    const label = objectContextLabel(context);
    return count === 1 ? label : `${label}s`;
  }

  function isGuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value));
  }

  function portalStateLabel(state) {
    if (state === 'enabled') return 'On - policy will enforce';
    if (state === 'enabledForReportingButNotEnforced') return 'Report-only - evaluate without enforcing';
    if (state === 'disabled') return 'Off - policy will not apply';
    return state || notConfigured();
  }

  function grantOperatorLabel(operator) {
    if (String(operator).toUpperCase() === 'AND') return 'Require all selected controls';
    if (String(operator).toUpperCase() === 'OR') return 'Require one selected control';
    return operator;
  }

  function grantAccessResult(grant) {
    if (!grant || isEmptyManualValue(grant)) return notConfigured();
    const controls = grant.builtInControls || [];
    if (controls.includes('block')) return 'Block access';
    return 'Grant access with selected controls';
  }

  function formatAuthenticationStrength(value) {
    if (isEmptyManualValue(value)) return notConfigured();
    const displayName = value.displayName || value.id || 'Configured authentication strength';
    const type = value.policyType === 'builtIn' ? 'Built-in authentication strength' : value.policyType || '';
    const requirement = value.requirementsSatisfied ? `Satisfies: ${authRequirementLabel(value.requirementsSatisfied)}` : '';
    const methods = Array.isArray(value.allowedCombinations) && value.allowedCombinations.length
      ? `Allowed methods in this strength:\n${value.allowedCombinations.map(authenticationMethodLabel).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' })).map(method => `- ${method}`).join('\n')}`
      : '';
    return [
      `Select: ${displayName}`,
      type,
      requirement,
      value.description ? `Description: ${value.description}` : '',
      methods
    ].filter(Boolean).join('\n');
  }

  function authRequirementLabel(value) {
    if (String(value).toLowerCase() === 'mfa') return 'Multifactor authentication';
    return value;
  }

  function authenticationMethodLabel(value) {
    const parts = String(value).split(',').map(part => ({
      windowsHelloForBusiness: 'Windows Hello for Business',
      fido2: 'FIDO2 security key',
      x509CertificateMultiFactor: 'Certificate-based MFA',
      deviceBasedPush: 'Device-based push',
      temporaryAccessPassOneTime: 'Temporary Access Pass - one-time',
      temporaryAccessPassMultiUse: 'Temporary Access Pass - multi-use',
      password: 'Password',
      microsoftAuthenticatorPush: 'Microsoft Authenticator push',
      softwareOath: 'Software OATH token',
      hardwareOath: 'Hardware OATH token',
      sms: 'SMS',
      voice: 'Voice call',
      federatedMultiFactor: 'Federated MFA',
      federatedSingleFactor: 'Federated single-factor'
    }[part] || part));
    return parts.join(' + ');
  }

  function formatSignInFrequency(value) {
    if (isEmptyManualValue(value)) return notConfigured();
    const enabled = value.isEnabled === false ? 'Disabled' : 'Enabled';
    const amount = value.value && value.type ? `${value.value} ${value.type}` : 'Configured';
    const authType = value.authenticationType ? `Authentication type: ${value.authenticationType}` : '';
    const interval = value.frequencyInterval ? `Interval: ${value.frequencyInterval}` : '';
    return [enabled, amount, authType, interval].filter(Boolean).join('\n');
  }

  function formatPersistentBrowser(value) {
    if (isEmptyManualValue(value)) return notConfigured();
    const mode = value.mode === 'never'
      ? 'Never persist'
      : value.mode === 'always'
        ? 'Always persist'
        : value.mode || 'Configured';
    const enabled = value.isEnabled === false ? 'Disabled' : 'Enabled';
    return `${enabled}\nMode: ${mode}`;
  }

  function formatContinuousAccessEvaluation(value) {
    if (isEmptyManualValue(value)) return notConfigured();
    const mode = value.mode || 'Configured';
    return `Mode: ${mode}`;
  }

  function manualAgentFieldSummary(conditions) {
    const apps = conditions.applications || {};
    const users = conditions.users || {};
    const clientApplications = conditions.clientApplications || {};
    return [
      ...(conditions.agentIdRiskLevels || []),
      ...(includesToken(apps.includeApplications, 'AllAgentIdResources') ? ['AllAgentIdResources'] : []),
      ...(includesToken(users.includeUsers, 'AllAgentIdUsers') ? ['AllAgentIdUsers'] : []),
      ...(clientApplications.includeAgentIdServicePrincipals || []),
      ...(clientApplications.excludeAgentIdServicePrincipals || []),
      ...(conditions.agents ? ['agents assignment block'] : [])
    ];
  }

  function hasVisibleExclusions(conditions) {
    const users = conditions.users || {};
    const apps = conditions.applications || {};
    const clientApplications = conditions.clientApplications || {};
    return hasAny(users.excludeUsers) || hasAny(users.excludeGroups) || hasAny(users.excludeRoles) ||
      hasAny(apps.excludeApplications) || hasAny(clientApplications.excludeServicePrincipals) ||
      hasAny(clientApplications.excludeAgentIdServicePrincipals);
  }

  function manualExclusionSummary(conditions) {
    const users = conditions.users || {};
    const apps = conditions.applications || {};
    const clientApplications = conditions.clientApplications || {};
    const count = [
      users.excludeUsers,
      users.excludeGroups,
      users.excludeRoles,
      apps.excludeApplications,
      clientApplications.excludeServicePrincipals,
      clientApplications.excludeAgentIdServicePrincipals
    ].reduce((total, values) => total + (Array.isArray(values) ? values.length : 0), 0);
    if (!count) return 'No visible exclusions are configured in this policy.';
    return `${count} exclusion reference${count === 1 ? '' : 's'} configured. Review the assignment rows above and resolve any object lookup items before enabling.`;
  }

  function manualKnownLimitations(item, exported, agentFields) {
    const notes = [];
    if (NON_REPORT_ONLY.has(item.id)) notes.push('This policy cannot be represented as report-only by the current exporter and is disabled in report-only export mode.');
    if (agentFields.length) notes.push('Agent identity/resource targeting uses current beta/preview Conditional Access fields.');
    if (isBroadBlockWithoutExclusion(exported)) notes.push('Broad block policies must include tested emergency exclusions before enforcement.');
    if (!notes.length) return 'No special limitations detected for this policy. Continue with normal report-only validation.';
    return notes.join('\n');
  }

  function renderSegmented(id, value, dataName) {
    $(id).querySelectorAll(`button[data-${dataName}]`).forEach(btn => {
      btn.classList.toggle('active', btn.dataset[dataName] === value);
    });
  }

  function renderMetrics() {
    const selected = selectedPolicies();
    const exportBlocked = selected.some(isGuideOnlyPolicy);
    ['exportConfiguredBtn', 'exportReportBtn', 'exportDisabledBtn'].forEach(id => {
      $(id).disabled = !selected.length || exportBlocked;
    });
  }

  function renderWarnings() {
    const warnings = safetyWarnings();
    $('warningList').innerHTML = warnings.length
      ? warnings.map(warning => `<div class="warning ${warning.critical ? 'critical' : ''}">${esc(warning.text)}</div>`).join('')
      : '<div class="warning">No active warnings for the selected rebuild set.</div>';
  }

  function renderImport() {
    $('auditTarget').value = state.auditTarget;
    renderImportFilterButtons();
    if (!state.imported.length || !state.compareReport) {
      $('importStatus').textContent = state.objectCatalog.size
        ? `Loaded ${state.objectCatalog.size} object names for manual guide resolution. Import Conditional Access policies to run tenant comparison.`
        : `Import a Graph or IntuneManagement export to compare against the ${state.auditTarget === 'baseline' ? 'full baseline library' : 'current rebuild set'}.`;
      $('importDashboard').innerHTML = '';
      $('importFindings').innerHTML = state.objectCatalog.size
        ? '<div class="empty-state">Object catalog loaded. Return to Policy recommendations to see resolved names in the manual build guide.</div>'
        : '<div class="empty-state">Paste or drop a tenant export to see policy-by-policy comparison results.</div>';
      return;
    }
    const summary = state.compareReport.summary;
    $('importStatus').textContent = `Compared ${summary.imported} imported tenant policies against ${summary.expected} policies in the ${state.auditTarget === 'baseline' ? 'full baseline library' : 'current rebuild set'}.`;
    $('importDashboard').innerHTML = renderImportDashboard(summary);
    $('importFindings').innerHTML = renderImportReport();
  }

  function renderImportFilterButtons() {
    $('importFilterControl').querySelectorAll('button[data-import-filter]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.importFilter === state.importFilter);
    });
  }

  function renderImportDashboard(summary) {
    return [
      ['Imported', summary.imported],
      [state.auditTarget === 'baseline' ? 'Baseline' : 'Rebuild set', summary.expected],
      ['Exact', summary.exact],
      ['Different', summary.different],
      ['Missing', summary.missing],
      ['Extra', summary.extra],
      ['Risk findings', summary.risk]
    ].map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join('');
  }

  function renderImportReport() {
    const report = state.compareReport;
    const sections = [];
    const filter = state.importFilter;
    const addSection = (title, items, renderer) => {
      if (!items.length) return;
      sections.push(`<section class="comparison-section"><div class="comparison-section-head"><h4>${esc(title)}</h4><span class="count-pill">${esc(items.length)}</span></div>${items.map(renderer).join('')}</section>`);
    };
    const exact = report.results.filter(item => item.status === 'exact');
    const different = report.results.filter(item => item.status === 'different' || item.status === 'likely');
    const missing = report.results.filter(item => item.status === 'missing');
    if (filter === 'all' || filter === 'exact') addSection('Already aligned', exact, renderComparisonCard);
    if (filter === 'all' || filter === 'different') addSection('Exists but differs', different, renderComparisonCard);
    if (filter === 'all' || filter === 'missing') addSection('Missing from tenant', missing, renderComparisonCard);
    if (filter === 'all' || filter === 'extra') addSection('Extra in tenant', report.extras, renderExtraPolicyCard);
    if (filter === 'all' || filter === 'risk') addSection('Risk review', report.risks, renderRiskFindingCard);
    return sections.join('') || '<div class="empty-state">No findings match this filter.</div>';
  }

  function renderComparisonCard(result) {
    const diffs = result.diffs?.length
      ? result.diffs.map(diff => `<li><strong>${esc(diff.label)}</strong><span>Expected ${esc(formatCompareValue(diff.expected))}</span><span>Tenant has ${esc(formatCompareValue(diff.actual))}</span></li>`).join('')
      : '<li><strong>No differences found</strong><span>The imported policy matches the export shape for compared fields.</span></li>';
    return `<details class="comparison-card status-${esc(result.status)}">
      <summary>
        <span class="status-chip import-${esc(result.status)}">${esc(result.label)}</span>
        <strong>${esc(shortName(result.toolName))}</strong>
        <em>${esc(result.action)}</em>
      </summary>
      <div class="comparison-body">
        <dl>
          <dt>Tool policy</dt><dd>${esc(result.toolName)}</dd>
          <dt>Tenant match</dt><dd>${esc(result.tenantName || 'No matching tenant policy')}</dd>
          <dt>Match method</dt><dd>${esc(result.matchMethod || 'No match')}</dd>
          <dt>Suggested action</dt><dd>${esc(result.action)}</dd>
        </dl>
        <p>${esc(result.reason)}</p>
        <ul class="diff-list">${diffs}</ul>
      </div>
    </details>`;
  }

  function renderExtraPolicyCard(policy) {
    return `<details class="comparison-card status-extra">
      <summary>
        <span class="status-chip import-extra">Extra</span>
        <strong>${esc(policy.displayName || 'Unnamed tenant policy')}</strong>
        <em>Review manually</em>
      </summary>
      <div class="comparison-body">
        <p>This tenant policy is not matched to the current rebuild set. Keep it only if it has a documented purpose outside this design.</p>
        <dl>
          <dt>State</dt><dd>${esc(policy.state || 'not set')}</dd>
          <dt>Grant controls</dt><dd>${esc(formatCompareValue(policy.grantControls || 'none'))}</dd>
          <dt>Session controls</dt><dd>${esc(formatCompareValue(policy.sessionControls || 'none'))}</dd>
        </dl>
      </div>
    </details>`;
  }

  function renderRiskFindingCard(finding) {
    return `<details class="comparison-card status-risk">
      <summary>
        <span class="status-chip import-risk">Risk</span>
        <strong>${esc(finding.title)}</strong>
        <em>${esc(finding.action || 'Review')}</em>
      </summary>
      <div class="comparison-body">
        <p>${esc(finding.body)}</p>
      </div>
    </details>`;
  }

  function shortName(name) {
    return String(name).replace(/^CA\d+-/, '').replace(/-/g, ' ');
  }

  function policyDisplayLine(policy) {
    return String(policy.displayName || shortName(policy.id)).replace(/-/g, ' ');
  }

  function decisionText(policy, decision) {
    if (decision === 'exclude') return 'Excluded policies stay visible as design gaps but do not appear in exports.';
    if (decision === 'monitor') {
      if (NON_REPORT_ONLY.has(policy.id)) return 'This policy cannot be report-only, so report-only exports it disabled.';
      return 'Monitor exports this as report-only so sign-in impact can be observed before enforcement.';
    }
    if (isPreviewPolicy(policy)) return 'Include exports this policy enabled with Microsoft Graph beta/preview fields.';
    return 'Include exports this policy enabled in the configured rebuild set.';
  }

  function isGuideOnlyPolicy(policy) {
    if (!policy || !state.guideOnly?.policyKeys?.length) return false;
    return state.guideOnly.policyKeys.includes(policyKey(policy));
  }

  function guideOnlyText() {
    const missing = state.guideOnly?.missing || [];
    if (!missing.length) return 'This policy is open for manual guidance only until required scenario object IDs are supplied.';
    return `Missing ${missing.map(item => item.field).join(', ')}. Add the required object ID${missing.length === 1 ? '' : 's'} in Scenario Planner before exporting Graph JSON.`;
  }

  function guideOnlySelectedPolicies() {
    return selectedPolicies().filter(isGuideOnlyPolicy);
  }

  function exportPolicy(item, mode) {
    const policy = clone(item.policy);
    const decision = state.decisions[policyKey(item)] || 'exclude';
    if (mode === 'disabled') {
      policy.state = 'disabled';
    } else if (mode === 'report') {
      policy.state = NON_REPORT_ONLY.has(item.id) ? 'disabled' : 'enabledForReportingButNotEnforced';
    } else if (decision === 'monitor') {
      policy.state = NON_REPORT_ONLY.has(item.id) ? 'disabled' : 'enabledForReportingButNotEnforced';
    } else if (decision === 'include') {
      policy.state = 'enabled';
    } else {
      policy.state = 'disabled';
    }
    applyOverrides(policy, state.overrides[policyKey(item)]);
    return sanitizePolicy(policy);
  }

  function sanitizePolicy(policy) {
    const out = {
      displayName: policy.displayName,
      state: policy.state,
      conditions: policy.conditions || {}
    };
    if (policy.grantControls) out.grantControls = policy.grantControls;
    if (policy.sessionControls) out.sessionControls = policy.sessionControls;
    return out;
  }

  function applyOverrides(policy, override) {
    if (!override) return;
    OVERRIDE_FIELDS.forEach(field => {
      const values = parseList(override[field.id]);
      if (!values.length) return;
      setPath(policy, field.path, values);
    });
  }

  function setPath(target, path, value) {
    let cursor = target;
    path.slice(0, -1).forEach(part => {
      if (!cursor[part] || typeof cursor[part] !== 'object') cursor[part] = {};
      cursor = cursor[part];
    });
    cursor[path[path.length - 1]] = value;
  }

  function parseList(value) {
    return Array.from(new Set(String(value || '')
      .split(/[\n,]+/)
      .map(item => item.trim())
      .filter(Boolean)));
  }

  function ensureOverride(key) {
    if (!state.overrides[key]) state.overrides[key] = {};
    return state.overrides[key];
  }

  async function copySelectedJson() {
    const policy = selectedPolicy();
    if (!policy) return;
    state.activeTab = 'policy-recommendations';
    renderTabs();
    if (isGuideOnlyPolicy(policy)) {
      toast('Add required scenario object IDs before copying policy JSON');
      renderSelected();
      return;
    }
    copyText(JSON.stringify(exportPolicy(policy, 'configured'), null, 2), 'Policy JSON copied');
  }

  async function copySelectedPolicyName() {
    const policy = selectedPolicy();
    if (!policy) return;
    state.activeTab = 'policy-recommendations';
    renderTabs();
    copyText(exportPolicy(policy, 'configured').displayName, 'Policy name copied');
  }

  async function copySelectedManualGuide() {
    const policy = selectedPolicy();
    if (!policy) return;
    state.activeTab = 'policy-recommendations';
    renderTabs();
    copyText(manualGuideText(policy), 'Manual checklist copied');
  }

  async function copyText(text, successMessage) {
    try {
      await navigator.clipboard.writeText(text);
      toast(successMessage);
    } catch {
      toast('Copy unavailable in this browser');
    }
  }

  function manualGuideText(item) {
    const decision = state.decisions[policyKey(item)] || 'exclude';
    const exported = exportPolicy(item, 'configured');
    return manualGuideSections(item, exported, decision)
      .map(section => ({ ...section, rows: state.expertMode ? section.rows : section.rows.filter(row => !row.empty) }))
      .filter(section => section.rows.length)
      .map(section => {
      const rows = section.rows.map(row => {
        const help = row.help ? ` (${row.help})` : '';
        const value = row.entries ? manualEntriesText(row.entries, state.expertMode) : row.value;
        return `- ${row.label}: ${value}${help}`;
      }).join('\n');
      return `${section.step}. ${section.title}\n${section.desc}\n${rows}`;
    }).join('\n\n');
  }

  function manualEntriesText(entries, includeIds = true) {
    return entries.map(entry => {
      if (entry.lookup) return entry.text;
      if (entry.id) return includeIds ? `${entry.name} (Object ID: ${entry.id})` : entry.name;
      return entry.text || entry.name || '';
    }).join('\n');
  }

  function exportSet(mode) {
    state.activeTab = 'policy-recommendations';
    renderTabs();
    const selected = selectedPolicies();
    if (!selected.length) {
      toast('No policies included in the rebuild set');
      return;
    }
    const blocked = selected.filter(isGuideOnlyPolicy);
    if (blocked.length) {
      toast('Add required scenario object IDs before exporting Graph JSON');
      renderWarnings();
      renderSelected();
      return;
    }
    const value = selected.map(policy => exportPolicy(policy, mode));
    downloadJson({ value }, `ca-architect-v2-${mode}-${new Date().toISOString().slice(0, 10)}.json`);
    toast(`Exported ${value.length} policies`);
  }

  function downloadJson(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function safeFilename(value) {
    return String(value || 'conditional-access-policy').replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase();
  }

  function analyseImportText() {
    state.activeTab = 'import-compare';
    const text = $('importText').value.trim();
    if (!text) {
      renderTabs();
      toast('Paste or drop JSON first');
      return;
    }
    try {
      const parsed = parseImportPayload(text);
      state.imported = parsed.policies;
      state.objectCatalog = parsed.objectCatalog;
      if (state.imported.length) {
        compareImported();
      } else {
        state.compareReport = null;
        state.compare = new Map();
        state.extra = [];
      }
      renderAll();
      const objectText = state.objectCatalog.size ? ` and loaded ${state.objectCatalog.size} object names` : '';
      toast(`Analysed ${state.imported.length} policies${objectText}`);
    } catch (err) {
      state.compareReport = null;
      state.compare = new Map();
      state.extra = [];
      $('importStatus').textContent = err.message || 'Could not parse import';
      renderTabs();
      toast('Import failed');
    }
  }

  function clearImport() {
    state.activeTab = 'import-compare';
    state.imported = [];
    state.compare = new Map();
    state.extra = [];
    state.compareReport = null;
    state.importFilter = 'all';
    state.objectCatalog = new Map();
    $('importText').value = '';
    renderAll();
    toast('Import cleared');
  }

  function handleFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      $('importText').value = typeof result === 'string' ? result : decodeArrayBuffer(result);
      analyseImportText();
    };
    reader.readAsArrayBuffer(file);
  }

  function decodeArrayBuffer(buffer) {
    const bytes = new Uint8Array(buffer);
    if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes.slice(2));
    return new TextDecoder('utf-8').decode(bytes);
  }

  function parseImportPayload(text) {
    const data = JSON.parse(text.replace(/^\uFEFF/, ''));
    const objectCatalog = extractObjectCatalog(data);
    const extracted = dedupePolicies(extractImportedPolicies(data));
    if (!extracted.length && !objectCatalog.size) {
      throw new Error('No Conditional Access policies or object catalog entries found. Paste a Graph export, an IntuneManagement export, or JSON containing objects with id and displayName.');
    }
    return { policies: extracted.map(policy => stripNoise(policy)), objectCatalog };
  }

  function normaliseImport(text) {
    return parseImportPayload(text).policies;
  }

  function extractObjectCatalog(value, seen = new WeakSet(), depth = 0, parentKey = '') {
    const catalog = new Map();
    const add = item => {
      if (!item) return;
      catalog.set(objectCatalogKey(item.id, item.type), item);
    };
    if (depth > 25 || value === null || value === undefined) return catalog;
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed || !/^[\[{]/.test(trimmed)) return catalog;
      try {
        return extractObjectCatalog(JSON.parse(trimmed), seen, depth + 1, parentKey);
      } catch {
        return catalog;
      }
    }
    if (Array.isArray(value)) {
      value.forEach(item => {
        mergeCatalog(catalog, extractObjectCatalog(item, seen, depth + 1, parentKey));
      });
      return catalog;
    }
    if (typeof value !== 'object') return catalog;
    if (seen.has(value)) return catalog;
    seen.add(value);

    normalizeCatalogObject(value, parentKey).forEach(add);
    Object.entries(value)
      .filter(([key]) => !key.startsWith('@odata') && !key.includes('@odata'))
      .forEach(([key, child]) => mergeCatalog(catalog, extractObjectCatalog(child, seen, depth + 1, key)));
    return catalog;
  }

  function mergeCatalog(target, source) {
    source.forEach((value, key) => target.set(key, value));
    return target;
  }

  function normalizeCatalogObject(value, parentKey) {
    if (!value || typeof value !== 'object' || isConditionalAccessPolicy(normalizeImportedPolicy(value))) return [];
    const type = catalogTypeFromObject(value, parentKey);
    const name = value.displayName || value.DisplayName || value.name || value.Name || value.display_name;
    const ids = [
      value.id,
      value.Id,
      value.objectId,
      value.ObjectId,
      value.objectID,
      value.appId,
      value.AppId,
      value.applicationId,
      value.ApplicationId
    ].filter(id => isGuid(id));
    if (!type || !name || !ids.length) return [];
    return Array.from(new Set(ids.map(id => String(id).toLowerCase()))).map(id => ({
      id,
      name: String(name),
      type,
      source: 'import'
    }));
  }

  function catalogTypeFromObject(value, parentKey) {
    const key = String(parentKey || '').toLowerCase();
    const odata = String(value['@odata.type'] || value.odataType || '').toLowerCase();
    const type = String(value.type || value.Type || value.objectType || value.ObjectType || '').toLowerCase();
    const combined = `${key} ${odata} ${type}`;
    if (/directoryroles?|roledefinitions?|roletemplates?/.test(combined)) return 'role';
    if (/groups?/.test(combined)) return 'group';
    if (/serviceprincipals?/.test(combined)) return 'servicePrincipal';
    if (/agent/.test(combined)) return 'agentIdentity';
    if (/namedlocations?|locations?/.test(combined)) return 'location';
    if (/applications?|apps?/.test(combined)) return 'application';
    if (/termsofuse/.test(combined)) return 'termsOfUse';
    return '';
  }

  function extractImportedPolicies(value, seen = new WeakSet(), depth = 0) {
    if (depth > 25 || value === null || value === undefined) return [];
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed || !/^[\[{]/.test(trimmed)) return [];
      try {
        return extractImportedPolicies(JSON.parse(trimmed), seen, depth + 1);
      } catch {
        return [];
      }
    }
    if (Array.isArray(value)) {
      return value.flatMap(item => extractImportedPolicies(item, seen, depth + 1));
    }
    if (typeof value !== 'object') return [];
    if (seen.has(value)) return [];
    seen.add(value);

    const normalized = normalizeImportedPolicy(value);
    if (isConditionalAccessPolicy(normalized)) return [normalized];

    return Object.entries(value)
      .filter(([key]) => !key.startsWith('@odata') && !key.includes('@odata'))
      .flatMap(([, child]) => extractImportedPolicies(child, seen, depth + 1));
  }

  function normalizeImportedPolicy(value) {
    const policy = clone(value);
    if (!policy.displayName) policy.displayName = policy.DisplayName || policy.name || policy.Name || policy.display_name;
    if (!policy.state) policy.state = policy.State;
    if (!policy.conditions) policy.conditions = policy.Conditions;
    if (!policy.grantControls) policy.grantControls = policy.GrantControls || policy.grantcontrols;
    if (!policy.sessionControls) policy.sessionControls = policy.SessionControls || policy.sessioncontrols;
    return policy;
  }

  function isConditionalAccessPolicy(policy) {
    if (!policy || typeof policy !== 'object') return false;
    const hasDisplayName = typeof policy.displayName === 'string' && policy.displayName.trim().length > 0;
    const hasPolicyShape = Boolean(policy.conditions || policy.grantControls || policy.sessionControls || policy.state);
    const hasCaName = hasDisplayName && /conditional\s*access|^ca\d+[-\s_]|identityprotection|attack\s*surface|baseprotection|dataprotection|admins|guest|agent/i.test(policy.displayName);
    return hasPolicyShape && (hasDisplayName || hasCaName);
  }

  function dedupePolicies(policies) {
    const seen = new Set();
    return policies.filter(policy => {
      const key = `${normName(policy.displayName)}|${fingerprint(policy)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function stripNoise(value) {
    if (Array.isArray(value)) return value.map(stripNoise).filter(item => item !== undefined);
    if (value && typeof value === 'object') {
      const out = {};
      Object.entries(value).forEach(([key, val]) => {
        if (key.startsWith('@odata') || key.includes('@odata') || key.startsWith('#microsoft.graph')) return;
        if (['id', 'templateId', 'createdDateTime', 'modifiedDateTime', 'deletedDateTime', 'partialEnablementStrategy'].includes(key)) return;
        const stripped = stripNoise(val);
        if (stripped === undefined || stripped === null) return;
        if (Array.isArray(stripped) && stripped.length === 0) return;
        if (typeof stripped === 'object' && !Array.isArray(stripped) && Object.keys(stripped).length === 0) return;
        out[key] = stripped;
      });
      return out;
    }
    return value;
  }

  function compareImported() {
    const used = new Set();
    state.compare = new Map();
    const expectedPolicies = state.auditTarget === 'baseline' ? baselinePolicies() : selectedPolicies();
    const results = expectedPolicies.map(item => compareExpectedPolicy(item, used));
    results.forEach(result => state.compare.set(policyKey(result.item), result));
    state.extra = state.imported.filter((_, index) => !used.has(index));
    const risks = riskFindings(results, state.extra);
    const summary = {
      imported: state.imported.length,
      expected: results.length,
      exact: results.filter(item => item.status === 'exact').length,
      different: results.filter(item => item.status === 'different' || item.status === 'likely').length,
      missing: results.filter(item => item.status === 'missing').length,
      extra: state.extra.length,
      risk: risks.length
    };
    state.compareReport = { results, extras: state.extra, risks, summary };
  }

  function compareExpectedPolicy(item, used) {
    const expected = state.auditTarget === 'baseline' ? sanitizePolicy(item.policy) : exportPolicy(item, 'configured');
    const match = findImportedMatch(item, expected, used);
    if (!match) {
      return {
        item,
        status: 'missing',
        label: 'Missing',
        action: 'Create',
        toolName: expected.displayName,
        tenantName: '',
        matchMethod: '',
        reason: 'No imported tenant policy matched this selected rebuild-set policy.',
        diffs: []
      };
    }
    used.add(match.index);
    const imported = state.imported[match.index];
    const diffs = diffPolicies(expected, imported);
    if (!diffs.length && match.method !== 'semantic' && match.method !== 'fuzzy') {
      return {
        item,
        status: 'exact',
        label: 'Exact',
        action: 'Keep',
        toolName: expected.displayName,
        tenantName: imported.displayName,
        matchMethod: match.label,
        reason: 'Tenant policy matches the configured export for all compared fields.',
        diffs
      };
    }
    if (!diffs.length) {
      return {
        item,
        status: 'likely',
        label: 'Likely same purpose',
        action: 'Review manually',
        toolName: expected.displayName,
        tenantName: imported.displayName,
        matchMethod: match.label,
        reason: 'The settings match, but the tenant policy name is different from the tool policy name.',
        diffs
      };
    }
    const samePurpose = match.method === 'intent';
    const likely = samePurpose || match.method === 'semantic' || match.method === 'fuzzy';
    return {
      item,
      status: likely ? 'likely' : 'different',
      label: samePurpose ? 'Same purpose, review settings' : likely ? 'Likely same purpose' : 'Different',
      action: likely ? 'Review manually' : 'Update',
      toolName: expected.displayName,
      tenantName: imported.displayName,
      matchMethod: match.label,
      reason: likely
        ? 'A tenant policy appears to cover the same purpose, but key settings differ from the rebuild-set export.'
        : 'A tenant policy matched by name or baseline ID, but key settings differ from the rebuild-set export.',
      diffs
    };
  }

  function findImportedMatch(item, expected, used) {
    const candidates = state.imported
      .map((policy, index) => ({ policy, index }))
      .filter(candidate => !used.has(candidate.index));
    const exactName = candidates.find(candidate => normName(candidate.policy.displayName) === normName(expected.displayName));
    if (exactName) return { ...exactName, method: 'name', label: 'Exact display-name match' };
    const expectedId = item.id;
    const idMatch = candidates.find(candidate => policyNameIds(candidate.policy.displayName).includes(expectedId.toLowerCase()));
    if (idMatch) return { ...idMatch, method: 'baseline-id', label: `Baseline ID ${expectedId} match` };
    const intentMatches = candidates
      .map(candidate => ({ ...candidate, intent: intentSimilarity(expected, candidate.policy) }))
      .filter(candidate => candidate.intent.score >= 0.58 && candidate.intent.shared.length > 0)
      .sort((a, b) => b.intent.score - a.intent.score);
    if (intentMatches[0]) {
      return {
        ...intentMatches[0],
        method: 'intent',
        label: `Matched by purpose: ${intentMatches[0].intent.sharedLabels.join(', ')}`
      };
    }
    const semanticMatches = candidates
      .map(candidate => ({ ...candidate, score: semanticSimilarity(expected, candidate.policy) }))
      .filter(candidate => candidate.score >= 0.76)
      .sort((a, b) => b.score - a.score);
    if (semanticMatches[0]) return { ...semanticMatches[0], method: 'semantic', label: `Semantic controls match (${Math.round(semanticMatches[0].score * 100)}%)` };
    const fuzzyMatches = candidates
      .map(candidate => ({ ...candidate, score: similarity(fingerprint(expected), fingerprint(candidate.policy)) }))
      .filter(candidate => candidate.score >= 0.72)
      .sort((a, b) => b.score - a.score);
    if (fuzzyMatches[0]) return { ...fuzzyMatches[0], method: 'fuzzy', label: `Closest fingerprint match (${Math.round(fuzzyMatches[0].score * 100)}%)` };
    return null;
  }

  function policyNameIds(name) {
    return String(name || '').toLowerCase().match(/ca\d{3}/g) || [];
  }

  function intentSimilarity(expected, imported) {
    const expectedIntent = policyIntent(expected);
    const importedIntent = policyIntent(imported);
    const expectedTokens = new Set(expectedIntent.tokens);
    const importedTokens = new Set(importedIntent.tokens);
    const shared = [...expectedTokens].filter(token => importedTokens.has(token));
    const orderedShared = shared.sort((a, b) => intentPriority(b) - intentPriority(a) || a.localeCompare(b));
    const denominator = Math.max(expectedTokens.size, importedTokens.size, 1);
    const coreHit = expectedIntent.core.some(token => importedTokens.has(token));
    const score = shared.length / denominator + (coreHit ? 0.25 : 0);
    return {
      score: Math.min(1, score),
      shared: orderedShared,
      sharedLabels: orderedShared.slice(0, 3).map(intentLabel)
    };
  }

  function intentPriority(token) {
    if (token.startsWith('purpose:')) return 5;
    if (token.startsWith('risk:')) return 4;
    if (token.startsWith('grant:')) return 3;
    if (token.startsWith('session:')) return 3;
    if (token.startsWith('agent:')) return 2;
    if (token.startsWith('scope:')) return 1;
    return 0;
  }

  function policyIntent(policy) {
    const normalized = {
      conditions: normalizeConditions(policy.conditions || {}),
      grant: normalizeGrantControls(policy.grantControls || {}),
      session: normalizeSessionControls(policy.sessionControls || {})
    };
    const tokens = new Set();
    const name = String(policy.displayName || '').toLowerCase();
    const add = token => tokens.add(token);

    normalized.conditions.clientApps.forEach(value => add(`client:${value}`));
    normalized.conditions.apps.forEach(value => add(`app:${value}`));
    normalized.conditions.userActions.forEach(value => add(`action:${value}`));
    normalized.conditions.platforms.forEach(value => add(`platform:${value}`));
    normalized.conditions.locations.forEach(value => add(`location:${value}`));
    normalized.conditions.userScope.forEach(value => add(`user:${value}`));
    normalized.conditions.risks.forEach(value => add(`risk:${value}`));
    normalized.conditions.agent.forEach(value => add(`agent:${value}`));
    normalized.grant.tokens.forEach(add);
    normalized.session.tokens.forEach(add);

    if (name.includes('legacy') || normalized.conditions.clientApps.some(value => ['exchangeactivesync', 'other'].includes(value))) add('purpose:block-legacy-auth');
    if (normalized.grant.tokens.includes('grant:block')) add('purpose:block-access');
    if (normalized.grant.tokens.includes('grant:mfa')) add('purpose:require-mfa');
    if (normalized.grant.tokens.includes('grant:auth-strength-phishing-resistant') || name.includes('phishing-resistant')) add('purpose:require-phishing-resistant-mfa');
    if (normalized.conditions.risks.includes('signin-high') || name.includes('highrisksignin') || name.includes('risky sign-in')) add('purpose:block-high-signin-risk');
    if (normalized.conditions.risks.includes('user-high') || name.includes('highriskuser') || name.includes('password change')) add('purpose:block-high-user-risk');
    if (normalized.session.tokens.includes('session:signin-frequency') || name.includes('signinfrequency') || name.includes('sign-in frequency')) add('purpose:session-signin-frequency');
    if (normalized.session.tokens.includes('session:persistent-browser') || name.includes('persistentbrowser') || name.includes('persistent browser')) add('purpose:session-persistent-browser');
    if (normalized.session.tokens.includes('session:cae') || name.includes('continuousaccessevaluation')) add('purpose:continuous-access-evaluation');
    if (normalized.grant.tokens.includes('grant:compliant-device') || name.includes('compliant')) add('purpose:require-compliant-device');
    if (normalized.grant.tokens.includes('grant:approved-app') || normalized.grant.tokens.includes('grant:app-protection') || name.includes('app protection')) add('purpose:app-protection');
    if (normalized.conditions.locations.length || name.includes('location')) add('purpose:location-control');
    if (normalized.conditions.userScope.includes('guest') || name.includes('guest')) add('purpose:guest-controls');
    if (normalized.conditions.agent.length || name.includes('agent')) add('purpose:agent-controls');
    if (normalized.conditions.userScope.includes('admin-role') || name.includes('admin')) add('scope:admins');
    if (normalized.conditions.userScope.includes('all-users')) add('scope:all-users');
    if (normalized.conditions.apps.includes('all')) add('scope:all-apps');
    if (normalized.conditions.apps.includes('office365')) add('scope:office365');

    const core = [...tokens].filter(token => token.startsWith('purpose:'));
    return { tokens: [...tokens].sort(), core };
  }

  function normalizeConditions(conditions) {
    const users = conditions.users || {};
    const applications = conditions.applications || {};
    const platforms = conditions.platforms || {};
    const locations = conditions.locations || {};
    const clientApplications = conditions.clientApplications || {};
    const userScope = [];
    if (includesToken(users.includeUsers, 'All')) userScope.push('all-users');
    if (includesToken(users.includeUsers, 'AllAgentIdUsers')) userScope.push('agent-users');
    if (hasAny(users.includeRoles)) userScope.push('admin-role');
    if (hasAny(users.includeGroups)) userScope.push('group-targeted');
    if (hasAny(users.excludeUsers) || hasAny(users.excludeGroups) || hasAny(users.excludeRoles)) userScope.push('has-exclusions');

    const apps = normalizeApplications(applications);
    const risks = [
      ...(conditions.signInRiskLevels || []).map(level => `signin-${String(level).toLowerCase()}`),
      ...(conditions.userRiskLevels || []).map(level => `user-${String(level).toLowerCase()}`),
      ...(conditions.agentIdRiskLevels || []).map(level => `agent-${String(level).toLowerCase()}`)
    ];
    const agent = [];
    if (includesToken(applications.includeApplications, 'AllAgentIdResources')) agent.push('all-agent-resources');
    if (includesToken(users.includeUsers, 'AllAgentIdUsers')) agent.push('all-agent-users');
    if (hasAny(clientApplications.includeAgentIdServicePrincipals)) agent.push('agent-service-principals');
    if (hasAny(clientApplications.excludeAgentIdServicePrincipals)) agent.push('agent-exclusions');

    return {
      clientApps: (conditions.clientAppTypes || []).map(value => String(value).toLowerCase()).sort(),
      apps,
      userActions: (applications.includeUserActions || []).map(value => String(value).toLowerCase()).sort(),
      platforms: [...(platforms.includePlatforms || []), ...(platforms.excludePlatforms || []).map(value => `exclude-${value}`)].map(value => String(value).toLowerCase()).sort(),
      locations: [...(locations.includeLocations || []), ...(locations.excludeLocations || []).map(value => `exclude-${value}`)].map(value => String(value).toLowerCase()).sort(),
      userScope: userScope.sort(),
      risks: risks.sort(),
      agent: agent.sort()
    };
  }

  function normalizeApplications(applications) {
    const values = [...(applications.includeApplications || []), ...(applications.excludeApplications || []).map(value => `exclude-${value}`)]
      .map(value => String(value).toLowerCase());
    return values.map(value => {
      if (value === 'all') return 'all';
      if (value === 'office365' || value.includes('office')) return 'office365';
      if (value === 'allagentidresources') return 'all-agent-resources';
      return value;
    }).sort();
  }

  function normalizeGrantControls(grantControls) {
    const controls = grantControls.builtInControls || [];
    const tokens = controls.map(control => `grant:${String(control).toLowerCase()}`);
    const authStrength = grantControls.authenticationStrength || {};
    const authName = String(authStrength.displayName || authStrength.id || '').toLowerCase();
    if (authName.includes('phishing')) tokens.push('grant:auth-strength-phishing-resistant');
    if (authName.includes('multifactor') || authName.includes('mfa')) tokens.push('grant:mfa');
    if ((grantControls.operator || '').toLowerCase()) tokens.push(`grant-operator:${String(grantControls.operator).toLowerCase()}`);
    if (controls.includes('compliantDevice')) tokens.push('grant:compliant-device');
    if (controls.includes('approvedApplication')) tokens.push('grant:approved-app');
    if (controls.includes('compliantApplication')) tokens.push('grant:app-protection');
    return { tokens: Array.from(new Set(tokens)).sort() };
  }

  function normalizeSessionControls(sessionControls) {
    const tokens = [];
    if (sessionControls.signInFrequency) tokens.push('session:signin-frequency');
    if (sessionControls.persistentBrowser) tokens.push('session:persistent-browser');
    if (sessionControls.continuousAccessEvaluation) tokens.push('session:cae');
    if (sessionControls.applicationEnforcedRestrictions) tokens.push('session:app-enforced-restrictions');
    if (sessionControls.cloudAppSecurity) tokens.push('session:cloud-app-security');
    return { tokens: tokens.sort() };
  }

  function intentLabel(token) {
    return token
      .replace(/^purpose:/, '')
      .replace(/^scope:/, '')
      .replace(/^grant:/, '')
      .replace(/^risk:/, '')
      .replace(/^session:/, '')
      .replace(/-/g, ' ');
  }

  function diffPolicies(expected, imported) {
    return COMPARE_FIELDS.flatMap(field => {
      const expectedValue = comparableValue(pathValue(expected, field.path));
      const actualValue = comparableValue(pathValue(imported, field.path));
      if (JSON.stringify(expectedValue) === JSON.stringify(actualValue)) return [];
      if (isEmptyCompareValue(expectedValue) && isEmptyCompareValue(actualValue)) return [];
      return [{ label: field.label, path: field.path.join('.'), expected: expectedValue, actual: actualValue }];
    });
  }

  function pathValue(obj, path) {
    return path.reduce((cursor, part) => (cursor && cursor[part] !== undefined ? cursor[part] : undefined), obj);
  }

  function comparableValue(value) {
    return stable(stripNoise(value));
  }

  function isEmptyCompareValue(value) {
    if (value === undefined || value === null || value === '') return true;
    if (Array.isArray(value) && !value.length) return true;
    return Boolean(value && typeof value === 'object' && !Array.isArray(value) && !Object.keys(value).length);
  }

  function formatCompareValue(value) {
    if (isEmptyCompareValue(value)) return 'empty';
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  }

  function semanticSimilarity(a, b) {
    return similarity(semanticFingerprint(a), semanticFingerprint(b));
  }

  function semanticFingerprint(policy) {
    const semantic = {};
    COMPARE_FIELDS.forEach(field => {
      semantic[field.path.join('.')] = comparableValue(pathValue(policy, field.path));
    });
    return JSON.stringify(stable(semantic)).toLowerCase();
  }

  function riskFindings(results, extras) {
    const findings = [];
    results.filter(result => result.status === 'missing').forEach(result => {
      findings.push({
        title: `${result.item.id} missing from tenant`,
        body: `${result.toolName} is selected in the rebuild set but no tenant policy matched it.`,
        action: 'Create'
      });
    });
    results.filter(result => isPreviewPolicy(result.item) && result.status !== 'exact').forEach(result => {
      findings.push({
        title: `${result.item.id} preview or agent policy needs review`,
        body: `${result.toolName} uses preview/agent identity fields and is ${result.label.toLowerCase()} in the tenant comparison.`,
        action: 'Review'
      });
    });
    state.imported.forEach(policy => {
      if (isBroadBlockWithoutExclusion(policy) && policy.state === 'enabled') {
        findings.push({
          title: 'Tenant lockout hazard',
          body: `${policy.displayName || 'Unnamed policy'} blocks broad users and resources without visible user, group, or role exclusions.`,
          action: 'Fix exclusions'
        });
      }
    });
    extras.forEach(policy => {
      if (policy.state === 'enabled' && isBlockPolicy(policy)) {
        findings.push({
          title: 'Extra enabled block policy',
          body: `${policy.displayName || 'Unnamed policy'} is enabled in the tenant but is not part of the current rebuild set.`,
          action: 'Review manually'
        });
      }
    });
    return findings;
  }

  function normName(value) {
    return String(value || '').toLowerCase().replace(/\s+/g, '').replace(/[\u2013\u2014]/g, '-');
  }

  function stable(value) {
    if (Array.isArray(value)) return value.map(stable).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    if (value && typeof value === 'object') {
      return Object.keys(value).sort().reduce((out, key) => {
        out[key] = stable(value[key]);
        return out;
      }, {});
    }
    return value;
  }

  function fingerprint(policy) {
    const core = {
      conditions: policy.conditions || {},
      grantControls: policy.grantControls || null,
      sessionControls: policy.sessionControls || null,
      state: policy.state || null
    };
    return JSON.stringify(stable(core)).toLowerCase();
  }

  function similarity(a, b) {
    const setA = new Set(a.match(/[a-z0-9]+/g) || []);
    const setB = new Set(b.match(/[a-z0-9]+/g) || []);
    if (!setA.size || !setB.size) return 0;
    let hit = 0;
    setA.forEach(value => {
      if (setB.has(value)) hit += 1;
    });
    return hit / Math.max(setA.size, setB.size);
  }

  function safetyWarnings() {
    const warnings = [
      { text: 'Confirm Security Defaults are disabled before deploying Conditional Access policies.', critical: false },
      { text: 'Add and test break-glass exclusions before enabling broad block or MFA policies.', critical: true }
    ];
    if (!state.selectedThreats.size && !state.appliedStrategy) {
      warnings.push({ text: 'No threats are selected. Current recommendations are only from identity and target scope until threats are chosen or the recommended strategy is loaded.', critical: false });
    }
    if (state.guideOnly?.missing?.length) {
      warnings.push({ text: `Scenario build guide is open for manual planning only. ${guideOnlyText()}`, critical: true });
    }
    selectedPolicies().forEach(item => {
      const decision = state.decisions[policyKey(item)];
      const exported = exportPolicy(item, 'configured');
      if (decision === 'monitor' && NON_REPORT_ONLY.has(item.id)) {
        warnings.push({ text: `${item.id} cannot be report-only and exports disabled in monitor/report-only modes.`, critical: false });
      }
      if (isPreviewPolicy(item)) {
        warnings.push({ text: `${item.id} uses Microsoft Graph beta/preview Conditional Access fields for agent identities or agent resources.`, critical: false });
      }
      if (item.id === 'CA001' && decision === 'include') {
        warnings.push({ text: 'CA001 blocks by country whitelist. Validate ALLOWED COUNTRIES before enabling.', critical: true });
      }
      if (item.id === 'CA502' && decision === 'include') {
        warnings.push({ text: 'CA502 blocks all agent identities except approved exclusions. Start in monitor unless agent inventory is complete.', critical: true });
      }
      if (isAgentIdentityPolicy(exported) && !isBlockPolicy(exported)) {
        warnings.push({ text: `${item.id} targets agent identities, but Microsoft guidance only supports block controls for agent identities.`, critical: true });
      }
      if (isBroadBlockWithoutExclusion(exported)) {
        warnings.push({ text: `${item.id} blocks broad users/resources without visible user, group, or role exclusions.`, critical: true });
      }
      if (item.id === 'CA503' || item.id === 'CA505') {
        warnings.push({ text: `${item.id} depends on endpoint or compliant network signals for agent users. Use only for endpoint-backed agents.`, critical: false });
      }
    });
    recommendedPolicies().forEach(item => {
      if (state.decisions[policyKey(item)] === 'exclude') {
        warnings.push({ text: `${item.id} is recommended by the selected threats but excluded from the rebuild set.`, critical: false });
      }
    });
    return warnings;
  }

  function isPreviewPolicy(item) {
    if (item.preview) return true;
    const policy = item.policy || item;
    const conditions = policy.conditions || {};
    const applications = conditions.applications || {};
    const clientApplications = conditions.clientApplications || {};
    const users = conditions.users || {};
    return Boolean(
      conditions.agentIdRiskLevels ||
      conditions.agents ||
      conditions.agentContext ||
      hasAny(clientApplications.includeAgentIdServicePrincipals) ||
      hasAny(clientApplications.excludeAgentIdServicePrincipals) ||
      hasAny(clientApplications.agentIdServicePrincipalFilter) ||
      includesToken(applications.includeApplications, 'AllAgentIdResources') ||
      includesToken(users.includeUsers, 'AllAgentIdUsers')
    );
  }

  function hasAny(value) {
    if (Array.isArray(value)) return value.length > 0;
    return Boolean(value);
  }

  function includesToken(value, token) {
    return Array.isArray(value) && value.includes(token);
  }

  function isAgentIdentityPolicy(policy) {
    const shape = policy.policy || policy;
    const clientApplications = shape.conditions?.clientApplications || {};
    return hasAny(clientApplications.includeAgentIdServicePrincipals) || hasAny(clientApplications.excludeAgentIdServicePrincipals);
  }

  function isBlockPolicy(policy) {
    const shape = policy.policy || policy;
    return (shape.grantControls?.builtInControls || []).includes('block');
  }

  function isBroadBlockWithoutExclusion(policy) {
    const conditions = policy.conditions || {};
    const users = conditions.users || {};
    const applications = conditions.applications || {};
    const allUsers = includesToken(users.includeUsers, 'All') || includesToken(users.includeUsers, 'AllAgentIdUsers');
    const allApps = includesToken(applications.includeApplications, 'All') || includesToken(applications.includeApplications, 'AllAgentIdResources');
    const hasExclusions = hasAny(users.excludeUsers) || hasAny(users.excludeGroups) || hasAny(users.excludeRoles);
    return isBlockPolicy(policy) && allUsers && allApps && !hasExclusions;
  }

  function riskyImported() {
    return state.imported.flatMap(policy => {
      const conditions = policy.conditions || {};
      const users = conditions.users || {};
      const applications = conditions.applications || {};
      const allUsers = includesToken(users.includeUsers, 'All');
      const allApps = includesToken(applications.includeApplications, 'All');
      const exclusions = hasAny(users.excludeUsers) || hasAny(users.excludeGroups) || hasAny(users.excludeRoles);
      if (policy.state === 'enabled' && allUsers && allApps && isBlockPolicy(policy) && !exclusions) {
        return [{ title: 'Tenant lockout hazard', body: `${policy.displayName || 'Unnamed policy'} blocks all users and all apps without visible user exclusions.` }];
      }
      return [];
    });
  }

  function toast(message) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove('show'), 2600);
  }

  init();
})();
