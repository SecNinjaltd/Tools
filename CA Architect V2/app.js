(() => {
  'use strict';

  const BASELINE = window.CA_BASELINE;
  const DECISIONS = { include: 'include', monitor: 'monitor', exclude: 'exclude' };
  const NON_REPORT_ONLY = new Set(['CA104', 'CA209']);
  const RECOMMENDED_STRATEGY_THREATS = ['T1078', 'T1110', 'T1557', 'T1621', 'T1528', 'AGENT-RISK'];
  const THEME_STORAGE_KEY = 'caArchitectComplianceTheme';
  const EXPERT_STORAGE_KEY = 'caArchitectExpertDetail';
  const TEXT_SIZE_STORAGE_KEY = 'caArchitectTextSize';
  const SHARED_GROUPS = {
    workforce: { id: 'ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57', name: 'APP_Microsoft365_E5' },
    breakGlass: { id: '2802b872-ccfb-4b29-a9a9-459808dfb11b', name: 'CA-BreakGlassAccounts-Exclude' },
    serviceAccounts: { id: '77c1ed37-10d0-4ef1-93dc-198e70abb166', name: 'CA-ServiceAccounts' }
  };
  const SHARED_GROUP_IDS = new Set(Object.values(SHARED_GROUPS).map(group => group.id));
  const GLOBAL_PREREQUISITES = [
    `Create security group ${SHARED_GROUPS.breakGlass.name} for break-glass and emergency access exclusions`
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
    ['group', SHARED_GROUPS.workforce.id, SHARED_GROUPS.workforce.name],
    ['group', SHARED_GROUPS.breakGlass.id, SHARED_GROUPS.breakGlass.name],
    ['group', SHARED_GROUPS.serviceAccounts.id, SHARED_GROUPS.serviceAccounts.name],
    ['group', '7452a2db-063a-4048-84b0-ff691fa2900e', 'CA000 Global MFA - upstream policy exclusion'],
    ['group', '6499f521-8620-4f4e-92a1-db47c79362e8', 'CA001 Country whitelist - upstream policy exclusion'],
    ['group', '8861a932-f1d1-4d1d-a5e6-cdce20fada27', 'CA002 Legacy authentication - upstream policy exclusion'],
    ['group', 'c4906422-18aa-47d8-b808-8c4919b655d8', 'CA003 Device registration - upstream policy exclusion'],
    ['group', 'f389fc8e-3965-4ae0-aa53-87511ab05f2b', 'CA004 Authentication flows - upstream policy exclusion'],
    ['group', '20cd89e3-25e2-4fcd-82c5-de666dfd31a4', 'CA005 App protection - upstream policy exclusion'],
    ['group', 'a8e55fcf-f8ed-43c2-bb4f-0c62edd62963', 'CA006 App-enforced restrictions - upstream policy exclusion'],
    ['group', '70899f87-a5ba-4145-8bd5-2230db5dbbff', 'CA100 Admin portals - upstream policy exclusion'],
    ['group', '8e75af29-5176-4372-a718-724b8a4620dc', 'CA101 Admin MFA - upstream policy exclusion'],
    ['group', '5dcf5173-9efb-4f3f-a19d-2f03760d4e1d', 'CA102 Admin sign-in frequency - upstream policy exclusion'],
    ['group', 'b89d30c2-3cbb-4431-aaad-c866aec9d7ba', 'CA103 Admin browser persistence - upstream policy exclusion'],
    ['group', '03267499-cd03-41bd-865b-70703b9bdb4d', 'CA104 Admin continuous access evaluation - upstream policy exclusion'],
    ['group', 'ab2172b3-67e0-4b55-b538-21467c8ebd45', 'CA105 Admin phishing-resistant MFA - upstream policy exclusion'],
    ['group', 'cfa1f128-ec48-4ee1-9ea9-1c28fdb57722', 'CA200 Workforce MFA - upstream policy exclusion'],
    ['group', 'c80b6cc8-5981-484b-80f2-da0387fe4393', 'CA201 Workforce user risk - upstream policy exclusion'],
    ['group', '663dad60-a2c9-4228-afa5-a39fef078ad7', 'CA202 Workforce sign-in frequency - upstream policy exclusion'],
    ['group', '2eee133e-3427-4860-81b9-057d5b28b022', 'CA203 Intune enrollment - upstream policy exclusion'],
    ['group', '5002e94c-71d0-49ef-9633-b15168b0774c', 'CA204 Unknown platforms - upstream policy exclusion'],
    ['group', 'a76676e6-d7f2-45ff-9973-d6a28680db56', 'CA205 Windows compliance - upstream policy exclusion'],
    ['group', '9168105d-1b57-4863-8008-94e8c619ca45', 'CA206 Workforce browser persistence - upstream policy exclusion'],
    ['group', '25114fcf-1656-47dc-9b4e-5dd4a2f680d7', 'CA207 Selected apps - upstream policy exclusion'],
    ['group', '814dd6f8-2cc8-49a7-b360-b4887d686dc3', 'CA208 macOS compliance - upstream policy exclusion'],
    ['group', 'e7bb9f14-58fa-4a3f-9a7a-3c67cabc8788', 'CA209 Workforce continuous access evaluation - upstream policy exclusion'],
    ['group', '669c1f87-63ac-40c3-8fc2-fcc72e690e68', 'CA210 Workforce sign-in risk - upstream policy exclusion'],
    ['group', '68ce874b-21a9-4ca9-b447-f09a037be53a', 'CA300 Service account MFA - upstream policy exclusion'],
    ['group', '813e2655-e8b9-4255-91f5-7761ee2824bb', 'CA301 Service account location - upstream policy exclusion'],
    ['group', '349156c1-2fb1-4ffa-9cd3-5c4418e24e4c', 'CA400 Guest MFA - upstream policy exclusion'],
    ['group', 'dd82b6e5-6500-4616-93ec-c2558ba20813', 'CA401 Guest app access - upstream policy exclusion'],
    ['group', '0e4ab0ed-e589-46ad-80a2-f913b6b6b0ed', 'CA402 Guest sign-in frequency - upstream policy exclusion'],
    ['group', 'ffba4a95-5986-4d87-804a-1f354533a930', 'CA403 Guest browser persistence - upstream policy exclusion'],
    ['group', '86e8b29d-f7f2-4962-8a2d-65b8f0e5602f', 'CA404 Guest selected apps - upstream policy exclusion'],
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
  const WORKFLOW_TABS = new Set(['start', 'strategy-builder', 'scenario-planner', 'policy-recommendations', 'log-analysis']);
  const IMPORT_FILTERS = new Set(['all', 'exact', 'different', 'missing', 'extra', 'risk']);
  const LOG_FILTERS = new Set(['all', 'high', 'medium', 'low', 'info']);
  const LOG_SOURCE_FILTERS = new Set(['all', 'interactive', 'nonInteractive', 'application']);
  const LOG_JOURNEY_DECISIONS = [
    { id: 'enforcing', label: 'Enforcing policy applied', icon: 'shield-check', tone: 'protected', description: 'At least one enabled Conditional Access policy applied to the event.' },
    { id: 'reportOnly', label: 'Report-only matched', icon: 'document-search', tone: 'review', description: 'A report-only policy matched, but no enabled policy enforced a control.' },
    { id: 'workloadReportOnly', label: 'Workload policy matched, report-only', icon: 'document-search', tone: 'gap', description: 'An eligible workload policy matched in report-only mode while access continued.' },
    { id: 'byDesign', label: 'By-design exclusion', icon: 'branch', tone: 'neutral', description: 'The event was a recognised bootstrap or platform flow outside normal Conditional Access evaluation.' },
    { id: 'workloadBlindspot', label: 'Workload policy detail unavailable', icon: 'eye-off', tone: 'blind', description: 'The export did not return per-policy evaluation detail, so workload Conditional Access coverage cannot be inferred.' },
    { id: 'outsideCa', label: 'Outside workload CA eligibility', icon: 'external', tone: 'neutral', description: 'Tenant ownership evidence identifies a Microsoft, third-party or multitenant workload that Conditional Access for workload identities cannot target.' },
    { id: 'workloadReview', label: 'Workload policies evaluated, no match', icon: 'filter', tone: 'review', description: 'Workload policies were returned but did not apply. Review ownership, eligibility and scope before treating this as a gap.' },
    { id: 'filtered', label: 'Evaluated, no match', icon: 'filter', tone: 'gap', description: 'Policies were returned, but every policy was filtered out or did not apply.' },
    { id: 'noEvaluation', label: 'No policy evaluation returned', icon: 'shield-off', tone: 'gap', description: 'The export returned no policy evaluation for this event. CSV exports may not include the policy-level detail needed to explain why.' }
  ];
  const LOG_JOURNEY_OUTCOMES = [
    { id: 'blocked', label: 'Blocked by CA', icon: 'blocked', tone: 'protected', description: 'Conditional Access interrupted the sign-in.' },
    { id: 'protectedSuccess', label: 'Protected access succeeded', icon: 'shield-check', tone: 'protected', description: 'The sign-in succeeded after an enforcing policy applied.' },
    { id: 'allowedReportOnly', label: 'Allowed under report-only', icon: 'document-search', tone: 'review', description: 'The sign-in succeeded while the matching policy remained report-only.' },
    { id: 'workloadReportOnlyFlow', label: 'Workload access continued under report-only', icon: 'unlock', tone: 'gap', description: 'A matching workload policy was report-only, so its configured control was not enforced.' },
    { id: 'allowedWithoutCa', label: 'Allowed without a CA control', icon: 'unlock', tone: 'gap', description: 'The sign-in succeeded without an enforcing Conditional Access policy.' },
    { id: 'workloadUnknownFlow', label: 'Workload access, CA detail unknown', icon: 'eye-off', tone: 'blind', description: 'Access completed, but the export did not include enough workload policy detail to assess Conditional Access coverage.' },
    { id: 'workloadReviewFlow', label: 'Workload access, scope needs review', icon: 'document-search', tone: 'review', description: 'Workload policy evaluation was recorded, but eligibility and intended scope must be confirmed.' },
    { id: 'byDesignFlow', label: 'By-design platform flow', icon: 'branch', tone: 'neutral', description: 'A platform or bootstrap flow completed outside the normal user Conditional Access path.' },
    { id: 'outsideCaFlow', label: 'Outside Conditional Access', icon: 'external', tone: 'neutral', description: 'The workload is explicitly outside Conditional Access eligibility; govern it through permissions, credentials and vendor controls.' },
    { id: 'otherFailure', label: 'Other sign-in failure', icon: 'warning', tone: 'neutral', description: 'The event failed for a reason other than an observed Conditional Access block.' }
  ];
  const CA_COVERAGE_CATEGORIES = [
    {
      id: 'confirmedGap',
      label: 'Confirmed scoping gap',
      confidence: 'Confirmed from policy evaluation',
      tone: 'gap',
      interpretation: 'Conditional Access evaluated the successful sign-in, but every returned policy was filtered out or did not apply.',
      action: 'Review the returned policies and unsatisfied conditions, then widen only the assignment or condition that created the unintended gap.'
    },
    {
      id: 'reportOnlyExposure',
      label: 'Report-only exposure',
      confidence: 'Confirmed non-enforcement',
      tone: 'review',
      interpretation: 'A report-only user or workload policy matched, but no enabled policy enforced a control on the successful event.',
      action: 'Review report-only results, exclusions and user impact before moving the intended control through a staged rollout.'
    },
    {
      id: 'evidenceUnknown',
      label: 'Evidence unknown',
      confidence: 'Requires richer evidence or scope validation',
      tone: 'blind',
      interpretation: 'The event succeeded without enough returned policy detail to prove whether this is a scoping gap, an export limitation or an intended workload route.',
      action: 'Load the equivalent JSON sign-in export and validate the event in the Entra Conditional Access details before changing policy.'
    },
    {
      id: 'expectedOutsideCa',
      label: 'Expected outside CA',
      confidence: 'Recognised platform or eligibility boundary',
      tone: 'neutral',
      interpretation: 'The successful event followed a recognised platform flow or involved a workload that Conditional Access cannot target.',
      action: 'Do not count this as a bypass. Confirm the classification and govern the activity through the appropriate platform, credential, permission or vendor control.'
    }
  ];
  const LOG_LEARN_GUIDANCE = {
    deviceFilters: { label: 'Filter for devices', url: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-condition-filters-for-devices' },
    grantControls: { label: 'Conditional Access grant controls', url: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant' },
    sessionControls: { label: 'Conditional Access session controls', url: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-session' },
    externalDeviceTrust: { label: 'External-user device trust', url: 'https://learn.microsoft.com/entra/external-id/authentication-conditional-access' },
    reportOnly: { label: 'Report-only evaluation', url: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only' },
    deployment: { label: 'Plan a Conditional Access deployment', url: 'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access' }
  };
  const LOG_JOURNEY_GUIDANCE = {
    'device-identity': {
      notes: [
        'A device identity lets Conditional Access evaluate directory-backed device attributes. Registration or join state is useful context, but it does not prove compliance.',
        'Device filters evaluate registered devices. When the intent is to include unregistered devices, Microsoft recommends a negative operator because their device properties are null.',
        'The device-code OAuth flow cannot pass the authenticating device state to the device that displays the code; use an appropriate authentication control instead.'
      ],
      links: ['deviceFilters', 'grantControls']
    },
    'device-compliance': {
      notes: [
        'Compliance requires a registered device and a supported management path. A managed device that fails compliance needs remediation; an unmanaged device needs enrolment or a deliberate alternate access path.',
        'Microsoft Entra hybrid joined is a Windows-specific grant and should not be the default for a cloud-native estate.',
        'A compliant-device policy in report-only can still prompt macOS, iOS and Android users to select a device certificate during evaluation.'
      ],
      links: ['grantControls', 'reportOnly']
    },
    'byod-protection': {
      notes: [
        'App protection and restricted browser experiences are alternatives for supported unmanaged-device scenarios; they are not universal replacements for device compliance.',
        'External users can present compliance or hybrid-join claims from their home tenant only when cross-tenant inbound trust is configured.'
      ],
      links: ['grantControls', 'externalDeviceTrust']
    },
    'session-protection': {
      notes: [
        'Sign-in frequency, persistent browser, application-enforced restrictions, Conditional Access App Control, token protection and continuous access evaluation solve different problems.',
        'Recommend a session control only when the target application, client and operational requirement support it.'
      ],
      links: ['sessionControls']
    },
    'report-only-state': {
      notes: [
        'Report-only Success, Failure, User action required and Not applied describe different evaluation results. The report-only policy itself enforces nothing, but another enabled policy can still protect the same event.'
      ],
      links: ['reportOnly']
    },
    'runtime-coverage': {
      notes: [
        'Loaded sign-in sources and returned fields define what this assessment can prove. Policy configuration is not substituted for missing runtime evidence.'
      ],
      links: ['deployment']
    }
  };
  const LOG_DEVICE_CONTEXT_STATES = [
    { id: 'unregistered', label: 'No device identity' },
    { id: 'registeredNotCompliant', label: 'Registered but unmanaged' },
    { id: 'enrolledNotCompliant', label: 'Managed but noncompliant' },
    { id: 'compliant', label: 'Compliant' },
    { id: 'unknown', label: 'Posture not returned' }
  ];
  const LOG_RECOMMENDATION_PRIMARY_ELEMENT = {
    mfa: 'mfa-coverage',
    admin_mfa: 'mfa-coverage',
    phish_mfa: 'auth-strength',
    legacy_auth: 'legacy-controls',
    auth_flows: 'authentication-flows',
    unknown_platforms: 'authentication-flows',
    device_registration_mfa: 'device-identity',
    intune_enrollment_mfa: 'device-identity',
    device_compliance: 'device-compliance',
    agent_compliant_device: 'device-compliance',
    app_protection: 'byod-protection',
    session_controls: 'session-protection',
    persistent_browser: 'session-protection',
    admin_session: 'session-protection',
    sign_in_risk: 'risk-protection',
    user_risk: 'risk-protection',
    trusted_location: 'location-context',
    guest_access: 'guest-scope',
    selected_app_block: 'application-scope',
    users_agent_resources_block: 'application-scope',
    service_account_protection: 'service-account-scope',
    agent_identity_block: 'managed-identities',
    agent_users_block: 'managed-identities',
    agent_risk: 'managed-identities',
    agent_user_risk: 'managed-identities',
    agent_compliant_network: 'managed-identities'
  };
  const LOG_RECOMMENDATION_ACTION_TIERS = {
    actNow: { label: 'Act now', rank: 3 },
    validateFirst: { label: 'Validate first', rank: 2 },
    optionalAdvanced: { label: 'Optional / advanced', rank: 1 }
  };
  const LOG_RECOMMENDATION_CONTROL_DECLARATIONS = {
    device_compliance: ['intune'],
    intune_enrollment_mfa: ['intune'],
    app_protection: ['intune'],
    agent_compliant_device: ['intune', 'agents'],
    sign_in_risk: ['entraP2'],
    user_risk: ['entraP2'],
    trusted_location: ['locations'],
    guest_access: ['guests'],
    service_account_protection: ['serviceAccounts'],
    agent_risk: ['agents'],
    agent_identity_block: ['agents'],
    agent_user_risk: ['agents'],
    agent_compliant_network: ['agents', 'locations'],
    agent_users_block: ['agents'],
    users_agent_resources_block: ['agents']
  };
  const LOG_RECOMMENDATION_CAPABILITY_PREREQUISITES = {
    app_protection: 'Confirm the target platform, application and app-protection capability are supported.',
    session_controls: 'Confirm the selected session capability is supported by the target application and client.',
    persistent_browser: 'Confirm browser persistence behaviour is supported and appropriate for the target client.',
    admin_session: 'Confirm the selected administrator session controls are supported by the target application and client.',
    auth_flows: 'Confirm which authentication flows are in use and validate a supported control for each flow.',
    unknown_platforms: 'Confirm platform detection behaviour and the intended fallback path before blocking unknown platforms.',
    selected_app_block: 'Confirm the exact application scope and identifiers before creating a block policy.'
  };
  const LOG_JOURNEY_STAGES = [
    {
      id: 'scope', label: 'Scope & Targeting', icon: 'target', summary: 'Who and what the policy reaches.',
      elements: [
        { id: 'identity-scope', label: 'Workforce & admin scope', icon: 'users', findingIds: [], sources: ['interactive', 'nonInteractive'], why: 'Workforce and administrator assignments decide which human identities reach the rest of the policy.' },
        { id: 'guest-scope', label: 'Guest & external scope', icon: 'external', findingIds: ['guest-uncontrolled'], sources: ['interactive', 'nonInteractive'], why: 'Inbound guests remain subject to your tenant policies, while trusted claims and outbound access are governed through cross-tenant settings.' },
        { id: 'service-account-scope', label: 'Human service-account scope', icon: 'certificate', findingIds: [], sources: ['interactive', 'nonInteractive'], defaultStatus: 'review', why: 'Human-operated service accounts are user objects and can be protected by workforce Conditional Access; workload service principals use a separate policy and licensing boundary.' },
        { id: 'application-scope', label: 'Application scope', icon: 'applications', findingIds: ['uncovered-apps'], sources: ['interactive'], why: 'Target resources determine which applications and services are actually protected.' },
        { id: 'exclusions-filters', label: 'Exclusions & filters', icon: 'filter', findingIds: ['possible-exclusions'], sources: ['interactive'], field: 'appliedPolicies', why: 'Exclusions and filters can create deliberate exceptions or accidental coverage gaps.' }
      ]
    },
    {
      id: 'authentication', label: 'Authentication & Grant', icon: 'key', summary: 'How access is challenged or blocked.',
      elements: [
        { id: 'mfa-coverage', label: 'MFA coverage', icon: 'key', findingIds: ['single-factor-success'], sources: ['interactive'], positive: 'mfa', why: 'MFA coverage answers whether a password alone was enough on the measured path.' },
        { id: 'auth-strength', label: 'Authentication strength', icon: 'certificate', findingIds: ['weak-mfa'], sources: ['interactive'], positive: 'authStrength', why: 'Authentication strength distinguishes any MFA from passwordless or phishing-resistant methods.' },
        { id: 'legacy-controls', label: 'Legacy authentication', icon: 'clock', findingIds: ['legacy-auth'], sources: ['interactive', 'nonInteractive'], why: 'Legacy clients cannot satisfy modern authentication controls and should be blocked after migration.' },
        { id: 'authentication-flows', label: 'Authentication flows', icon: 'branch', findingIds: [], sources: ['interactive', 'nonInteractive'], field: 'appliedPolicies', defaultStatus: 'review', why: 'Device code, authentication transfer and similar flows require controls designed for how the authentication is completed.' }
      ]
    },
    {
      id: 'device', label: 'Device & Session', icon: 'device', summary: 'Device trust and session hardening.',
      elements: [
        { id: 'device-identity', label: 'Device identity', icon: 'device', findingIds: [], sources: ['interactive'], field: 'deviceIdentity', defaultStatus: 'review', why: 'Registration and join state determine whether Entra has a device object whose attributes can be evaluated.' },
        { id: 'device-compliance', label: 'Compliance & management', icon: 'shield-check', findingIds: ['noncompliant-device', 'outdated-os'], sources: ['interactive'], field: 'devicePosture', positive: 'deviceCompliance', why: 'Management supplies posture and compliance evaluates it; join state alone is not proof of a healthy device.' },
        { id: 'byod-protection', label: 'Unmanaged / BYOD protection', icon: 'applications', findingIds: [], sources: ['interactive'], field: 'devicePosture', positive: 'byod', defaultStatus: 'review', why: 'Supported app-protection and restricted-browser paths can contain corporate data when full device management is inappropriate.' },
        { id: 'session-protection', label: 'Session protection', icon: 'session', findingIds: [], sources: ['interactive', 'nonInteractive'], field: 'appliedPolicies', positive: 'session', defaultStatus: 'review', why: 'Session controls limit persistence, data movement or token replay after access is granted, where the application and client support them.' }
      ]
    },
    {
      id: 'context', label: 'Context & Risk', icon: 'risk', summary: 'Risk, location and behavioural context.',
      elements: [
        { id: 'risk-protection', label: 'Risk protection', icon: 'risk', findingIds: ['risky-signin-success', 'password-spray', 'impossible-travel'], sources: ['interactive', 'nonInteractive'], field: 'riskLevels', why: 'Identity Protection signals should trigger an appropriate challenge or block when risk is elevated.' },
        { id: 'location-context', label: 'Location context', icon: 'location', findingIds: ['geo-spread', 'sp-location-spread'], sources: ['interactive', 'nonInteractive', 'application'], findingStatus: 'review', why: 'Named locations and workload geography help distinguish expected access from routes that need review. Geography alone does not prove malicious access or a missing policy.' }
      ]
    },
    {
      id: 'enforcement', label: 'Enforcement & Validation', icon: 'shield-check', summary: 'What actually applied at runtime.',
      elements: [
        { id: 'applied-path', label: 'Applied policy path', icon: 'shield-check', findingIds: ['ca-not-applied', 'sp-ca-review'], sources: ['interactive', 'nonInteractive', 'application'], positive: 'enforcing', why: 'Runtime results show whether an enabled policy actually reached and acted on the sign-in.' },
        { id: 'report-only-state', label: 'Report-only state', icon: 'document-search', findingIds: ['report-only', 'sp-report-only'], sources: ['interactive', 'nonInteractive', 'application'], field: 'appliedPolicies', why: 'Report-only is evidence of intent and impact testing, not enforcement.' },
        { id: 'runtime-coverage', label: 'Runtime coverage', icon: 'pulse', findingIds: [], sources: ['interactive', 'nonInteractive', 'application'], why: 'Interactive, non-interactive and service-principal exports provide distinct evidence. Missing sources limit only the assessment that depends on them.' }
      ]
    }
  ];
  const LOG_JOURNEY_ADJACENT = [
    { id: 'outbound-b2b', label: 'Outbound B2B', icon: 'external', findingIds: ['outbound-b2b'], sources: ['interactive', 'nonInteractive'], why: 'The destination tenant controls access. Your lever is Cross-Tenant Access outbound configuration.' },
    { id: 'sp-credentials', label: 'Service-principal credential hygiene', icon: 'certificate', findingIds: ['sp-credential-hygiene'], sources: ['application'], why: 'Secrets, certificates and federation are application-identity controls rather than Conditional Access coverage.' }
  ];
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
    // Device registration and Intune enrolment are their own user action / app targets. Without
    // these entries CA003 and CA203 were unreachable: no control listed them, so no combination
    // of requirements could ever produce them.
    device_registration_mfa: {
      label: 'MFA to register or join a device',
      category: 'Device',
      reduction: 14,
      color: '#00a96e',
      policyIds: ['CA003']
    },
    intune_enrollment_mfa: {
      label: 'MFA for Intune enrolment',
      category: 'Device',
      reduction: 12,
      color: '#00a96e',
      policyIds: ['CA203']
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
    authenticationPosture: 'adminsPhishingResistant',
    retirePhishableMethods: false,
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

  const AUTHENTICATION_POSTURES = {
    standard: {
      label: 'Standard MFA',
      shortLabel: 'Standard MFA',
      desc: 'Selected human-user policies use the ordinary Require multifactor authentication grant control.'
    },
    adminsPhishingResistant: {
      label: 'Phishing-resistant MFA for privileged admins',
      shortLabel: 'Admin phishing-resistant MFA',
      desc: 'Selected privileged-admin policies require the built-in phishing-resistant authentication strength. Other human-user policies keep their own MFA setting.'
    },
    allHumansPhishingResistant: {
      label: 'Phishing-resistant MFA for every supported human user',
      shortLabel: 'All supported human users',
      desc: 'Selected admin, workforce, and compatible external-user policies require the built-in phishing-resistant authentication strength. Non-human identities are never upgraded.'
    }
  };

  const AUTHENTICATION_READINESS_STEPS = [
    { id: 'registrationCoverage', label: 'Registration coverage reviewed', detail: 'Confirm every in-scope user has a usable passkey/FIDO2 credential, Windows Hello for Business or platform credential, or certificate-based MFA.' },
    { id: 'bootstrapReady', label: 'Bootstrap and recovery prepared', detail: 'Prepare Temporary Access Pass or another approved onboarding path before enforcing the new strength.' },
    { id: 'emergencyAccess', label: 'Emergency access validated', detail: 'Test emergency accounts and keep them outside broad human-user Conditional Access targeting.' },
    { id: 'pilotValidated', label: 'Pilot and What If validation complete', detail: 'Pilot with a non-admin test identity, run What If, and review report-only sign-in results before enabling.' },
    { id: 'externalCompatibility', label: 'External identity compatibility confirmed', detail: 'Confirm external users authenticate with Microsoft Entra methods that can satisfy the strength and review cross-tenant MFA trust.' }
  ];

  const AUTHENTICATION_METHOD_HARDENING_STEPS = [
    ['01', 'Inventory registrations and usage', 'Use Authentication methods activity and registration details to identify who still depends on phishable methods.'],
    ['02', 'Deploy phishing-resistant credentials', 'Enable and roll out passkeys/FIDO2, Windows Hello for Business or platform credentials, or certificate-based authentication.'],
    ['03', 'Prepare bootstrap and recovery', 'Configure Temporary Access Pass or an approved equivalent so users can register strong credentials safely.'],
    ['04', 'Validate emergency access', 'Test emergency accounts with independent, phishing-resistant credentials before changing authentication methods.'],
    ['05', 'Pilot with a scoped group', 'Apply the authentication-method changes to a controlled group and verify registration, sign-in, recovery, and support paths.'],
    ['06', 'Retire phishable methods', 'After coverage is proven, disable Authenticator push/OTP, SMS, voice, software or hardware OATH, and other non-phishing-resistant methods for the selected scope.']
  ];

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
      controls: ['admin_mfa', 'admin_session'],
      controlsByLevel: {
        starter: ['admin_mfa', 'admin_session'],
        strong: ['admin_mfa', 'admin_session', 'persistent_browser'],
        maximum: ['admin_mfa', 'admin_session', 'session_controls', 'persistent_browser', 'legacy_auth', 'auth_flows', 'sign_in_risk', 'user_risk']
      },
      threats: ['T1078', 'T1557', 'T1621', 'T1484']
    },
    internals: {
      label: 'Internal workforce',
      // Device registration MFA belongs to every tenant, not just Intune shops: without it
      // anyone who phishes a password can register their own device and satisfy later
      // device-based policies.
      controls: ['mfa', 'session_controls', 'device_registration_mfa'],
      controlsByLevel: {
        starter: ['mfa', 'device_registration_mfa'],
        strong: ['mfa', 'session_controls', 'persistent_browser', 'device_registration_mfa'],
        maximum: ['mfa', 'session_controls', 'persistent_browser', 'legacy_auth', 'sign_in_risk', 'user_risk', 'device_registration_mfa']
      },
      threats: ['T1078', 'T1110', 'T1539', 'T1528']
    },
    managedDevices: {
      label: 'Managed device posture',
      controls: ['device_compliance', 'app_protection', 'unknown_platforms', 'intune_enrollment_mfa'],
      controlsByLevel: {
        starter: ['device_compliance'],
        strong: ['device_compliance', 'app_protection', 'intune_enrollment_mfa'],
        maximum: ['device_compliance', 'app_protection', 'unknown_platforms', 'intune_enrollment_mfa']
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
    authInherited: false,
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

  // Facts a sign-in log physically cannot show. The logs record what happened, not what
  // exists: a tenant full of guests who did not sign in during the exported window looks
  // identical to a tenant with no guests. Rather than treat that silence as "no need",
  // ask — and when the answer is unknown, include the policy and say why.
  const LOG_DECLARATIONS = [
    {
      key: 'guests',
      question: 'Do you have guest or external users in your tenant?',
      why: 'Guest sign-ins only appear here if a guest signed in during the exported window. An invited guest who was quiet looks the same as no guests at all.',
      requirements: ['guests'],
      unknownNote: 'Guest policies are included because these logs cannot tell us whether you have guests.'
    },
    {
      key: 'intune',
      question: 'Do you use Intune to manage devices?',
      why: 'Device compliance and enrolment policies lock out every user if Intune is not enrolling and marking devices compliant first.',
      requirements: ['managedDevices'],
      controls: ['device_compliance', 'intune_enrollment_mfa', 'app_protection', 'unknown_platforms', 'agent_compliant_device'],
      unknownNote: 'Device management policies are included because these logs cannot confirm whether Intune is in use.'
    },
    {
      key: 'entraP2',
      question: 'Are you licensed for Microsoft Entra ID P2?',
      why: 'Sign-in risk and user risk policies save without P2 but never trigger, so they look deployed while protecting nothing.',
      controls: ['sign_in_risk', 'user_risk'],
      unknownNote: 'Risk policies are included because these logs cannot confirm your licensing. Without P2 they will never fire.'
    },
    {
      key: 'locations',
      question: 'Do you restrict access by country or location?',
      why: 'Location policies need named locations defined first; enabled before that, they block everyone.',
      requirements: ['trustedLocations'],
      unknownNote: 'Location policies are included because these logs cannot tell us your intended geography.'
    },
    {
      key: 'serviceAccounts',
      question: 'Do you have service accounts that are user objects?',
      why: 'Distinct from workload identities. A user-object service account can be covered by ordinary Conditional Access; a service principal cannot.',
      requirements: ['serviceAccounts'],
      unknownNote: 'The service account policy is included because these logs cannot distinguish a service account from an ordinary user.'
    },
    {
      key: 'agents',
      question: 'Do you use agent identities (preview)?',
      why: 'Agent policies use preview/beta targeting and should only be built in tenants where those capabilities exist.',
      requirements: ['agents'],
      unknownNote: 'Agent policies are included because these logs cannot confirm whether agent identities are in use.'
    }
  ];

  const LOG_DECLARATION_ANSWERS = ['yes', 'unknown', 'no'];

  function defaultDeclarations() {
    const out = {};
    LOG_DECLARATIONS.forEach(d => { out[d.key] = 'unknown'; });
    return out;
  }

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
    expandedStrategyPolicy: null,
    guideOnly: null,
    consolidatedPolicies: [],
    activeTab: 'start',
    workflowStage: { strategy: 'requirements', scenario: 'template' },
    detailView: 'overview',
    reviewedPolicies: new Set(),
    manualGuideStep: '01',
    manualGuidePolicy: null,
    manualGuideCompleted: new Set(),
    authenticationReadiness: {
      registrationCoverage: false,
      bootstrapReady: false,
      emergencyAccess: false,
      pilotValidated: false,
      externalCompatibility: false
    },
    expertMode: savedExpertMode(),
    textSize: savedTextSize(),
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
    auditTarget: 'baseline',
    logAnalysis: emptyLogAnalysis()
  };

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clone = obj => JSON.parse(JSON.stringify(obj));
  const policyKey = item => item.sourceFile;
  let visualFlyoutOpener = null;
  let logJourneySelectionOpener = null;
  let logJourneyResizeObserver = null;
  let logJourneyDrawFrame = 0;
  let logJourneyRevealFrame = 0;
  let accessibleRegionsFrame = 0;

  function init() {
    applyTextSize(state.textSize);
    applyTheme(savedTheme());
    applyExpertMode(state.expertMode);
    allPolicies().forEach(item => {
      state.decisions[policyKey(item)] = 'exclude';
    });
    wireEvents();
    syncRecommendations();
    renderAll();
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
    $('textSizeToggle').addEventListener('click', () => {
      applyTextSize(state.textSize === 'large' ? 'standard' : 'large', true);
    });
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
    $('strategyAuthenticationPosture').addEventListener('change', e => {
      state.strategy.authenticationPosture = AUTHENTICATION_POSTURES[e.target.value] ? e.target.value : 'standard';
      if (state.strategy.authenticationPosture === 'standard') {
        state.strategy.retirePhishableMethods = false;
        resetAuthenticationReadiness();
      }
      state.appliedStrategy = null;
      state.guideOnly = null;
      renderStrategyBuilder();
    });
    $('strategyRetirePhishableMethods').addEventListener('change', e => {
      state.strategy.retirePhishableMethods = e.target.checked && state.strategy.authenticationPosture !== 'standard';
      state.appliedStrategy = null;
      state.guideOnly = null;
      renderStrategyBuilder();
    });
    $('authenticationHardeningPlan').addEventListener('change', e => {
      const input = e.target.closest('input[data-auth-readiness]');
      if (!input) return;
      state.authenticationReadiness[input.dataset.authReadiness] = input.checked;
      renderStrategyBuilder();
      renderMetrics();
      renderWarnings();
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
        if (id === 'scenarioAuthRequirement') state.scenario.authInherited = false;
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
    const toggleStrategyDetail = key => {
      state.expandedStrategyPolicy = state.expandedStrategyPolicy === key ? null : key;
      renderStrategyBuilder();
      if (state.expandedStrategyPolicy) {
        document.querySelector(`[data-strategy-detail="${CSS.escape(key)}"]`)?.scrollIntoView({ block: 'nearest' });
      }
    };
    $('strategySummary').addEventListener('click', e => {
      const btn = e.target.closest('button[data-strategy-open]');
      if (btn) {
        applyBestPracticeStrategy(btn.dataset.strategyOpen);
        return;
      }
      const card = e.target.closest('[data-strategy-detail]');
      if (!card) return;
      if (e.target.closest('a, button, .strategy-policy-detail')) return;
      toggleStrategyDetail(card.dataset.strategyDetail);
    });
    $('strategySummary').addEventListener('keydown', e => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const card = e.target.closest('[data-strategy-detail]');
      if (!card || e.target !== card) return;
      e.preventDefault();
      toggleStrategyDetail(card.dataset.strategyDetail);
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
      btn.addEventListener('click', () => navigateReviewStage(btn.dataset.reviewStage));
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
    $('manualGuide').addEventListener('click', e => {
      const stepButton = e.target.closest('button[data-manual-step]');
      if (stepButton) {
        state.manualGuideStep = stepButton.dataset.manualStep;
        renderSelected();
        return;
      }
      const completeButton = e.target.closest('button[data-manual-complete]');
      if (completeButton) {
        toggleManualGuideStep(completeButton.dataset.manualComplete);
        return;
      }
      const copyButton = e.target.closest('button[data-manual-copy]');
      if (copyButton) copyManualGuideSection(copyButton.dataset.manualCopy);
    });
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
      if (configuredAuthenticationExportBlocked(policy)) {
        toast('Complete phishing-resistant authentication readiness before downloading an enabled policy');
        renderSelected();
        return;
      }
      downloadJson(exportPolicy(policy, 'configured'), `${safeFilename(tenantPolicyName(policy.displayName))}.json`);
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

    const logDropzone = $('logDropzone');
    logDropzone.addEventListener('click', () => $('logFileInput').click());
    $('logFileInput').addEventListener('change', e => handleLogFiles(e.target.files));
    ['dragenter', 'dragover'].forEach(ev => {
      logDropzone.addEventListener(ev, e => {
        e.preventDefault();
        logDropzone.classList.add('drag');
      });
    });
    ['dragleave', 'drop'].forEach(ev => {
      logDropzone.addEventListener(ev, e => {
        e.preventDefault();
        logDropzone.classList.remove('drag');
      });
    });
    logDropzone.addEventListener('drop', e => handleLogFiles(e.dataTransfer.files));
    $('logExportDocxBtn').addEventListener('click', () => exportLogReport('docx'));
    $('logExportXlsxBtn').addEventListener('click', () => exportLogReport('xlsx'));
    $('logClearBtn').addEventListener('click', clearLogAnalysis);
    $('logFilterControl').addEventListener('click', e => {
      const btn = e.target.closest('button[data-log-filter]');
      if (!btn || !LOG_FILTERS.has(btn.dataset.logFilter)) return;
      state.logAnalysis.filter = btn.dataset.logFilter;
      renderLogAnalysis();
    });
    $('logSourceFilterControl').addEventListener('click', e => {
      const btn = e.target.closest('button[data-log-source-filter]');
      if (!btn || btn.disabled || !LOG_SOURCE_FILTERS.has(btn.dataset.logSourceFilter)) return;
      state.logAnalysis.sourceFilter = btn.dataset.logSourceFilter;
      renderLogAnalysis();
    });
    $('logViewControl').addEventListener('click', e => {
      if (!e.target.closest('[data-log-show-visual]')) return;
      state.logAnalysis.view = 'visual';
      state.logAnalysis.journeySelected = null;
      renderLogAnalysis();
    });
    $('logVisualContent').addEventListener('click', onLogVisualInteraction);
    $('logVisualContent').addEventListener('toggle', event => {
      const disclosure = event.target.closest?.('details.log-journey-declarations');
      if (!disclosure || event.target !== disclosure) return;
      state.logAnalysis.tenantAssumptionsExpanded = disclosure.open;
    }, true);
    document.addEventListener('keydown', onLogJourneyKeydown);
    $('logStrategyCta').addEventListener('click', e => {
      if (e.target.closest('#logBuildStrategyBtn')) buildStrategyFromFindings();
      if (e.target.closest('#logBuildGuideBtn')) exportBuildGuideDocx();
      const answer = e.target.closest('[data-declaration]');
      if (answer) setDeclaration(answer.dataset.declaration, answer.dataset.answer);
    });
    $('logFindings').addEventListener('click', onEvidenceRowToggle);
    $('logFindings').addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.closest('tr.log-evidence-row')) {
        e.preventDefault();
        onEvidenceRowToggle(e);
      }
    });
  }

  function savedTheme() {
    try {
      const theme = localStorage.getItem(THEME_STORAGE_KEY);
      return theme === 'dark' ? 'dark' : 'light';
    } catch (_) {
      return 'light';
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

  function savedTextSize() {
    try {
      return localStorage.getItem(TEXT_SIZE_STORAGE_KEY) === 'large' ? 'large' : 'standard';
    } catch (_) {
      return 'standard';
    }
  }

  function applyTextSize(size, persist = false) {
    state.textSize = size === 'large' ? 'large' : 'standard';
    document.documentElement.dataset.textSize = state.textSize;
    const toggle = $('textSizeToggle');
    if (toggle) {
      const isLarge = state.textSize === 'large';
      toggle.textContent = `Text size: ${state.textSize}`;
      toggle.setAttribute('aria-pressed', String(isLarge));
      toggle.setAttribute('aria-label', isLarge ? 'Use standard text size' : 'Use large text size');
    }
    if (persist) {
      try {
        localStorage.setItem(TEXT_SIZE_STORAGE_KEY, state.textSize);
      } catch (_) {
        // Text-size persistence is optional; the current session still updates.
      }
    }
    scheduleScrollableRegionEnhancement();
  }

  function scheduleScrollableRegionEnhancement() {
    cancelAnimationFrame(accessibleRegionsFrame);
    accessibleRegionsFrame = requestAnimationFrame(() => {
      const regions = [
        ['pre, .json-output, .json-preview', 'Scrollable technical output'],
        ['.table-wrap, .comparison-table-wrap, .log-evidence-scroll', 'Scrollable data table']
      ];
      regions.forEach(([selector, label]) => {
        document.querySelectorAll(selector).forEach(region => {
          if (region.scrollWidth <= region.clientWidth + 1 && region.scrollHeight <= region.clientHeight + 1) return;
          if (!region.hasAttribute('tabindex')) region.tabIndex = 0;
          if (!region.hasAttribute('role')) region.setAttribute('role', 'region');
          if (!region.hasAttribute('aria-label')) region.setAttribute('aria-label', label);
        });
      });
    });
  }

  function applyExpertMode(enabled, persist = false) {
    state.expertMode = Boolean(enabled);
    document.documentElement.dataset.expert = state.expertMode ? 'on' : 'off';
    const toggle = $('expertModeToggle');
    if (toggle) {
      toggle.textContent = `Advanced detail: ${state.expertMode ? 'on' : 'off'}`;
      toggle.setAttribute('aria-pressed', String(state.expertMode));
      toggle.setAttribute('aria-label', state.expertMode ? 'Hide advanced detail' : 'Show advanced detail');
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

  function navigateReviewStage(stage) {
    const scenarioSource = ['scenario', 'scenario-guide'].includes(state.appliedStrategy?.type);
    if (stage === 'requirements') {
      if (scenarioSource) setScenarioStage('settings');
      else setStrategyStage('requirements');
      return;
    }
    if (stage === 'architecture') {
      if (scenarioSource) setScenarioStage('plan');
      else setStrategyStage(strategyPlan().empty ? 'requirements' : 'architecture');
      return;
    }
    setPolicyDetailView(stage === 'export' ? 'export' : 'overview');
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

  // Accepts an explicit requirements object so a caller can preview exactly what a given
  // strategy would build without mutating state — the log analysis uses this so its
  // recommended policy list is the same set "Build this strategy" produces.
  function strategyPlan(requirementsInput) {
    const requirements = requirementsInput || state.strategy;
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

    const authenticationPosture = normalizedAuthenticationPosture(requirements.authenticationPosture);
    if (requirements.admins && authenticationPosture !== 'standard') {
      addControl('phish_mfa', AUTHENTICATION_POSTURES[authenticationPosture].label);
    }
    if (authenticationPosture === 'allHumansPhishingResistant' && (requirements.internals || requirements.guests)) {
      addControl('phish_mfa', AUTHENTICATION_POSTURES[authenticationPosture].label);
    }

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

  function normalizedAuthenticationPosture(value) {
    return AUTHENTICATION_POSTURES[value] ? value : 'standard';
  }

  function phishingResistantForScope(requirements, scope) {
    const posture = normalizedAuthenticationPosture(requirements.authenticationPosture);
    if (posture === 'allHumansPhishingResistant') return ['admins', 'internals', 'guests'].includes(scope);
    return posture === 'adminsPhishingResistant' && scope === 'admins';
  }

  function phishingResistantGrant(existingGrant = {}) {
    const builtInControls = (existingGrant.builtInControls || []).filter(control => String(control).toLowerCase() !== 'mfa');
    const grant = {
      operator: builtInControls.length ? 'AND' : (existingGrant.operator || 'OR'),
      authenticationStrength: clone(policiesById('CA105')[0].policy.grantControls.authenticationStrength)
    };
    if (builtInControls.length) grant.builtInControls = builtInControls;
    return grant;
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
      add(consolidatedAdminCorePolicy(requirements, controls, controlReasons));
    }

    // Device registration is a user-action target (urn:user:registerdevice), which cannot be
    // merged into an app-scoped policy — it has to stay its own policy.
    if (has('device_registration_mfa')) add(consolidatedClonePolicy('CA003C', 'Tenant-RequireMFAToRegisterOrJoinDevice', 'CA003', ['device_registration_mfa'], 'Device registration targets a user action rather than an app, so it cannot merge into the core policies.'));
    if (has('legacy_auth')) add(consolidatedClonePolicy('CA001C', 'Tenant-BlockLegacyAuthentication', 'CA002', ['legacy_auth'], 'Legacy authentication must stay as its own block policy.'));
    if (has('auth_flows')) add(consolidatedClonePolicy('CA002C', 'Tenant-BlockRiskyAuthenticationFlows', 'CA004', ['auth_flows'], 'Risky authentication flows stay separate so block logic remains explicit.'));
    if (has('sign_in_risk')) add(scopeConsolidatedRiskPolicy(consolidatedClonePolicy('CA011C', 'Tenant-BlockHighRiskSignIns', 'CA210', ['sign_in_risk'], 'Sign-in risk remains separate from user risk per Microsoft guidance.'), requirements));
    if (has('user_risk')) add(scopeConsolidatedRiskPolicy(consolidatedClonePolicy('CA012C', 'Tenant-BlockHighRiskUsers', 'CA201', ['user_risk'], 'User risk remains separate from sign-in risk per Microsoft guidance.'), requirements));

    if (requirements.internals) {
      add(consolidatedWorkforceCorePolicy(requirements, controls, controlReasons));
    }
    if (requirements.managedDevices && (has('device_compliance') || has('unknown_platforms'))) {
      // CA201C is a clone of CA205, which requires a compliant device. It does NOT block
      // unknown platforms — that is CA204, a separate all-platforms-except-known block.
      // Claiming the control here hid CA204's absence from the gap list.
      add(consolidatedClonePolicy('CA201C', 'Workforce-ManagedDeviceCompliance', 'CA205', ['device_compliance'], 'Device compliance remains a clear device posture policy.'));
    }
    if (requirements.managedDevices && has('app_protection')) {
      add(consolidatedClonePolicy('CA202C', 'Workforce-AppProtection-Office365', 'CA005', ['app_protection'], 'App protection controls stay separate because their app and client targeting differs from core MFA/session controls.'));
    }
    if (requirements.managedDevices && has('intune_enrollment_mfa')) {
      add(consolidatedClonePolicy('CA203C', 'Workforce-IntuneEnrollment-MFA', 'CA203', ['intune_enrollment_mfa'], 'Enrolment targets the Intune Enrollment app specifically, so it stays separate from the all-apps policies.'));
    }

    if (requirements.guests || has('guest_access')) add(consolidatedGuestCorePolicy(requirements, controlReasons));
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

    // Completeness pass. Anything the selected controls imply that the merges above did not
    // absorb is carried through as its own policy. Previously these were reported as "10 more
    // controls you still need, go build them yourself" — a strategy that names a gap and then
    // declines to close it is not a strategy.
    policiesForControlSet(controls).forEach(baseline => {
      if (policies.some(item => (item.represents || []).includes(baseline.id))) return;
      // The upstream CAE strict-location templates target `None` rather than an explicit
      // resource. Keep them as expert/optional guidance until the tenant chooses a valid
      // target instead of silently adding an unusable policy to a consolidated design.
      if (['CA104', 'CA209'].includes(baseline.id)) return;
      const delivered = Object.keys(CONTROLS)
        .filter(key => controls.includes(key) && (CONTROLS[key].policyIds || []).includes(baseline.id));
      if (!delivered.length) return;
      // A policy must also belong to a selected requirement. CA404 targets guests but happens
      // to deliver `selected_app_block`; without this it reappeared for a tenant that had
      // explicitly said it has no guests.
      const owningRequirements = policyCategory(baseline.id).requirements || [];
      if (owningRequirements.length && !owningRequirements.some(key => requirements[key])) return;
      // Keep the baseline's own number where it is free, so the lineage stays obvious.
      const taken = new Set(policies.map(item => item.displayName.slice(0, 5)));
      let id = baseline.id;
      if (taken.has(id)) {
        const band = baseline.id.slice(2, 3);
        for (let n = 1; n < 100; n += 1) {
          const candidate = `CA${band}${String(n).padStart(2, '0')}`;
          if (!taken.has(candidate)) { id = candidate; break; }
        }
      }
      add(consolidatedClonePolicy(id, baseline.displayName.replace(/^CA\d{3}-/, ''), baseline.id, delivered,
        'Carried through unmerged: its targeting differs from the consolidated policies, so it stays a policy in its own right.'));
    });

    return sortPolicies(policies);
  }

  function consolidatedAdminCorePolicy(requirements, controls) {
    const representedIds = ['CA100', 'CA101'];
    if (controls.includes('admin_session') || controls.includes('session_controls')) representedIds.push('CA102');
    if (controls.includes('persistent_browser')) representedIds.push('CA103');
    if (controls.includes('phish_mfa')) representedIds.push('CA105');
    const represented = policiesByIds(representedIds);
    const roles = uniqueValues(represented.flatMap(policy => policy.policy.conditions?.users?.includeRoles || []));
    const usePhishingResistant = phishingResistantForScope(requirements, 'admins');
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
    const displayName = `CA100C-PrivilegedAdmins-Core-${strengthLabel}-SessionControls`;
    const policy = {
      id: 'CA100C',
      persona: 'Admins',
      displayName,
      sourceFile: `Strategy/ConditionalAccess/${displayName}.json`,
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
        displayName,
        state: 'enabledForReportingButNotEnforced',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeRoles: roles,
            excludeGroups: [SHARED_GROUPS.breakGlass.id]
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
    const usePhishingResistant = phishingResistantForScope(requirements, 'internals');
    const strengthLabel = usePhishingResistant ? 'PhishingResistantMFA' : 'MFA';
    const displayName = `CA200C-Workforce-Core-${strengthLabel}-SessionControls`;
    const grantControls = usePhishingResistant
      ? phishingResistantGrant({ operator: 'OR', builtInControls: ['mfa'] })
      : { operator: 'OR', builtInControls: ['mfa'] };
    return {
      id: 'CA200C',
      persona: 'Internals',
      displayName,
      sourceFile: `Strategy/ConditionalAccess/${displayName}.json`,
      state: 'enabled',
      risk: 'medium',
      summary: usePhishingResistant
        ? 'Consolidated workforce policy requiring phishing-resistant MFA with session lifetime controls.'
        : 'Consolidated workforce policy for MFA and session lifetime controls.',
      prerequisites: GLOBAL_PREREQUISITES,
      requiredObjects: ['CA-BreakGlassAccounts-Exclude'],
      rolloutDefault: 'include',
      kind: 'consolidated',
      generated: true,
      consolidated: true,
      controls: ['mfa', 'phish_mfa', 'session_controls', 'persistent_browser'].filter(controlId => controls.includes(controlId)),
      represents: representedIds,
      mergeReason: 'Safe to merge because workforce MFA and session controls share broad user and all-app scope.',
      separateReason: 'Device compliance, app protection, and block controls stay separate because their conditions and grant semantics differ.',
      policy: {
        displayName,
        state: 'enabled',
        conditions: {
          clientAppTypes: ['all'],
          users: {
            includeUsers: ['All'],
            excludeGroups: [SHARED_GROUPS.breakGlass.id, SHARED_GROUPS.serviceAccounts.id]
          },
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls,
        sessionControls: {
          signInFrequency,
          persistentBrowser
        }
      }
    };
  }

  function consolidatedGuestCorePolicy(requirements) {
    const represented = policiesByIds(['CA400', 'CA402', 'CA403']);
    const usePhishingResistant = phishingResistantForScope(requirements, 'guests');
    const strengthLabel = usePhishingResistant ? 'PhishingResistantMFA' : 'MFA';
    const displayName = `CA400C-Guests-Core-${strengthLabel}-SessionControls`;
    const prerequisites = [...GLOBAL_PREREQUISITES, 'Guest and partner access model reviewed'];
    if (usePhishingResistant) prerequisites.push('External Entra authentication methods and cross-tenant MFA trust validated');
    const policy = {
      id: 'CA400C',
      persona: 'Guests',
      displayName,
      sourceFile: `Strategy/ConditionalAccess/${displayName}.json`,
      state: 'enabled',
      risk: 'medium',
      summary: usePhishingResistant
        ? 'Consolidated external-user policy requiring phishing-resistant MFA and shorter sessions where the external identity can satisfy the strength.'
        : 'Consolidated guest and partner access policy requiring MFA and shorter sessions.',
      prerequisites,
      requiredObjects: ['CA-BreakGlassAccounts-Exclude'],
      rolloutDefault: 'include',
      kind: 'consolidated',
      generated: true,
      consolidated: true,
      controls: ['guest_access', usePhishingResistant ? 'phish_mfa' : 'mfa', 'session_controls', 'persistent_browser'],
      represents: represented.map(policy => policy.id),
      mergeReason: 'Safe to merge because guest MFA and session controls share external identity scope and all-app targeting.',
      separateReason: 'Guest block policies remain separate because they use block controls and selected-app restrictions.',
      policy: {
        displayName,
        state: 'enabled',
        conditions: {
          clientAppTypes: ['all'],
          users: clone(policiesById('CA400')[0].policy.conditions.users),
          applications: {
            includeApplications: ['All']
          }
        },
        grantControls: usePhishingResistant
          ? phishingResistantGrant(policiesById('CA400')[0].policy.grantControls)
          : clone(policiesById('CA400')[0].policy.grantControls),
        sessionControls: {
          signInFrequency: clone(policiesById('CA402')[0].policy.sessionControls.signInFrequency),
          persistentBrowser: clone(policiesById('CA403')[0].policy.sessionControls.persistentBrowser)
        }
      }
    };
    policy.policy.conditions.users.excludeGroups = [SHARED_GROUPS.breakGlass.id];
    return policy;
  }

  function consolidatedServiceAccountPolicy() {
    const base = clone(policiesById('CA301')[0]);
    base.id = 'CA300C';
    base.displayName = 'CA300C-ServiceAccounts-TrustedLocation-BlockUntrustedAccess';
    base.sourceFile = 'Strategy/ConditionalAccess/CA300C-ServiceAccounts-TrustedLocation-BlockUntrustedAccess.json';
    base.summary = 'Restrict human-operated service or automation accounts to approved named locations without applying human MFA controls to workload identities.';
    base.kind = 'consolidated';
    base.generated = true;
    base.consolidated = true;
    base.controls = ['service_account_protection', 'trusted_location'];
    base.represents = ['CA300', 'CA301'];
    base.mergeReason = 'Replaces human MFA with a location boundary for the user accounts in the service-account group; service principals require workload-identity controls and separate ownership.';
    base.separateReason = 'Block controls and workload-identity targeting remain separate from human authentication-strength policies.';
    base.policy = clone(base.policy);
    base.policy.displayName = base.displayName;
    return normalizeConsolidatedGroupAssignments(base);
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
    return normalizeConsolidatedGroupAssignments(item);
  }

  function normalizeConsolidatedGroupAssignments(item) {
    const users = item.policy?.conditions?.users;
    if (!users) return item;
    if (Array.isArray(users.includeGroups)) {
      users.includeGroups = users.includeGroups.filter(groupId => SHARED_GROUP_IDS.has(groupId));
      if (!users.includeGroups.length) delete users.includeGroups;
    }
    if (item.persona === 'Service Accounts') {
      users.includeGroups = [SHARED_GROUPS.serviceAccounts.id];
      delete users.excludeGroups;
    } else if (Array.isArray(users.excludeGroups) || users.includeUsers?.includes('All') || users.includeRoles?.length || users.includeGuestsOrExternalUsers) {
      users.excludeGroups = [SHARED_GROUPS.breakGlass.id];
    }
    item.requiredObjects = minimalRequiredObjects(item);
    return item;
  }

  function scopeConsolidatedRiskPolicy(item, requirements) {
    if (!item) return item;
    const users = item.policy.conditions.users;
    if (requirements.admins && !requirements.internals) {
      users.includeRoles = uniqueValues(policiesByIds(['CA100', 'CA101']).flatMap(policy => policy.policy.conditions?.users?.includeRoles || []));
      users.excludeGroups = [SHARED_GROUPS.breakGlass.id];
      delete users.includeGroups;
      delete users.includeUsers;
      item.persona = 'Admins';
      item.displayName = item.displayName.replace('-Tenant-', '-PrivilegedAdmins-');
      item.policy.displayName = item.displayName;
      item.sourceFile = `Strategy/ConditionalAccess/${item.displayName}.json`;
      item.requiredObjects = [SHARED_GROUPS.breakGlass.name];
      return item;
    }
    if (requirements.internals) {
      users.includeUsers = ['All'];
      users.excludeGroups = [SHARED_GROUPS.breakGlass.id, SHARED_GROUPS.serviceAccounts.id];
      delete users.includeGroups;
      item.persona = 'Internals';
      item.requiredObjects = [SHARED_GROUPS.breakGlass.name, SHARED_GROUPS.serviceAccounts.name];
    }
    return item;
  }

  function minimalRequiredObjects(item) {
    const users = item.policy?.conditions?.users || {};
    const required = new Set((item.requiredObjects || []).filter(name => !/^CA\d{3}.*exclude$/i.test(String(name).replace(/\s+-\s+/g, '-'))));
    const groupIds = [...(users.includeGroups || []), ...(users.excludeGroups || [])];
    Object.values(SHARED_GROUPS).forEach(group => {
      if (groupIds.includes(group.id)) required.add(group.name);
    });
    return [...required];
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

  function resetAuthenticationReadiness() {
    Object.keys(state.authenticationReadiness).forEach(key => {
      state.authenticationReadiness[key] = false;
    });
  }

  function authenticationReadinessKeys(requirements = state.strategy) {
    const keys = ['registrationCoverage', 'bootstrapReady', 'emergencyAccess', 'pilotValidated'];
    if (normalizedAuthenticationPosture(requirements.authenticationPosture) === 'allHumansPhishingResistant' && requirements.guests) {
      keys.push('externalCompatibility');
    }
    return keys;
  }

  function authenticationReadinessMissing(requirements = state.appliedStrategy?.requirements || state.strategy, policy = null) {
    let keys = authenticationReadinessKeys(requirements);
    if (policy?.persona === 'Guests' && !keys.includes('externalCompatibility')) keys = [...keys, 'externalCompatibility'];
    return keys.filter(key => !state.authenticationReadiness[key]);
  }

  function isPhishingResistantPolicy(policy) {
    const strength = (policy?.policy || policy)?.grantControls?.authenticationStrength;
    if (!strength) return false;
    return /phishing[- ]?resistant/i.test(`${strength.displayName || ''} ${strength.description || ''}`);
  }

  function configuredAuthenticationExportBlocked(policy) {
    if (!policy || !isPhishingResistantPolicy(policy)) return false;
    if ((state.decisions[policyKey(policy)] || 'exclude') !== 'include') return false;
    return authenticationReadinessMissing(state.appliedStrategy?.requirements || state.strategy, policy).length > 0;
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
    renderLogAnalysis();
    renderSegmented('policyViewControl', state.policyView, 'view');
    scheduleScrollableRegionEnhancement();
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
    $('sourceUpstream').textContent = upstream.repo || 'j0eyv/ConditionalAccessBaseline';
    $('commitText').textContent = BASELINE.commit;
    $('sourceParity').textContent = `${BASELINE.policies.length - overrides.length}/${BASELINE.policies.length} exact, ${overrides.length} approved override`;
    $('sourceOverride').textContent = overrides.length
      ? overrides.map(item => `${item.id}: ${item.path} ${item.upstream} hours -> ${item.local} hours`).join('; ')
      : 'None';
    $('sourcePolicies').textContent = `${BASELINE.policies.length} baseline templates`;
    $('sourceGenerated').textContent = `${GENERATED_POLICIES.length} V2 preview variants`;
    $('sourceGroups').textContent = `${Object.keys(SHARED_GROUPS).length} reusable group patterns`;
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
    document.querySelectorAll('#strategyProgress button[data-review-stage]').forEach(btn => {
      btn.disabled = !state.appliedStrategy;
      btn.classList.toggle('complete', Boolean(state.appliedStrategy));
    });
    $('strategyProtection').value = state.strategy.protection;
    $('strategyRollout').value = state.strategy.rollout;
    $('strategyAuthenticationPosture').value = normalizedAuthenticationPosture(state.strategy.authenticationPosture);
    $('strategyRetirePhishableMethods').checked = Boolean(state.strategy.retirePhishableMethods);
    $('strategyRetirePhishableMethods').disabled = state.strategy.authenticationPosture === 'standard';
    $('strategyAuthenticationPostureHelp').textContent = AUTHENTICATION_POSTURES[normalizedAuthenticationPosture(state.strategy.authenticationPosture)].desc;
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
    ${plan.empty ? '' : strategyGroupModel(plan)}
    ${plan.empty ? strategyEmptyState(plan) : strategyBuildOrder(plan)}
    ${state.appliedStrategy ? '<div class="strategy-applied">This strategy is currently applied to the rebuild set.</div>' : ''}`;

    $('strategySafety').innerHTML = plan.empty ? '<div class="empty-state">Guardrails appear after you select a requirement.</div>' : plan.safety.map(strategySafetyCard).join('') || '<div class="empty-state">No separation warnings for this strategy.</div>';
    $('strategyBaselineRepresented').innerHTML = plan.empty ? '<div class="empty-state">Baseline traceability appears after the consolidated design is generated.</div>' : plan.consolidatedPolicies.map(strategyRepresentationCard).join('');
    $('mitreCoverage').innerHTML = plan.mitre.map(mitreCoverageRow).join('');
    $('strategyResidualGaps').innerHTML = RESIDUAL_GAPS.map(gap => `<div class="strategy-note">${esc(gap)}</div>`).join('');
    renderAuthenticationHardening(plan);
  }

  function strategyGroupModel(plan) {
    const groupIds = new Set(plan.consolidatedPolicies.flatMap(policy => {
      const users = policy.policy?.conditions?.users || {};
      return [...(users.includeGroups || []), ...(users.excludeGroups || [])];
    }));
    const names = Object.values(SHARED_GROUPS)
      .filter(group => groupIds.has(group.id))
      .map(group => group.name);
    return `<div class="strategy-context-line group-model"><strong>${esc(names.length)} shared security group${names.length === 1 ? '' : 's'}</strong><span>${esc(names.join(', ') || 'No security group required')}. Policy-specific baseline exclusion groups are not generated.</span></div>`;
  }

  function renderAuthenticationHardening(plan) {
    const posture = normalizedAuthenticationPosture(plan.requirements.authenticationPosture);
    const panel = $('authenticationHardeningPanel');
    const visible = !plan.empty && posture !== 'standard';
    panel.hidden = !visible;
    if (!visible) {
      $('authenticationHardeningPlan').innerHTML = '';
      return;
    }
    const requiredKeys = authenticationReadinessKeys(plan.requirements);
    const missing = requiredKeys.filter(key => !state.authenticationReadiness[key]);
    const retirement = Boolean(plan.requirements.retirePhishableMethods);
    const scope = posture === 'adminsPhishingResistant' ? 'privileged administrators' : 'internal human users';
    const readiness = AUTHENTICATION_READINESS_STEPS
      .filter(step => requiredKeys.includes(step.id))
      .map(step => `<label class="authentication-readiness-item ${state.authenticationReadiness[step.id] ? 'complete' : ''}">
        <input type="checkbox" data-auth-readiness="${esc(step.id)}" ${state.authenticationReadiness[step.id] ? 'checked' : ''}>
        <span><strong>${esc(step.label)}</strong><small>${esc(step.detail)}</small></span>
      </label>`).join('');
    const hardening = retirement
      ? `<section class="authentication-method-plan">
          <div class="authentication-plan-heading"><span>Separate Entra configuration</span><strong>Retire phishable methods for ${esc(scope)}</strong><p>This changes the Authentication methods policy, not Conditional Access JSON. External users keep methods controlled by their home tenant.</p></div>
          <ol>${AUTHENTICATION_METHOD_HARDENING_STEPS.map(([number, title, detail]) => `<li><span>${esc(number)}</span><div><strong>${esc(title)}</strong><small>${esc(detail)}</small></div></li>`).join('')}</ol>
        </section>`
      : `<div class="authentication-boundary-note"><strong>Authentication strength and method availability are different controls</strong><span>Conditional Access decides which strength must satisfy this access. Authentication methods policy decides which credentials users can register and use across Entra.</span></div>`;
    $('authenticationHardeningPlan').innerHTML = `<div class="authentication-hardening-head">
        <div><p class="eyebrow">Authentication readiness</p><h3>${esc(AUTHENTICATION_POSTURES[posture].label)}</h3><p>${esc(AUTHENTICATION_POSTURES[posture].desc)}</p></div>
        <span class="readiness-status ${missing.length ? 'incomplete' : 'complete'}">${missing.length ? `${missing.length} checks remaining` : 'Ready for enabled rollout'}</span>
      </div>
      <div class="authentication-hardening-body">
        <section><h4>Before enabling</h4><div class="authentication-readiness-list">${readiness}</div></section>
        ${hardening}
      </div>
      <footer class="authentication-guidance-links">
        <span>Microsoft guidance reviewed 5 August 2026</span>
        <a href="https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths" target="_blank" rel="noopener noreferrer">Authentication strengths</a>
        <a href="https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa" target="_blank" rel="noopener noreferrer">Admin policy</a>
        <a href="https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-methods-manage" target="_blank" rel="noopener noreferrer">Authentication methods</a>
        <a href="https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strength-external-users" target="_blank" rel="noopener noreferrer">External users</a>
      </footer>`;
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
    next.authRequirement = inheritedScenarioAuthentication(next, next.authRequirement);
    next.authInherited = next.authRequirement !== custom.fields.authRequirement;
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
    const templateAuth = state.scenario.authRequirement;
    state.scenario.authRequirement = inheritedScenarioAuthentication(state.scenario, templateAuth);
    state.scenario.authInherited = state.scenario.authRequirement !== templateAuth;
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

  function inheritedScenarioAuthentication(inputs, fallback = 'standardMfa') {
    if (['serviceAccount', 'agentIdentity'].includes(inputs.accountType)) return fallback;
    const posture = normalizedAuthenticationPosture(state.strategy.authenticationPosture);
    if (posture === 'allHumansPhishingResistant') return 'phishingResistantMfa';
    if (posture === 'adminsPhishingResistant' && inputs.accountType === 'admin') return 'phishingResistantMfa';
    return fallback;
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
            excludeGroups: [SHARED_GROUPS.breakGlass.id]
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
            excludeGroups: [SHARED_GROUPS.breakGlass.id]
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
            excludeGroups: [SHARED_GROUPS.breakGlass.id]
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
    if (['unmanaged', 'browserOnly'].includes(inputs.deviceTrust)) {
      conditions.devices = {
        deviceFilter: {
          mode: 'include',
          rule: 'device.isCompliant -ne True'
        }
      };
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
    if (['unmanaged', 'browserOnly'].includes(inputs.deviceTrust)) items.push('Validate the device filter in Conditional Access What If. The recommended negative compliance test intentionally includes noncompliant and unregistered devices.');
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
    if (['unmanaged', 'browserOnly'].includes(inputs.deviceTrust)) items.push('Device filter: include devices where compliance is not true. Microsoft recommends a negative operator when unregistered devices, whose properties are null, must also be captured.');
    if (inputs.sensitivity === 'highlySensitive') items.push('Use stricter authentication, shorter sessions, and an explicit owner for exception removal.');
    if (inputs.authInherited) items.push(`Authentication inherited from Strategy Builder: ${scenarioAuthRequirementLabel(inputs.authRequirement)}. Change the authentication requirement here if this access pattern needs an explicit exception.`);
    return items;
  }

  function scenarioWarnings(template, inputs, missing) {
    const warnings = [];
    if (missing.length) warnings.push(`Apply/export is blocked until ${missing.map(item => item.field).join(', ')} is supplied.`);
    if (inputs.resource === 'sharepoint') warnings.push('Conditional Access cannot target a specific SharePoint folder. Use SharePoint permissions and site controls for the folder boundary.');
    if (inputs.resource === 'exchange' && inputs.deviceTrust === 'unmanaged') warnings.push('Unmanaged desktop app access is weaker than browser-only access unless app protection or device compliance is available.');
    if (template.preview || inputs.resource === 'agentResources') warnings.push('Agent scenarios use preview/beta-shaped Conditional Access fields and require tenant capability validation.');
    if (template.validationOnly) warnings.push('Break-glass validation policies should remain disabled or report-only and must not block emergency access.');
    if (inputs.accountType === 'externalGuest' && inputs.authRequirement === 'phishingResistantMfa') {
      warnings.push('Phishing-resistant authentication strength can block email one-time passcode, SAML/WS-Fed, Google federation, or other external identities that cannot satisfy the selected strength. Validate the external authentication path and cross-tenant trust before enforcement.');
    }
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
          <strong>${esc(tenantPolicyName(policy.displayName))}</strong>
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
        ['Device filter', scenarioDeviceFilterSummary(conditions.devices)],
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
      if (entry.name) return context === 'groups' ? entry.name : `${entry.name} (${entry.id})`;
      if (context === 'groups') return 'Security group name required';
      return entry.text || value;
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

  function scenarioDeviceFilterSummary(devices = {}) {
    const filter = devices.deviceFilter;
    if (!filter?.rule) return 'Not configured';
    if (filter.mode === 'include' && /device\.isCompliant\s+-ne\s+True/i.test(filter.rule)) {
      return 'Include devices that are not compliant, including unregistered devices';
    }
    return `${filter.mode === 'exclude' ? 'Exclude' : 'Include'} devices matching the configured filter`;
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
    const expanded = state.expandedStrategyPolicy === key;
    return `<div class="strategy-policy-card${expanded ? ' expanded' : ''}" data-strategy-detail="${esc(key)}" role="button" tabindex="0" aria-expanded="${expanded}">
      <div class="strategy-policy-top">
        <div>
          <span class="strategy-step-label">Step ${esc(index + 1)}</span>
          <strong>${esc(tenantPolicyName(policy.displayName))}</strong>
        </div>
        <span class="status-chip">${esc(policy.consolidated ? 'Consolidated' : isPreviewPolicy(policy) ? 'Preview/beta' : 'Baseline')}</span>
        <span class="strategy-card-caret" aria-hidden="true">${expanded ? '−' : '+'}</span>
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
      ${expanded ? strategyPolicyDetail(policy, plan, guideAction) : ''}
    </div>`;
  }

  function strategyPolicyDetail(policy, plan, guideAction = '') {
    let sections = [];
    try {
      const decision = strategyDecisionForPolicy(policy, plan);
      const exported = exportPolicy(policy, 'configured');
      sections = manualGuideSections(policy, exported, decision)
        .map(section => ({ ...section, rows: section.rows.filter(row => !row.empty) }))
        .filter(section => section.rows.length);
    } catch (err) {
      return '<div class="strategy-policy-detail"><p class="strategy-detail-note">Configuration detail is unavailable for this policy. Use Open build guide instead.</p></div>';
    }
    const mitre = strategyPolicyMitre(policy, plan);
    const mitreRows = mitre.length
      ? mitre.map(item => `<div class="strategy-mitre-row">
          <span class="strategy-mitre-id">${esc(item.id)}</span>
          <div>
            <strong>${esc(item.name)}</strong>
            <small>${esc(item.tactic)} - via ${esc(item.via.join(', '))}</small>
          </div>
          <span class="strategy-mitre-status ${item.status === 'Strongly mitigated' ? 'strong' : 'partial'}">${esc(item.status)}</span>
        </div>`).join('')
      : '<p class="strategy-detail-note">This policy supports coverage indirectly; no technique maps to its controls on its own.</p>';
    return `<div class="strategy-policy-detail">
      <div class="strategy-detail-block">
        <h5>Configuration reference</h5>
        <p class="strategy-detail-note">Configured settings only, as entered in the Entra portal. Copy values from here while you build.</p>
        <div class="manual-section-grid strategy-detail-sections">${sections.map(renderStrategyDetailSection).join('')}</div>
      </div>
      <div class="strategy-detail-block">
        <h5>MITRE ATT&amp;CK resolved by this policy</h5>
        <div class="strategy-mitre-list">${mitreRows}</div>
      </div>
      ${guideAction ? `<div class="strategy-detail-actions">${guideAction}</div>` : ''}
    </div>`;
  }

  function renderStrategyDetailSection(section) {
    return `<section class="manual-section strategy-detail-section">
      <div class="manual-section-head">
        <span>${esc(section.step)}</span>
        <div>
          <h5>${esc(section.title)}</h5>
          <p>${esc(section.desc)}</p>
        </div>
      </div>
      <dl class="manual-rows">
        ${section.rows.map(renderManualRow).join('')}
      </dl>
    </section>`;
  }

  function strategyPolicyMitre(policy, plan) {
    const labels = strategyControlsForPolicy(policy, plan);
    return plan.mitre
      .map(item => ({ ...item, via: item.controls.filter(label => labels.includes(label)) }))
      .filter(item => item.via.length && (item.status === 'Strongly mitigated' || item.status === 'Partially mitigated'))
      .sort((a, b) => a.id.localeCompare(b.id));
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
    return represented.map(tenantPolicyReference).join(', ');
  }

  function strategyRepresentationCard(policy) {
    const represented = (policy.represents || []).flatMap(id => policiesById(id));
    const representedList = represented.length
      ? represented.map(item => `<li><strong>${esc(tenantPolicyReference(item.id))}</strong><span>${esc(tenantPolicyName(item.displayName))}</span></li>`).join('')
      : '<li><span>No represented baseline policies recorded.</span></li>';
    return `<div class="strategy-note">
      <strong>${esc(tenantPolicyName(policy.displayName))}</strong>
      <p>${esc(policy.mergeReason || 'Generated consolidated strategy policy.')}</p>
      <span>${esc(policy.separateReason || 'No additional separation note.')}</span>
      <ul class="represented-list">${representedList}</ul>
    </div>`;
  }

  function strategySafetyCard(item) {
    const policies = item.policies.length
      ? `<span>${esc(item.policies.map(policy => tenantPolicyReference(policy.id)).join(', '))}</span>`
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
      type: 'strategy',
      requirements: { ...plan.requirements },
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
        id: tenantPolicyReference(policy.id),
        displayName: tenantPolicyName(policy.displayName),
        sourceFile: policy.sourceFile,
        type: policy.consolidated ? 'consolidated' : isPreviewPolicy(policy) ? 'preview/beta' : 'baseline',
        recommendedDecision: strategyDecisionForPolicy(policy, plan),
        represents: (policy.represents || []).map(tenantPolicyReference)
      })),
      baselineEquivalent: plan.equivalentPolicies.map(policy => ({ id: tenantPolicyReference(policy.id), displayName: tenantPolicyName(policy.displayName), sourceFile: policy.sourceFile })),
      keptSeparateForSafety: plan.safety.map(item => ({
        title: item.title,
        reason: item.body,
        policies: item.policies.map(policy => tenantPolicyReference(policy.id))
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
      requirements: { ...state.strategy },
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
      requirements: { ...state.strategy },
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
        id: tenantPolicyReference(policy.id),
        displayName: tenantPolicyName(policy.displayName),
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
          <span class="eyebrow">${esc(tenantPolicyReference(policy.id))} - ${esc(policy.persona)}</span>
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
    if (state.manualGuidePolicy !== policyKey(policy)) {
      state.manualGuidePolicy = policyKey(policy);
      state.manualGuideStep = '01';
    }
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
    const authenticationBlocked = configuredAuthenticationExportBlocked(policy);
    $('copyJsonBtn').disabled = guideOnly || authenticationBlocked;
    $('downloadPolicyBtn').disabled = guideOnly || authenticationBlocked;
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
    if (!visibleSections.some(section => section.step === state.manualGuideStep)) state.manualGuideStep = visibleSections[0]?.step || '01';
    const activeSection = visibleSections.find(section => section.step === state.manualGuideStep) || visibleSections[0];
    const guideOnly = isGuideOnlyPolicy(item)
      ? `<div class="manual-callout guide-only"><strong>Object IDs required before export</strong><span>${esc(guideOnlyText())} The checklist below is safe to use for manual planning, but Graph JSON copy/download is disabled until the required scenario objects are supplied.</span></div>`
      : '';
    const preview = isPreviewPolicy(item)
      ? `<div class="manual-callout beta"><strong>Preview/beta policy fields</strong><span>This policy includes agent identity or agent resource targeting. Build manually only in tenants where the current Entra and Microsoft Graph beta/preview capabilities are available.</span></div>`
      : '';
    const authenticationBlocked = configuredAuthenticationExportBlocked(item)
      ? `<div class="manual-callout guide-only"><strong>Readiness required before enabled export</strong><span>${esc(authenticationReadinessMissing(state.appliedStrategy?.requirements || state.strategy, item).map(key => AUTHENTICATION_READINESS_STEPS.find(step => step.id === key)?.label || key).join(', '))}. Report-only export remains available.</span></div>`
      : '';
    const authenticationStrength = renderAuthenticationStrengthReadiness(item, exported);
    const simpleNote = state.expertMode ? '' : '<div class="manual-callout simple"><strong>Configured settings only</strong><span>Turn on Advanced detail to show raw object IDs and every unconfigured Entra section.</span></div>';
    $('manualGuide').innerHTML = `${guideOnly}${authenticationBlocked}${preview}${simpleNote}${manualPolicySnapshot(exported)}${authenticationStrength}
      <div class="manual-path-layout">
        <nav class="manual-path-nav" aria-label="Entra policy build sections">
          ${visibleSections.map(section => manualPathButton(section, item)).join('')}
        </nav>
        ${activeSection ? renderActiveManualSection(activeSection, item) : '<div class="empty-state">No configured settings are available for this policy.</div>'}
      </div>`;
  }

  function manualPathButton(section, item) {
    const active = section.step === state.manualGuideStep;
    const complete = state.manualGuideCompleted.has(`${policyKey(item)}|${section.step}`);
    const meta = manualSectionMeta(section.step);
    return `<button type="button" class="manual-path-step ${active ? 'active' : ''} ${complete ? 'complete' : ''}" data-manual-step="${esc(section.step)}" aria-current="${active ? 'step' : 'false'}">
      <span>${esc(section.step)}</span><div><strong>${esc(section.title)}</strong><small>${esc(meta.shortPath)}</small></div><em>${complete ? 'Done' : active ? 'Current' : 'Open'}</em>
    </button>`;
  }

  function renderActiveManualSection(section, item) {
    const meta = manualSectionMeta(section.step);
    const complete = state.manualGuideCompleted.has(`${policyKey(item)}|${section.step}`);
    return `<section class="manual-active-section manual-section">
      <header class="manual-section-head">
        <span>${esc(section.step)}</span>
        <div>
          <h5>${esc(section.title)}</h5>
          <p>${esc(section.desc)}</p>
        </div>
        <b>${section.rows.some(row => !row.empty) ? 'Configure: Yes' : 'Configure: No'}</b>
      </header>
      <div class="manual-portal-path"><span>Entra navigation</span><strong>${esc(meta.path)}</strong></div>
      <dl class="manual-rows">
        ${section.rows.map(renderManualRow).join('')}
      </dl>
      <div class="manual-step-guidance">
        <article><span>Why this matters</span><strong>${esc(meta.why)}</strong></article>
        <article><span>User impact</span><strong>${esc(meta.impact)}</strong></article>
        <article class="warning"><span>Check before continuing</span><strong>${esc(meta.warning)}</strong></article>
      </div>
      <footer class="manual-step-actions">
        <button class="btn secondary" type="button" data-manual-copy="${esc(section.step)}">Copy this step</button>
        <button class="btn ${complete ? 'secondary' : 'primary'}" type="button" data-manual-complete="${esc(section.step)}">${complete ? 'Mark as not complete' : 'Mark step complete'}</button>
      </footer>
    </section>`;
  }

  function renderManualRow(row) {
    const empty = row.empty ? ' empty' : '';
    const help = row.help ? `<em>${esc(row.help)}</em>` : '';
    const value = row.entries ? renderManualEntries(row.entries) : `<span>${esc(row.value)}</span>`;
    return `<div class="manual-row${empty}">
      <dt>${esc(row.label)}</dt>
      <dd><small class="manual-action-label">${row.empty ? 'Leave unchanged' : 'Select or set'}</small>${value}${help}</dd>
    </div>`;
  }

  function manualSectionMeta(step) {
    return {
      '01': { shortPath: 'New policy', path: 'Microsoft Entra admin center > Entra ID > Conditional Access > Policies > New policy', why: 'Creates a clearly named policy shell and establishes the rollout state after all settings are reviewed.', impact: 'No user impact until the policy is enabled.', warning: 'Create assignments and exclusions before changing the policy to On.' },
      '02': { shortPath: 'Assignments', path: 'Assignments > Users or workload identities', why: 'Defines exactly which identities receive the protection and which emergency or exception identities remain outside it.', impact: 'Only included identities that are not excluded evaluate this policy.', warning: 'Validate emergency-access exclusions and avoid targeting non-human identities with human MFA controls.' },
      '03': { shortPath: 'Target resources', path: 'Assignments > Target resources', why: 'Limits the policy to the cloud apps, user actions, authentication contexts, or agent resources that need this control.', impact: 'Users see the control only when accessing an included resource.', warning: 'All resources is broad. Use What If to test representative applications before enforcement.' },
      '04': { shortPath: 'Conditions', path: 'Conditions > Configure', why: 'Uses device, client, network, platform, and risk signals to decide when the policy applies.', impact: 'Narrow conditions can create different sign-in experiences across devices and networks.', warning: 'Multiple configured conditions are evaluated together. Confirm the combined logic matches the intended access path.' },
      '05': { shortPath: 'Grant', path: 'Access controls > Grant', why: 'Defines whether matching access is blocked or which security requirements must be satisfied.', impact: 'Users may be blocked, prompted for stronger authentication, or required to use a compliant device.', warning: 'Do not select Require multifactor authentication and Require authentication strength in the same policy.' },
      '06': { shortPath: 'Session', path: 'Access controls > Session', why: 'Controls session lifetime, browser persistence, token behavior, and supported application restrictions.', impact: 'Shorter sessions and non-persistent browsers increase prompts but reduce the value of stolen sessions.', warning: 'Application-enforced restrictions work only with supported services. Validate the selected resource and client.' },
      '07': { shortPath: 'Validate', path: 'Enable policy > Report-only or On', why: 'Confirms emergency access, licensing, report-only findings, and What If results before enforcement.', impact: 'Report-only records impact without enforcing; On immediately affects matching sign-ins.', warning: 'Review sign-in logs and Conditional Access results before changing a broad policy to On.' },
      '!': { shortPath: 'Object lookup', path: 'Microsoft Entra admin center > Groups, Enterprise applications, or Named locations', why: 'Resolves tenant-specific objects so the engineer can select the correct named item.', impact: 'No policy should be enabled until every unresolved object is identified.', warning: 'Do not substitute a similarly named object without validating its Object ID.' }
    }[step] || { shortPath: 'Policy settings', path: 'Microsoft Entra admin center > Conditional Access', why: 'Configures this part of the policy.', impact: 'Depends on the selected setting.', warning: 'Validate the resulting policy with What If.' };
  }

  function manualPolicySnapshot(exported) {
    const conditions = exported.conditions || {};
    const grant = exported.grantControls || {};
    const session = exported.sessionControls || {};
    const identity = manualScopeSummary(conditions.users || {}, conditions.clientApplications || {});
    const resources = (conditions.applications?.includeApplications || []).map(value => manualLiteralTokenLabel(String(value).toLowerCase(), value, 'applications')).join(', ') || 'No target resource configured';
    const conditionCount = ['clientAppTypes', 'platforms', 'locations', 'signInRiskLevels', 'userRiskLevels', 'agentIdRiskLevels', 'authenticationFlows', 'devices'].filter(key => !isEmptyManualValue(conditions[key])).length;
    const grantText = grant.authenticationStrength?.displayName || (grant.builtInControls || []).map(value => manualLiteralTokenLabel(String(value).toLowerCase(), value, 'grantControls')).join(', ') || 'No grant control';
    const sessionText = Object.keys(session).length ? `${Object.keys(session).length} configured` : 'Not configured';
    return `<section class="manual-policy-snapshot" aria-label="Configured policy summary">
      ${[
        ['Identity', identity],
        ['Target', resources],
        ['Conditions', conditionCount ? `${conditionCount} configured` : 'No additional conditions'],
        ['Grant', grantText],
        ['Session', sessionText],
        ['Rollout', portalStateLabel(exported.state)]
      ].map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join('')}
    </section>`;
  }

  function manualScopeSummary(users, clientApplications) {
    if (users.includeRoles?.length) return `${users.includeRoles.length} directory roles`;
    if (users.includeGuestsOrExternalUsers) return 'Guests and external users';
    if (users.includeUsers?.includes('All')) return 'All users';
    if (users.includeGroups?.length) return `${users.includeGroups.length} selected group${users.includeGroups.length === 1 ? '' : 's'}`;
    if (clientApplications.includeServicePrincipals?.length) return `${clientApplications.includeServicePrincipals.length} service principals`;
    if (clientApplications.includeAgentIdServicePrincipals?.length) return `${clientApplications.includeAgentIdServicePrincipals.length} agent identities`;
    return 'Selected identities';
  }

  function renderAuthenticationStrengthReadiness(item, exported) {
    const strength = exported.grantControls?.authenticationStrength;
    if (!strength) return '';
    const methods = (strength.allowedCombinations || []).map(authenticationMethodLabel).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    const phishing = isPhishingResistantPolicy(item);
    return `<section class="manual-authentication-strength ${phishing ? 'phishing-resistant' : ''}">
      <div><p class="eyebrow">Authentication requirement</p><h5>Select ${esc(strength.displayName || 'the configured authentication strength')}</h5><p>${phishing ? 'Only a phishing-resistant method can satisfy this access decision. A password may still be entered, but it cannot complete the requirement by itself.' : 'The user must satisfy one of the method combinations allowed by this strength.'}</p></div>
      <div><span>Accepted methods</span><ul>${methods.map(method => `<li>${esc(method)}</li>`).join('') || '<li>Review the named authentication strength in Entra.</li>'}</ul></div>
      <div class="authentication-strength-check"><strong>Before enabling</strong><span>Confirm in-scope users are registered and emergency access has been tested. Authentication methods must be enabled separately from Conditional Access.</span></div>
    </section>`;
  }

  function toggleManualGuideStep(step) {
    const policy = selectedPolicy();
    if (!policy) return;
    const key = `${policyKey(policy)}|${step}`;
    if (state.manualGuideCompleted.has(key)) state.manualGuideCompleted.delete(key);
    else state.manualGuideCompleted.add(key);
    renderSelected();
  }

  function copyManualGuideSection(step) {
    const policy = selectedPolicy();
    if (!policy) return;
    const decision = state.decisions[policyKey(policy)] || 'exclude';
    const section = manualGuideSections(policy, exportPolicy(policy, 'configured'), decision).find(item => item.step === step);
    if (!section) return;
    const meta = manualSectionMeta(step);
    const rows = section.rows.filter(row => state.expertMode || !row.empty).map(row => {
      const value = row.entries ? manualEntriesText(row.entries, state.expertMode) : row.value;
      return `- ${row.label}: ${value}${row.help ? ` (${row.help})` : ''}`;
    }).join('\n');
    copyText(`${section.step}. ${section.title}\nEntra navigation: ${meta.path}\n${section.desc}\n${rows}\n\nWhy this matters: ${meta.why}\nUser impact: ${meta.impact}\nCheck: ${meta.warning}`, `${section.title} step copied`);
  }

  function renderManualEntries(entries) {
    return entries.map(entry => {
      if (entry.lookup) return `<span class="manual-lookup-required">${esc(entry.text)}</span>`;
      if (entry.id) return `<span class="manual-object"><strong>${esc(entry.name)}</strong>${state.expertMode && entry.type !== 'group' ? `<small>Object ID: ${esc(entry.id)}</small>` : ''}</span>`;
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
        refs[0].context === 'groups'
          ? `${refs.length} security group name${refs.length === 1 ? '' : 's'} must be resolved from the tenant object catalog`
          : refs.map(ref => `${objectContextLabel(ref.context)}: ${ref.id}`).join('\n'),
        refs[0].context === 'groups'
          ? 'Import an object catalog containing the security group display names before manual creation.'
          : 'Look this up in Entra, or import JSON containing id and displayName for this object.'
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
    $('exportConfiguredBtn').disabled = !selected.length || exportBlocked || selected.some(configuredAuthenticationExportBlocked);
    $('exportReportBtn').disabled = !selected.length || exportBlocked;
    $('exportDisabledBtn').disabled = !selected.length || exportBlocked;
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
    return tenantPolicyName(name).replace(/-/g, ' ');
  }

  function policyDisplayLine(policy) {
    return tenantPolicyName(policy.displayName || policy.id).replace(/-/g, ' ');
  }

  function tenantPolicyName(name) {
    return String(name || '')
      .replace(/^CA(?=\d{3}[A-Z]*-)/i, '')
      .replace(/^(\d{3})C(?=[A-Z]*-)/i, '$1');
  }

  function tenantPolicyReference(id) {
    return String(id || '')
      .replace(/^CA(?=\d)/i, '')
      .replace(/^(\d{3})C(?=[A-Z]*$)/i, '$1');
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
    policy.displayName = tenantPolicyName(policy.displayName);
    return sanitizePolicy(policy);
  }

  function sanitizePolicy(policy) {
    const out = {
      displayName: tenantPolicyName(policy.displayName),
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
    if (configuredAuthenticationExportBlocked(policy)) {
      toast('Complete phishing-resistant authentication readiness before copying an enabled policy');
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
      if (entry.id) return includeIds && entry.type !== 'group' ? `${entry.name} (Object ID: ${entry.id})` : entry.name;
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
    if (mode === 'configured' && selected.some(configuredAuthenticationExportBlocked)) {
      toast('Complete phishing-resistant authentication readiness before exporting enabled policies. Report-only export remains available.');
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

  function downloadBlob(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 0);
  }

  // ---------------------------------------------------------------------------
  // Minimal ZIP writer. A .docx IS a zip of XML parts, and the page's CSP blocks
  // every external script, so the archive is assembled here. Entries are stored
  // uncompressed (method 0) — a build guide is small and this avoids shipping a
  // DEFLATE implementation for no practical gain.
  // ---------------------------------------------------------------------------
  const CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i += 1) {
      let c = i;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[i] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i += 1) c = CRC32_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

  function zipStore(entries, mimeType = DOCX_MIME) {
    const encoder = new TextEncoder();
    const now = new Date();
    // MS-DOS packed date/time, which is what the ZIP local header expects.
    const dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xffff;
    const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;
    const parts = [];
    const central = [];
    let offset = 0;

    entries.forEach(entry => {
      const nameBytes = encoder.encode(entry.name);
      const data = typeof entry.data === 'string' ? encoder.encode(entry.data) : entry.data;
      const crc = crc32(data);

      const local = new DataView(new ArrayBuffer(30));
      local.setUint32(0, 0x04034b50, true);
      local.setUint16(4, 20, true);
      local.setUint16(6, 0x0800, true); // UTF-8 filenames
      local.setUint16(8, 0, true); // stored
      local.setUint16(10, dosTime, true);
      local.setUint16(12, dosDate, true);
      local.setUint32(14, crc, true);
      local.setUint32(18, data.length, true);
      local.setUint32(22, data.length, true);
      local.setUint16(26, nameBytes.length, true);
      local.setUint16(28, 0, true);
      parts.push(new Uint8Array(local.buffer), nameBytes, data);

      const dir = new DataView(new ArrayBuffer(46));
      dir.setUint32(0, 0x02014b50, true);
      dir.setUint16(4, 20, true);
      dir.setUint16(6, 20, true);
      dir.setUint16(8, 0x0800, true);
      dir.setUint16(10, 0, true);
      dir.setUint16(12, dosTime, true);
      dir.setUint16(14, dosDate, true);
      dir.setUint32(16, crc, true);
      dir.setUint32(20, data.length, true);
      dir.setUint32(24, data.length, true);
      dir.setUint16(28, nameBytes.length, true);
      dir.setUint32(42, offset, true);
      central.push(new Uint8Array(dir.buffer), nameBytes);

      offset += 30 + nameBytes.length + data.length;
    });

    const centralSize = central.reduce((n, chunk) => n + chunk.length, 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, entries.length, true);
    end.setUint16(10, entries.length, true);
    end.setUint32(12, centralSize, true);
    end.setUint32(16, offset, true);
    return new Blob([...parts, ...central, new Uint8Array(end.buffer)], { type: mimeType });
  }

  // ---------------------------------------------------------------------------
  // WordprocessingML document builder. Blocks are plain objects so the guide
  // content stays readable and separate from the XML.
  // ---------------------------------------------------------------------------
  function xmlEsc(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;')
      // Control characters are invalid in XML 1.0 and make Word reject the file.
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
  }

  function docxRun(text, opts = {}) {
    const props = [];
    if (opts.bold) props.push('<w:b/>');
    if (opts.italic) props.push('<w:i/>');
    if (opts.mono) props.push('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>');
    if (opts.color) props.push(`<w:color w:val="${opts.color}"/>`);
    if (opts.size) props.push(`<w:sz w:val="${opts.size}"/>`);
    const rPr = props.length ? `<w:rPr>${props.join('')}</w:rPr>` : '';
    return `<w:r>${rPr}<w:t xml:space="preserve">${xmlEsc(text)}</w:t></w:r>`;
  }

  function docxPara(text, opts = {}) {
    const props = [];
    if (opts.style) props.push(`<w:pStyle w:val="${opts.style}"/>`);
    if (opts.bullet) props.push('<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>');
    if (opts.pageBreakBefore) props.push('<w:pageBreakBefore/>');
    if (opts.spaceAfter !== undefined) props.push(`<w:spacing w:after="${opts.spaceAfter}"/>`);
    if (opts.shade) props.push(`<w:shd w:val="clear" w:color="auto" w:fill="${opts.shade}"/>`);
    const pPr = props.length ? `<w:pPr>${props.join('')}</w:pPr>` : '';
    const runs = Array.isArray(text) ? text.join('') : docxRun(text, opts);
    return `<w:p>${pPr}${runs}</w:p>`;
  }

  const DOCX_BORDER = '<w:tblBorders>'
    + ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']
      .map(side => `<w:${side} w:val="single" w:sz="4" w:space="0" w:color="D0D0D0"/>`).join('')
    + '</w:tblBorders>';

  // rows: [[leftCellBlocks, rightCellBlocks], ...] — a two-column reference table.
  function docxTable(rows, opts = {}) {
    const widths = opts.widths || [35, 65];
    const body = rows.map((row, index) => {
      const header = index === 0 && opts.header;
      const cells = row.map((cell, col) => {
        const shade = header ? '<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>' : '';
        const content = Array.isArray(cell) ? cell.join('') : docxPara(cell, { bold: Boolean(header) });
        return `<w:tc><w:tcPr><w:tcW w:w="${widths[col] * 50}" w:type="pct"/>${shade}</w:tcPr>${content || docxPara('')}</w:tc>`;
      }).join('');
      return `<w:tr>${header ? '<w:trPr><w:tblHeader/></w:trPr>' : ''}${cells}</w:tr>`;
    }).join('');
    // Word requires a paragraph after a table; without it the next table merges in.
    return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>${DOCX_BORDER}</w:tblPr>${body}</w:tbl>${docxPara('', { spaceAfter: 120 })}`;
  }

  const DOCX_STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="21"/></w:rPr></w:rPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="52"/><w:color w:val="1A1A1C"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="320"/></w:pPr><w:rPr><w:color w:val="6A6A6A"/><w:sz w:val="22"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:pageBreakBefore/><w:spacing w:before="240" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="34"/><w:color w:val="C2410C"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="1A1A1C"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="C2410C"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="480"/><w:contextualSpacing/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Callout"><w:name w:val="Callout"/><w:basedOn w:val="Normal"/><w:pPr><w:pBdr><w:left w:val="single" w:sz="18" w:space="8" w:color="C2410C"/></w:pBdr><w:ind w:left="120"/><w:spacing w:before="120" w:after="200"/></w:pPr></w:style>
</w:styles>`;

  const DOCX_NUMBERING = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="480" w:hanging="240"/></w:pPr></w:lvl></w:abstractNum>
  <w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>`;

  const DOCX_REPORT_STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:spacing w:after="120" w:line="300" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/><w:color w:val="201C18"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="52"/><w:color w:val="201C18"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="260"/></w:pPr><w:rPr><w:color w:val="5F5751"/><w:sz w:val="21"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="200"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="E8610A"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="140"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="201C18"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="100"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="C44E00"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="540"/><w:spacing w:after="80" w:line="300" w:lineRule="auto"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Callout"><w:name w:val="Callout"/><w:basedOn w:val="Normal"/><w:pPr><w:pBdr><w:left w:val="single" w:sz="18" w:space="8" w:color="E8610A"/></w:pBdr><w:ind w:left="120"/><w:spacing w:before="120" w:after="200"/></w:pPr></w:style>
</w:styles>`;

  const DOCX_REPORT_NUMBERING = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="540"/></w:tabs><w:ind w:left="540" w:hanging="270"/><w:spacing w:after="80" w:line="300" w:lineRule="auto"/></w:pPr></w:lvl></w:abstractNum>
  <w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>`;

  function docxReportTable(rows, widths) {
    const tableWidth = 9360;
    const resolvedWidths = widths && widths.reduce((sum, width) => sum + width, 0) === tableWidth
      ? widths
      : rows[0].map(() => Math.floor(tableWidth / rows[0].length));
    resolvedWidths[resolvedWidths.length - 1] += tableWidth - resolvedWidths.reduce((sum, width) => sum + width, 0);
    const grid = resolvedWidths.map(width => `<w:gridCol w:w="${width}"/>`).join('');
    const body = rows.map((row, rowIndex) => {
      const header = rowIndex === 0;
      const cells = row.map((cell, colIndex) => {
        const content = Array.isArray(cell) ? cell.join('') : docxPara(cell, { bold: header });
        const fill = header ? '<w:shd w:val="clear" w:color="auto" w:fill="292929"/>' : '';
        const textColor = header && !Array.isArray(cell) ? docxPara([docxRun(cell, { bold: true, color: 'FFFFFF' })]) : content;
        return `<w:tc><w:tcPr><w:tcW w:w="${resolvedWidths[colIndex]}" w:type="dxa"/><w:tcMar><w:top w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tcMar><w:vAlign w:val="center"/>${fill}</w:tcPr>${header ? textColor : (content || docxPara(''))}</w:tc>`;
      }).join('');
      return `<w:tr>${header ? '<w:trPr><w:tblHeader/></w:trPr>' : '<w:trPr><w:cantSplit/></w:trPr>'}${cells}</w:tr>`;
    }).join('');
    return `<w:tbl><w:tblPr><w:tblW w:w="${tableWidth}" w:type="dxa"/><w:tblInd w:w="120" w:type="dxa"/><w:tblLayout w:type="fixed"/>${DOCX_BORDER}</w:tblPr><w:tblGrid>${grid}</w:tblGrid>${body}</w:tbl>${docxPara('', { spaceAfter: 120 })}`;
  }

  function buildDocx(blocks, options = {}) {
    const styles = options.styles || DOCX_STYLES;
    const numbering = options.numbering || DOCX_NUMBERING;
    const section = options.section || '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="709" w:footer="709" w:gutter="0"/></w:sectPr>';
    const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${blocks.join('')}${section}</w:body></w:document>`;
    return zipStore([
      {
        name: '[Content_Types].xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/></Types>`
      },
      {
        name: '_rels/.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`
      },
      {
        name: 'word/_rels/document.xml.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/></Relationships>`
      },
      { name: 'word/document.xml', data: document },
      { name: 'word/styles.xml', data: styles },
      { name: 'word/numbering.xml', data: numbering }
    ]);
  }

  function policyOfficeValue(value) {
    if (value === null || value === undefined || value === '') return '';
    if (Array.isArray(value)) return value.map(policyOfficeValue).filter(Boolean).join('; ');
    if (typeof value !== 'object') return String(value);
    const name = value.label || value.name || value.displayName || value.id || value.key || '';
    const detail = [value.value, value.detail, value.description, value.status]
      .find(candidate => candidate !== null && candidate !== undefined && candidate !== '');
    const detailText = detail !== undefined && detail !== name ? String(detail) : '';
    return [name, detailText].filter(candidate => candidate !== '').join(': ');
  }

  function policyOfficeList(items, formatter) {
    return (items || []).map(formatter || policyOfficeValue).filter(Boolean).join('; ');
  }

  function caCoverageTopEntries(map, cap = LOG_TOP_CAP) {
    return [...map.entries()]
      .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
      .slice(0, cap)
      .map(([name, count]) => ({ name, count }));
  }

  function caCoveragePercent(value, total) {
    return total ? value / total : 0;
  }

  function buildCaCoverageReport(la = state.logAnalysis, options = {}) {
    const includeEvents = options.includeEvents !== false;
    const journey = la.agg?.journey || createSignInAgg().journey;
    const successful = Number(la.summary?.success) || 0;
    const categoryMap = new Map(CA_COVERAGE_CATEGORIES.map(meta => [meta.id, {
      ...meta,
      count: 0,
      share: 0,
      sources: new Map(),
      identities: new Map(),
      apps: new Map(),
      locations: new Map(),
      routes: [],
      samples: []
    }]));
    const decisionLabels = new Map(LOG_JOURNEY_DECISIONS.map(item => [item.id, item.label]));
    const outcomeLabels = new Map(LOG_JOURNEY_OUTCOMES.map(item => [item.id, item.label]));
    [...journey.routes.values()].forEach(route => {
      const categoryId = caCoverageCategoryId(route.decision, route.outcome);
      const category = categoryMap.get(categoryId);
      const count = Number(route.success) || 0;
      if (!category || !count) return;
      category.count += count;
      incrementJourneyMap(category.sources, route.source, count);
      route.identities.forEach((value, key) => incrementJourneyMap(category.identities, key, value));
      route.apps.forEach((value, key) => incrementJourneyMap(category.apps, key, value));
      route.locations.forEach((value, key) => incrementJourneyMap(category.locations, key, value));
      category.routes.push({
        category: categoryId,
        source: route.source,
        sourceLabel: LOG_SOURCES[route.source]?.label || route.source,
        decision: route.decision,
        decisionLabel: decisionLabels.get(route.decision) || route.decision,
        outcome: route.outcome,
        outcomeLabel: outcomeLabels.get(route.outcome) || route.outcome,
        count,
        share: caCoveragePercent(count, successful),
        confidence: category.confidence,
        interpretation: category.interpretation,
        action: category.action
      });
    });
    // The UI only needs aggregate coverage. Normalising and sorting the bounded 50,000-row
    // ledger is reserved for Office exports so opening the visual policy board stays cheap.
    const events = includeEvents
      ? [...(journey.coverageEvents || [])]
        .sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')))
        .map(event => {
          const category = categoryMap.get(event.category);
          return {
            ...event,
            categoryLabel: category?.label || event.category,
            confidence: category?.confidence || '',
            decisionLabel: decisionLabels.get(event.decision) || event.decision,
            outcomeLabel: outcomeLabels.get(event.outcome) || event.outcome,
            sourceLabel: LOG_SOURCES[event.source]?.label || event.source,
            policySummary: policyOfficeList(event.evaluatedPolicies, policy => `${policy.name} (${policy.result})`),
            unsatisfiedConditions: policyOfficeList(event.evaluatedPolicies?.flatMap(policy => policy.conditions || []))
          };
        })
      : [];
    const categories = CA_COVERAGE_CATEGORIES.map(meta => {
      const category = categoryMap.get(meta.id);
      category.share = caCoveragePercent(category.count, successful);
      category.topSources = caCoverageTopEntries(category.sources).map(item => ({ ...item, name: LOG_SOURCES[item.name]?.label || item.name }));
      category.topIdentities = caCoverageTopEntries(category.identities);
      category.topApps = caCoverageTopEntries(category.apps);
      category.topLocations = caCoverageTopEntries(category.locations);
      category.samples = includeEvents ? events.filter(event => event.category === category.id).slice(0, 10) : [];
      return category;
    });
    const byId = Object.fromEntries(categories.map(category => [category.id, category]));
    const protectedSuccess = journey.outcomes.get('protectedSuccess') || 0;
    const confirmedGap = byId.confirmedGap?.count || 0;
    const reportOnlyExposure = byId.reportOnlyExposure?.count || 0;
    const evidenceUnknown = byId.evidenceUnknown?.count || 0;
    const expectedOutsideCa = byId.expectedOutsideCa?.count || 0;
    const reviewTotal = confirmedGap + reportOnlyExposure + evidenceUnknown;
    const reconciled = protectedSuccess + reviewTotal + expectedOutsideCa;
    return {
      title: 'Conditional Access coverage',
      headline: 'Successful access without enforcing CA',
      successful,
      protectedSuccess,
      confirmedGap,
      reportOnlyExposure,
      evidenceUnknown,
      expectedOutsideCa,
      reviewTotal,
      reconciled,
      reconciliationDifference: successful - reconciled,
      blocked: journey.outcomes.get('blocked') || 0,
      categories,
      routes: categories.flatMap(category => category.routes),
      events,
      retention: {
        limit: LOG_COVERAGE_EVENT_ROW_CAP,
        eligibleRows: journey.coverageEventRows || 0,
        retainedRows: journey.coverageEvents?.length || 0,
        omittedRows: journey.coverageOmittedRows || 0,
        representedEvents: journey.coverageRepresentedEvents || 0,
        retainedRepresentedEvents: journey.coverageRetainedRepresentedEvents || 0,
        omittedRepresentedEvents: journey.coverageOmittedRepresentedEvents || 0,
        truncated: Boolean(journey.coverageOmittedRows)
      }
    };
  }

  function policyOfficeStateLabel(state) {
    return state === 'enforcing' ? 'Enforcing' : state === 'reportOnly' ? 'Report-only' : 'Never matched';
  }

  function policyOfficeReportOnlyLabel(result) {
    const labels = {
      reportonlysuccess: 'Success',
      reportonlyfailure: 'Failure',
      reportonlyuseractionrequired: 'User action required',
      reportonlynotapplied: 'Not applied',
      reportonlyinterrupted: 'Interrupted'
    };
    return labels[normToken(result)] || result || 'Unknown result';
  }

  function policyOfficeEvidenceRange(summary) {
    if (!summary?.from || !summary?.to) return 'Date range unavailable';
    return `${summary.from.slice(0, 10)} to ${summary.to.slice(0, 10)}`;
  }

  function policyOfficeMfaExclusions(policies) {
    return mfaExclusionPolicies(policies).map(policy => ({
      id: policy.id || '',
      name: policy.name,
      state: policy.state,
      stateLabel: policyOfficeStateLabel(policy.state),
      excludedEventCount: Number(policy.excludedEventCount) || 0,
      rules: (policy.exclusionRules || []).filter(rule => rule.identityAssignment).map(rule => ({ ...rule })),
      identities: (policy.exclusionIdentities || []).map(identity => ({
        ...identity,
        rules: (identity.rules || []).map(rule => ({ ...rule })),
        apps: (identity.apps || []).map(item => ({ ...item })),
        locations: (identity.locations || []).map(item => ({ ...item })),
        sources: [...(identity.sources || [])]
      })),
      samples: (policy.exclusionSamples || []).map(sample => ({ ...sample, rules: [...(sample.rules || [])] }))
    }));
  }

  function buildPolicyOfficeReport(kind) {
    const la = state.logAnalysis;
    const journey = buildLogJourneyModel();
    const summary = la.summary || {};
    const elementLabels = new Map([...LOG_JOURNEY_STAGES.flatMap(stage => stage.elements), ...LOG_JOURNEY_ADJACENT]
      .map(item => [item.id, item.label]));
    const common = {
      kind,
      generatedAt: new Date().toISOString(),
      evidenceRange: policyOfficeEvidenceRange(summary),
      signIns: Number(summary.total) || 0,
      sources: policyOfficeList(summary.sourcesLoaded, key => LOG_SOURCES[key]?.label || key),
      files: policyOfficeList(la.files, file => `${file.name} (${file.representedEvents || 0} represented sign-ins)`)
    };
    if (kind === 'recommended') {
      const policies = journey.recommendedPolicies.map(policy => {
        const controls = policyOfficeList(policy.controls, id => CONTROLS[id]?.label || id);
        const drivers = (policy.drivers || []).map(driver => ({
          ...driver,
          detail: `${driver.title} - ${driver.affected} of ${driver.scope}${Number.isFinite(Number(driver.pct)) ? ` (${driver.pct}%)` : ''}`
        }));
        const prerequisites = (policy.prerequisites || []).map(item => ({
          status: item.status || '',
          label: item.label || item.key || '',
          detail: item.detail || ''
        }));
        const settings = [...(policy.tailoring || []), ...(policy.settings || [])].map(item => ({
          label: item.label || item.key || 'Setting',
          value: policyOfficeValue(item.value ?? item.detail ?? item)
        }));
        return {
          id: policy.id,
          name: tenantPolicyName(policy.displayName),
          actionTier: policy.actionTier,
          actionTierLabel: policy.actionTierLabel,
          basis: policy.basis?.label || '',
          basisDetail: policy.basis?.detail || '',
          reasons: policyOfficeList(policy.reasonLabels),
          purpose: policy.summary || policy.basis?.detail || '',
          capability: policy.capabilityStatus || '',
          coverage: coverageHeadline(policy.coverage),
          applicability: policy.applicability || '',
          primaryRelationship: elementLabels.get(policy.primaryElementId) || policy.primaryElementId || '',
          secondaryRelationships: policyOfficeList(policy.secondaryElementIds, id => elementLabels.get(id) || id),
          controls,
          drivers,
          affected: drivers.reduce((maximum, driver) => Math.max(maximum, Number(driver.affected) || 0), 0),
          prerequisites,
          settings,
          requiredObjects: policyOfficeList(policy.requiredObjects),
          replaces: policyOfficeList(policy.represents),
          consolidated: Boolean(policy.consolidated),
          mergeReason: policy.mergeReason || ''
        };
      });
      return {
        ...common,
        title: 'Recommended Conditional Access policies',
        caveat: 'These policies are guidance derived from the loaded evidence and tenant answers. Validate tenant objects, licensing, exclusions and application support before deployment; create policies in report-only mode first.',
        policies
      };
    }
    const policies = [...journey.observedPolicies]
      .sort((a, b) => {
        const rank = policy => policy.state === 'enforcing' ? 0 : policy.state === 'reportOnly' ? 1 : 2;
        return rank(a) - rank(b) || b.applied - a.applied || b.evaluations - a.evaluations || a.name.localeCompare(b.name);
      })
      .map(policy => {
        const controls = [...policy.grants.map(item => item.label), ...policy.sessions.map(item => item.label)];
        const strengths = policy.authStrength.map(item => `${item.name} (${item.count})`);
        const observedScope = policyOfficeList(policy.observedConfig, item => `${item.label}: ${item.value}${item.note ? ` - ${item.note}` : ''}`);
        const excludedPrincipals = policyOfficeList(policy.excludedPrincipals, item => `${item.name} (${item.count})`);
        const mfaExclusion = policyOfficeMfaExclusions([policy])[0] || null;
        return {
          id: policy.id || '',
          name: policy.name,
          state: policy.state,
          stateLabel: policyOfficeStateLabel(policy.state),
          evaluations: Number(policy.evaluations) || 0,
          applied: Number(policy.applied) || 0,
          blocked: Number(policy.blocked) || 0,
          reportOnly: Number(policy.reportOnly) || 0,
          notApplied: Number(policy.notApplied) || 0,
          hitRate: Number(policy.hitRate) || 0,
          controls: [...new Set(controls)].join('; '),
          authenticationStrength: strengths.join('; '),
          observedScope: [observedScope, excludedPrincipals ? `Excluded principals observed: ${excludedPrincipals}` : ''].filter(Boolean).join('; '),
          reportOnlyResults: policyOfficeList(policy.reportOnlyResults, item => `${policyOfficeReportOnlyLabel(item.name)} (${item.count})`),
          notSatisfied: policyOfficeList(policy.notSatisfied, item => `${item.label} (${item.count})`),
          topUsers: policyOfficeList(policy.topUsers, item => `${item.name} (${item.count})`),
          topApps: policyOfficeList(policy.topApps, item => `${item.name} (${item.count})`),
          topDevices: policyOfficeList(policy.topDevices, item => `${item.name} (${item.count})`),
          topLocations: policyOfficeList(policy.topLocations, item => `${item.name} (${item.count})`),
          excludedPrincipals,
          sources: policyOfficeList(policy.sources, key => LOG_SOURCES[key]?.label || key),
          from: policy.from || '',
          to: policy.to || '',
          samples: (policy.samples || []).slice(0, 25).map(sample => ({ ...sample })),
          mfaExclusion
        };
      });
    return {
      ...common,
      title: 'Observed Conditional Access policies',
      caveat: 'This is runtime evidence from the loaded sign-in window, not an authoritative tenant policy export. A quiet or never-matched policy can still exist and be correctly configured; compare with a Graph configuration export before changing it.',
      coverage: buildCaCoverageReport(la),
      mfaExclusions: policyOfficeMfaExclusions(journey.observedPolicies),
      policies
    };
  }

  function policyOfficeSummaryRows(report) {
    if (report.kind === 'recommended') {
      const tiers = report.policies.reduce((counts, policy) => {
        counts[policy.actionTier] = (counts[policy.actionTier] || 0) + 1;
        return counts;
      }, {});
      const bases = report.policies.reduce((counts, policy) => {
        counts[policy.basis] = (counts[policy.basis] || 0) + 1;
        return counts;
      }, {});
      return [
        ['Policies', String(report.policies.length)],
        ['Action tiers', `${tiers.actNow || 0} act now; ${tiers.validateFirst || 0} validate first; ${tiers.optionalAdvanced || 0} optional / advanced`],
        ['Evidence basis', Object.entries(bases).map(([label, count]) => `${label}: ${count}`).join('; ') || 'None'],
        ['Sign-ins assessed', report.signIns.toLocaleString()],
        ['Evidence window', report.evidenceRange],
        ['Loaded sources', report.sources || 'None recorded']
      ];
    }
    const states = report.policies.reduce((counts, policy) => {
      counts[policy.state] = (counts[policy.state] || 0) + 1;
      return counts;
    }, {});
    return [
      ['Policies recorded', String(report.policies.length)],
      ['Policy states', `${states.enforcing || 0} enforcing; ${states.reportOnly || 0} report-only; ${states.neverMatched || 0} never matched`],
      ['Evaluations', report.policies.reduce((sum, policy) => sum + policy.evaluations, 0).toLocaleString()],
      ['Sign-ins assessed', report.signIns.toLocaleString()],
      ['Successful access without enforcing CA', report.coverage.reviewTotal.toLocaleString()],
      ['Confirmed scoping gaps', report.coverage.confirmedGap.toLocaleString()],
      ['Report-only exposure', report.coverage.reportOnlyExposure.toLocaleString()],
      ['Evidence unknown', report.coverage.evidenceUnknown.toLocaleString()],
      ['MFA policies with observed identity exclusions', report.mfaExclusions.length.toLocaleString()],
      ['Observed identities on MFA exclusion paths', new Set(report.mfaExclusions.flatMap(policy => policy.identities.map(identity => identity.objectId || `${identity.identityType}:${identity.name}`))).size.toLocaleString()],
      ['Evidence window', report.evidenceRange],
      ['Loaded sources', report.sources || 'None recorded']
    ];
  }

  function caCoveragePercentLabel(count, total) {
    return `${Math.round(caCoveragePercent(count, total) * 1000) / 10}%`;
  }

  function caCoverageConcentration(category) {
    return [
      category.topSources.length ? `Sources: ${category.topSources.map(item => `${item.name} (${item.count.toLocaleString()})`).join(', ')}` : '',
      category.topIdentities.length ? `Identities: ${category.topIdentities.map(item => `${item.name} (${item.count.toLocaleString()})`).join(', ')}` : '',
      category.topApps.length ? `Apps / resources: ${category.topApps.map(item => `${item.name} (${item.count.toLocaleString()})`).join(', ')}` : '',
      category.topLocations.length ? `Locations: ${category.topLocations.map(item => `${item.name} (${item.count.toLocaleString()})`).join(', ')}` : ''
    ].filter(Boolean);
  }

  function buildCaCoverageDocxBlocks(coverage, headingStyle = 'Heading1') {
    const detailHeadingStyle = headingStyle === 'Heading1' ? 'Heading2' : 'Heading3';
    const blocks = [
      docxPara('Conditional Access coverage', { style: headingStyle }),
      docxPara([
        docxRun(`${coverage.reviewTotal.toLocaleString()} successful event${coverage.reviewTotal === 1 ? '' : 's'} require coverage review. `, { bold: true }),
        docxRun('The categories below deliberately separate confirmed policy gaps, report-only exposure, incomplete evidence and activity that sits outside Conditional Access by design or eligibility.')
      ], { style: 'Callout' }),
      docxReportTable([
        ['Measure', 'Result'],
        ['Successful events analysed', coverage.successful.toLocaleString()],
        ['Protected by an enforcing CA policy', `${coverage.protectedSuccess.toLocaleString()} (${caCoveragePercentLabel(coverage.protectedSuccess, coverage.successful)})`],
        ['Successful access without enforcing CA', `${coverage.reviewTotal.toLocaleString()} (${caCoveragePercentLabel(coverage.reviewTotal, coverage.successful)})`],
        ['Confirmed scoping gap', `${coverage.confirmedGap.toLocaleString()} (${caCoveragePercentLabel(coverage.confirmedGap, coverage.successful)})`],
        ['Report-only exposure', `${coverage.reportOnlyExposure.toLocaleString()} (${caCoveragePercentLabel(coverage.reportOnlyExposure, coverage.successful)})`],
        ['Evidence unknown', `${coverage.evidenceUnknown.toLocaleString()} (${caCoveragePercentLabel(coverage.evidenceUnknown, coverage.successful)})`],
        ['Expected outside CA', `${coverage.expectedOutsideCa.toLocaleString()} (${caCoveragePercentLabel(coverage.expectedOutsideCa, coverage.successful)}) - not counted as bypasses`],
        ['Successful-event reconciliation', coverage.reconciliationDifference === 0 ? `${coverage.reconciled.toLocaleString()} of ${coverage.successful.toLocaleString()} - complete` : `${coverage.reconciled.toLocaleString()} of ${coverage.successful.toLocaleString()} - difference ${coverage.reconciliationDifference.toLocaleString()}`]
      ], [4000, 5360]),
      docxPara('Coverage classification', { style: detailHeadingStyle }),
      docxReportTable([
        ['Category', 'Events', 'Share', 'Meaning'],
        ...coverage.categories.map(category => [
          category.label,
          category.count.toLocaleString(),
          caCoveragePercentLabel(category.count, coverage.successful),
          `${category.confidence}. ${category.interpretation}`
        ])
      ], [2000, 1100, 1200, 5060]),
      docxPara('Expected outside CA activity is reported for reconciliation and context only. It is never included in the confirmed-gap or coverage-review totals.', { italic: true })
    ];
    coverage.categories.forEach(category => {
      if (!category.count) return;
      blocks.push(docxPara(`${category.label} - ${category.count.toLocaleString()} events`, { style: detailHeadingStyle }));
      blocks.push(docxPara(category.interpretation));
      blocks.push(docxPara([docxRun('Recommended action. ', { bold: true }), docxRun(category.action)]));
      const concentration = caCoverageConcentration(category);
      if (concentration.length) blocks.push(docxPara(concentration.join(' | ')));
      if (category.samples.length) {
        blocks.push(docxPara('Representative events', { style: 'Heading3' }));
        blocks.push(docxReportTable([
          ['UTC time', 'Source', 'Identity', 'App / resource', 'CA evidence'],
          ...category.samples.map(sample => [
            sample.time ? sample.time.replace('T', ' ').replace(/:\d{2}\.\d{3}Z$/, ' UTC') : 'Not returned',
            LOG_SOURCES[sample.source]?.short || sample.source,
            sample.principal,
            sample.app,
            `${sample.decisionLabel}; ${sample.caStatus}${sample.representedEvents > 1 ? `; represents ${sample.representedEvents} events` : ''}`
          ])
        ], [1600, 1200, 2200, 2400, 1960]));
      }
    });
    const retained = coverage.retention;
    blocks.push(docxPara([
      docxRun('Event-detail handling. ', { bold: true }),
      docxRun(`${retained.retainedRows.toLocaleString()} of ${retained.eligibleRows.toLocaleString()} qualifying imported rows are retained in the local evidence ledger, representing ${retained.retainedRepresentedEvents.toLocaleString()} of ${retained.representedEvents.toLocaleString()} events.${retained.truncated ? ` The ${retained.limit.toLocaleString()}-row browser safety limit omitted ${retained.omittedRows.toLocaleString()} rows representing ${retained.omittedRepresentedEvents.toLocaleString()} events; summary totals remain complete.` : ' The ledger is complete for the loaded evidence.'} Event details may contain identities, IP addresses and device information; handle the export as security-sensitive data.`)
    ], { style: 'Callout' }));
    return blocks;
  }

  function buildMfaExclusionDocxBlocks(exclusions, headingStyle = 'Heading1') {
    const detailHeadingStyle = headingStyle === 'Heading1' ? 'Heading2' : 'Heading3';
    const identityKeys = new Set((exclusions || []).flatMap(policy => policy.identities.map(identity => identity.objectId || `${identity.identityType}:${identity.name}`)));
    const observations = (exclusions || []).reduce((sum, policy) => sum + policy.excludedEventCount, 0);
    const blocks = [
      docxPara('MFA exclusion risk', { style: headingStyle }),
      docxPara([
        docxRun('High review priority. ', { bold: true }),
        docxRun(exclusions.length
          ? `${exclusions.length} MFA-related polic${exclusions.length === 1 ? 'y' : 'ies'} returned an exercised identity-assignment exclusion, affecting ${identityKeys.size} observed identit${identityKeys.size === 1 ? 'y' : 'ies'} across ${observations.toLocaleString()} policy-event observation${observations === 1 ? '' : 's'}. An exclusion may be intentional, including emergency access, but it can also remove MFA from high-value identities.`
          : 'No exercised identity-assignment exclusion was returned for an MFA-related policy in this sign-in window. This is not proof that the stored tenant configuration contains no exclusions.'),
      ], { style: 'Callout' }),
      docxPara('Evidence boundary: sign-in data identifies the affected identity and the exclusion rule category. For directory-role and group exclusions it does not return the configured role or group name/object ID. Inspect the policy in Microsoft Entra or compare an authorised Conditional Access configuration export before accepting the exclusion.', { italic: true })
    ];
    exclusions.forEach((policy, policyIndex) => {
      blocks.push(docxPara(`${policyIndex + 1}. ${policy.name}`, { style: detailHeadingStyle }));
      blocks.push(docxReportTable([
        ['Rule category', 'Observed events', 'What the sign-in evidence proves'],
        ...policy.rules.map(rule => [rule.ruleLabel, rule.count.toLocaleString(), rule.detail])
      ], [2100, 1400, 5860]));
      const visibleIdentities = policy.identities.slice(0, LOG_EXCLUSION_DOCX_CAP);
      if (visibleIdentities.length) {
        blocks.push(docxPara('Identities observed taking the exclusion path', { style: 'Heading3', pageBreakBefore: policyIndex > 0 }));
        blocks.push(docxReportTable([
          ['Identity', 'Object ID / type', 'Events', 'Rule / affected context'],
          ...visibleIdentities.map(identity => [
            identity.name,
            `${identity.objectId || 'Object ID not returned'}; ${[identity.identityType, identity.userType].filter(Boolean).join(' / ') || 'user'}`,
            identity.count.toLocaleString(),
            `${identity.rules.map(rule => `${rule.label} (${rule.count})`).join('; ')}. Apps: ${identity.apps.slice(0, 5).map(item => `${item.name} (${item.count})`).join(', ') || 'not returned'}. Locations: ${identity.locations.slice(0, 5).map(item => `${item.name} (${item.count})`).join(', ') || 'not returned'}. Observed ${identity.from ? identity.from.slice(0, 16).replace('T', ' ') : 'unknown'} to ${identity.to ? identity.to.slice(0, 16).replace('T', ' ') : 'unknown'} UTC.`
          ])
        ], [2100, 2350, 900, 4010]));
        if (policy.identities.length > visibleIdentities.length) {
          blocks.push(docxPara(`The document shows the top ${visibleIdentities.length} of ${policy.identities.length} observed identities for readability. The XLSX export contains the complete observed identity list.`, { italic: true }));
        }
      }
      if (policy.samples.length) {
        blocks.push(docxPara('Representative exclusion events', { style: 'Heading3' }));
        blocks.push(docxReportTable([
          ['UTC time', 'Identity', 'App / location', 'Rule and result'],
          ...policy.samples.slice(0, 10).map(sample => [
            sample.time ? sample.time.replace('T', ' ').slice(0, 19) : 'Not returned',
            `${sample.principal}${sample.objectId ? ` (${sample.objectId})` : ''}`,
            `${sample.app}; ${sample.location}; ${sample.source}`,
            `${sample.rules.join(', ')}; ${sample.result}; represents ${sample.representedEvents} event${sample.representedEvents === 1 ? '' : 's'}`
          ])
        ], [1700, 2500, 2700, 2460]));
      }
    });
    blocks.push(docxPara('Event details may contain personal, device, location or network information. Store and share this report as security-sensitive evidence.', { style: 'Callout' }));
    return blocks;
  }

  function buildPolicyOfficeDocxBlocks(report) {
    const blocks = [
      docxPara(report.title, { style: 'Title' }),
      docxPara(`Generated locally by CA Architect V2 on ${report.generatedAt.slice(0, 10)}. Evidence window: ${report.evidenceRange}.`, { style: 'Subtitle' }),
      docxPara([docxRun('How to read this report. ', { bold: true }), docxRun(report.caveat)], { style: 'Callout' }),
      docxPara('Summary', { style: 'Heading1' }),
      docxReportTable([['Measure', 'Result'], ...policyOfficeSummaryRows(report)], [2700, 6660])
    ];
    if (report.files) blocks.push(docxPara([docxRun('Files analysed: ', { bold: true }), docxRun(report.files)]));
    if (report.kind === 'observed') {
      blocks.push(...buildCaCoverageDocxBlocks(report.coverage));
      blocks.push(...buildMfaExclusionDocxBlocks(report.mfaExclusions));
    }
    blocks.push(docxPara('Policy overview', { style: 'Heading1' }));
    if (report.kind === 'recommended') {
      blocks.push(docxReportTable([
        ['Policy', 'Action tier', 'Basis'],
        ...report.policies.map(policy => [policy.name, policy.actionTierLabel, policy.basis])
      ], [4800, 2460, 2100]));
    } else {
      blocks.push(docxReportTable([
        ['Policy', 'State', 'Evaluated', 'Hit rate'],
        ...report.policies.map(policy => [policy.name, policy.stateLabel, policy.evaluations.toLocaleString(), `${policy.hitRate}%`])
      ], [4500, 1900, 1460, 1500]));
    }
    blocks.push(docxPara('Policy details', { style: 'Heading1' }));
    report.policies.forEach((policy, index) => {
      blocks.push(docxPara(`${index + 1}. ${policy.name}`, { style: 'Heading2' }));
      if (report.kind === 'recommended') {
        blocks.push(docxReportTable([
          ['Field', 'Assessment'],
          ['Policy ID', policy.id],
          ['Action tier', policy.actionTierLabel],
          ['Evidence basis', `${policy.basis}${policy.basisDetail ? ` - ${policy.basisDetail}` : ''}`],
          ['Purpose', policy.purpose || 'No additional summary recorded'],
          ['Capability', policy.capability || 'Not recorded'],
          ['Coverage', policy.coverage || 'Not measured'],
          ['Applicability', policy.applicability || 'Not recorded'],
          ['Control relationship', [policy.primaryRelationship, policy.secondaryRelationships].filter(Boolean).join('; ') || 'Not mapped'],
          ['Controls', policy.controls || 'No controls recorded'],
          ['Reason labels', policy.reasons || 'Baseline'],
          ['Required objects', policy.requiredObjects || 'None recorded'],
          ['Replaces baseline policies', policy.replaces || 'None recorded']
        ], [2700, 6660]));
        if (policy.drivers.length) {
          blocks.push(docxPara('Finding drivers', { style: 'Heading3' }));
          policy.drivers.forEach(driver => blocks.push(docxPara(`${String(driver.severity || 'information').toUpperCase()} - ${driver.detail}`, { bullet: true, style: 'ListParagraph' })));
        }
        if (policy.prerequisites.length) {
          blocks.push(docxPara('Prerequisites', { style: 'Heading3' }));
          policy.prerequisites.forEach(item => blocks.push(docxPara(`${item.status.toUpperCase()} - ${item.label}${item.detail ? `: ${item.detail}` : ''}`, { bullet: true, style: 'ListParagraph' })));
        }
        if (policy.settings.length) {
          blocks.push(docxPara('Tenant-specific settings', { style: 'Heading3' }));
          blocks.push(docxReportTable([['Setting', 'Recommended value'], ...policy.settings.map(item => [item.label, item.value])], [2700, 6660]));
        }
        if (policy.mergeReason) blocks.push(docxPara([docxRun('Consolidation note: ', { bold: true }), docxRun(policy.mergeReason)]));
      } else {
        blocks.push(docxReportTable([
          ['Field', 'Observed evidence'],
          ['Policy ID', policy.id || 'Not returned'],
          ['State in this window', policy.stateLabel],
          ['Activity', `${policy.applied.toLocaleString()} applied; ${policy.blocked.toLocaleString()} blocked; ${policy.reportOnly.toLocaleString()} report-only; ${policy.notApplied.toLocaleString()} not applied; ${policy.evaluations.toLocaleString()} evaluated`],
          ['Hit rate', `${policy.hitRate}%`],
          ['Controls recorded', policy.controls || 'None recorded'],
          ['Authentication strength', policy.authenticationStrength || 'None recorded'],
          ['Observed targeting and exclusions', policy.observedScope || 'No satisfied assignment rules were returned'],
          ['MFA identity-exclusion evidence', policy.mfaExclusion ? `${policy.mfaExclusion.identities.length} observed identities across ${policy.mfaExclusion.excludedEventCount.toLocaleString()} policy-event observations; see MFA exclusion risk section` : 'No exercised MFA identity-assignment exclusion was returned for this policy']
        ], [2700, 6660]));
        blocks.push(docxReportTable([
          ['Field', 'Observed evidence'],
          ['Report-only results', policy.reportOnlyResults || 'None recorded'],
          ['Conditions not satisfied', policy.notSatisfied || 'None recorded'],
          ['Top identities', policy.topUsers || 'None recorded'],
          ['Top apps / resources', policy.topApps || 'None recorded'],
          ['Top devices', policy.topDevices || 'None recorded'],
          ['Top locations', policy.topLocations || 'None recorded'],
          ['Sources and window', `${policy.sources || 'Unknown source'}; ${policy.from ? policy.from.slice(0, 10) : 'unknown'} to ${policy.to ? policy.to.slice(0, 10) : 'unknown'}`]
        ], [2700, 6660]));
        if (policy.samples.length) {
          blocks.push(docxPara('Representative events', { style: 'Heading3' }));
          blocks.push(docxReportTable([
            ['UTC time', 'Identity', 'App / resource', 'Result'],
            ...policy.samples.slice(0, 5).map(sample => [sample.time, sample.principal, sample.app, `${sample.result}${sample.representedEvents > 1 ? ` (${sample.representedEvents} events)` : ''}`])
          ], [1800, 2600, 3000, 1960]));
        }
      }
    });
    return blocks;
  }

  function buildPolicyOfficeDocx(report) {
    return buildDocx(buildPolicyOfficeDocxBlocks(report), {
      styles: DOCX_REPORT_STYLES,
      numbering: DOCX_REPORT_NUMBERING,
      section: '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
    });
  }

  const XLSX_STYLES = {
    normal: 0,
    title: 1,
    subtitle: 2,
    header: 3,
    text: 4,
    integer: 5,
    percent: 6,
    date: 7,
    label: 8,
    value: 9,
    section: 10,
    datetime: 11
  };

  function xlsxColumnName(index) {
    let value = index + 1;
    let name = '';
    while (value) {
      value -= 1;
      name = String.fromCharCode(65 + (value % 26)) + name;
      value = Math.floor(value / 26);
    }
    return name;
  }

  function xlsxCell(value, type = 'text', style) {
    return { value, type, style };
  }

  function xlsxDateSerial(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (!Number.isFinite(date.getTime())) return null;
    return date.getTime() / 86400000 + 25569;
  }

  function policyOfficeUtcTimestamp(value) {
    const timestamp = String(value || '').trim().replace(' ', 'T');
    if (!timestamp) return '';
    return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(timestamp) ? timestamp : `${timestamp}Z`;
  }

  function xlsxCellXml(cell, rowIndex, colIndex, header) {
    const ref = `${xlsxColumnName(colIndex)}${rowIndex + 1}`;
    const descriptor = cell && typeof cell === 'object' && Object.prototype.hasOwnProperty.call(cell, 'value')
      ? cell
      : { value: cell, type: typeof cell === 'number' ? 'number' : 'text' };
    const type = descriptor.type || 'text';
    const defaultStyle = header ? XLSX_STYLES.header
      : type === 'integer' || type === 'number' ? XLSX_STYLES.integer
        : type === 'percentage' ? XLSX_STYLES.percent
          : type === 'date' ? XLSX_STYLES.date
            : type === 'datetime' ? XLSX_STYLES.datetime
            : XLSX_STYLES.text;
    const style = descriptor.style === undefined ? defaultStyle : descriptor.style;
    if (descriptor.value === null || descriptor.value === undefined || descriptor.value === '') {
      return `<c r="${ref}" s="${style}"/>`;
    }
    if (type === 'date' || type === 'datetime') {
      const serial = xlsxDateSerial(descriptor.value);
      if (serial !== null) return `<c r="${ref}" s="${style}"><v>${serial}</v></c>`;
    }
    if (['integer', 'number', 'percentage'].includes(type) && Number.isFinite(Number(descriptor.value))) {
      return `<c r="${ref}" s="${style}"><v>${Number(descriptor.value)}</v></c>`;
    }
    return `<c r="${ref}" t="inlineStr" s="${style}"><is><t xml:space="preserve">${xmlEsc(descriptor.value)}</t></is></c>`;
  }

  function xlsxWorksheetXml(sheet) {
    const rowCount = sheet.rows.length;
    const colCount = sheet.rows.reduce((maximum, row) => Math.max(maximum, row.length), 1);
    const lastCell = `${xlsxColumnName(colCount - 1)}${Math.max(rowCount, 1)}`;
    const rows = sheet.rows.map((row, rowIndex) => {
      const header = rowIndex + 1 === sheet.headerRow;
      const height = rowIndex === 0 ? 26 : header ? 30 : undefined;
      return `<row r="${rowIndex + 1}"${height ? ` ht="${height}" customHeight="1"` : ''}>${row.map((cell, colIndex) => xlsxCellXml(cell, rowIndex, colIndex, header)).join('')}</row>`;
    }).join('');
    const columns = (sheet.widths || []).map((width, index) => `<col min="${index + 1}" max="${index + 1}" width="${width}" customWidth="1"/>`).join('');
    const pane = sheet.freezeRows
      ? `<pane ySplit="${sheet.freezeRows}" topLeftCell="A${sheet.freezeRows + 1}" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A${sheet.freezeRows + 1}" sqref="A${sheet.freezeRows + 1}"/>`
      : '<selection activeCell="A1" sqref="A1"/>';
    const merges = (sheet.merges || []).length
      ? `<mergeCells count="${sheet.merges.length}">${sheet.merges.map(ref => `<mergeCell ref="${ref}"/>`).join('')}</mergeCells>`
      : '';
    const filter = sheet.headerRow && rowCount > sheet.headerRow
      ? `<autoFilter ref="A${sheet.headerRow}:${xlsxColumnName(colCount - 1)}${rowCount}"/>`
      : '';
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetPr><pageSetUpPr fitToPage="1"/></sheetPr><dimension ref="A1:${lastCell}"/><sheetViews><sheetView workbookViewId="0">${pane}</sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/>${columns ? `<cols>${columns}</cols>` : ''}<sheetData>${rows}</sheetData>${filter}${merges}<pageMargins left="0.35" right="0.35" top="0.5" bottom="0.5" header="0.2" footer="0.2"/><pageSetup paperSize="1" orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`;
  }

  const XLSX_STYLE_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <numFmts count="3"><numFmt numFmtId="164" formatCode="0.0%"/><numFmt numFmtId="165" formatCode="yyyy-mm-dd"/><numFmt numFmtId="166" formatCode="yyyy-mm-dd hh:mm"/></numFmts>
  <fonts count="5">
    <font><sz val="11"/><name val="Calibri"/><family val="2"/><scheme val="minor"/></font>
    <font><b/><sz val="18"/><color rgb="FF201C18"/><name val="Calibri"/><family val="2"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>
    <font><i/><sz val="10"/><color rgb="FF5F5751"/><name val="Calibri"/><family val="2"/></font>
    <font><b/><sz val="11"/><color rgb="FFC44E00"/><name val="Calibri"/><family val="2"/></font>
  </fonts>
  <fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE8610A"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF292929"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF1E8"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFE1D7CC"/></left><right style="thin"><color rgb="FFE1D7CC"/></right><top style="thin"><color rgb="FFE1D7CC"/></top><bottom style="thin"><color rgb="FFE1D7CC"/></bottom><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="12">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
    <xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"><alignment wrapText="1" vertical="top"/></xf>
    <xf numFmtId="0" fontId="2" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="3" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"><alignment horizontal="right" vertical="center"/></xf>
    <xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"><alignment horizontal="right" vertical="center"/></xf>
    <xf numFmtId="165" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="4" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>
    <xf numFmtId="166" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles><dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>
</styleSheet>`;

  function buildXlsx(sheets) {
    const created = new Date().toISOString();
    const sheetOverrides = sheets.map((sheet, index) => `<Override PartName="/xl/worksheets/sheet${index + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('');
    const workbookSheets = sheets.map((sheet, index) => `<sheet name="${xmlEsc(sheet.name)}" sheetId="${index + 1}" r:id="rId${index + 1}"/>`).join('');
    const workbookRelationships = sheets.map((sheet, index) => `<Relationship Id="rId${index + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${index + 1}.xml"/>`).join('');
    const entries = [
      { name: '[Content_Types].xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${sheetOverrides}<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>` },
      { name: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>' },
      { name: 'docProps/core.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:creator>CA Architect V2</dc:creator><cp:lastModifiedBy>CA Architect V2</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">${created}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${created}</dcterms:modified></cp:coreProperties>` },
      { name: 'docProps/app.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>CA Architect V2</Application><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>${sheets.length}</vt:i4></vt:variant></vt:vector></HeadingPairs><TitlesOfParts><vt:vector size="${sheets.length}" baseType="lpstr">${sheets.map(sheet => `<vt:lpstr>${xmlEsc(sheet.name)}</vt:lpstr>`).join('')}</vt:vector></TitlesOfParts><Company>Security Ninja</Company><LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0300</AppVersion></Properties>` },
      { name: 'xl/workbook.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView xWindow="0" yWindow="0" windowWidth="24000" windowHeight="15000"/></bookViews><sheets>${workbookSheets}</sheets><calcPr calcId="191029" fullCalcOnLoad="1"/></workbook>` },
      { name: 'xl/_rels/workbook.xml.rels', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${workbookRelationships}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>` },
      { name: 'xl/styles.xml', data: XLSX_STYLE_XML }
    ];
    sheets.forEach((sheet, index) => entries.push({ name: `xl/worksheets/sheet${index + 1}.xml`, data: xlsxWorksheetXml(sheet) }));
    return zipStore(entries, XLSX_MIME);
  }

  function policyOfficeSummarySheet(report) {
    const numericMeasures = new Set([
      'Policies', 'Policies recorded', 'Evaluations', 'Sign-ins assessed',
      'Successful access without enforcing CA', 'Confirmed scoping gaps', 'Report-only exposure', 'Evidence unknown'
    ]);
    const rows = [
      [xlsxCell(report.title, 'text', XLSX_STYLES.title), ''],
      [xlsxCell(`Generated locally by CA Architect V2 on ${report.generatedAt.slice(0, 10)}. ${report.caveat}`, 'text', XLSX_STYLES.subtitle), ''],
      ['', ''],
      ['Measure', 'Result'],
      ...policyOfficeSummaryRows(report).map(([label, value]) => {
        const numericValue = Number(String(value).replace(/,/g, ''));
        const result = numericMeasures.has(label) && Number.isFinite(numericValue)
          ? xlsxCell(numericValue, 'integer')
          : xlsxCell(value, 'text', XLSX_STYLES.value);
        return [xlsxCell(label, 'text', XLSX_STYLES.label), result];
      }),
      [xlsxCell('Files analysed', 'text', XLSX_STYLES.label), xlsxCell(report.files || 'Not recorded', 'text', XLSX_STYLES.value)]
    ];
    return { name: 'Summary', rows, widths: [30, 90], headerRow: 4, freezeRows: 4, merges: ['A1:B1', 'A2:B2'] };
  }

  function caCoverageSheet(coverage) {
    const headers = ['Category', 'Evidence confidence', 'Source', 'CA decision', 'Outcome', 'Events', 'Share of successful events', 'Interpretation', 'Recommended action'];
    const rows = coverage.routes
      .sort((a, b) => CA_COVERAGE_CATEGORIES.findIndex(item => item.id === a.category) - CA_COVERAGE_CATEGORIES.findIndex(item => item.id === b.category)
        || b.count - a.count || a.sourceLabel.localeCompare(b.sourceLabel))
      .map(route => [
        CA_COVERAGE_CATEGORIES.find(item => item.id === route.category)?.label || route.category,
        route.confidence,
        route.sourceLabel,
        route.decisionLabel,
        route.outcomeLabel,
        xlsxCell(route.count, 'integer'),
        xlsxCell(route.share, 'percentage'),
        route.interpretation,
        route.action
      ]);
    const retention = coverage.retention;
    const subtitle = `${coverage.reviewTotal.toLocaleString()} successful events require coverage review. Expected outside-CA activity is shown for reconciliation and is never counted as a bypass. ${retention.retainedRows.toLocaleString()} of ${retention.eligibleRows.toLocaleString()} qualifying imported rows are retained${retention.truncated ? `; ${retention.omittedRows.toLocaleString()} rows were omitted by the ${retention.limit.toLocaleString()}-row browser safety limit while summary totals remained complete` : '; the event ledger is complete for this evidence window'}.`;
    return {
      name: 'CA Coverage',
      rows: [
        [xlsxCell('Conditional Access coverage', 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')],
        [xlsxCell(subtitle, 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')],
        headers,
        ...rows
      ],
      widths: [24, 34, 28, 34, 38, 13, 20, 62, 62],
      headerRow: 3,
      freezeRows: 3,
      merges: ['A1:I1', 'A2:I2']
    };
  }

  function caCoverageEventsSheet(coverage) {
    const headers = ['Category', 'Evidence confidence', 'UTC time', 'Source', 'Identity type', 'Identity', 'App / resource', 'Client app', 'Device', 'Platform', 'Location', 'IP address', 'CA status', 'Authentication requirement', 'CA decision', 'Outcome', 'Evaluated policies and results', 'Unsatisfied conditions', 'Represented events', 'Grouped evidence row'];
    const rows = coverage.events.map(event => [
      event.categoryLabel,
      event.confidence,
      event.time ? xlsxCell(policyOfficeUtcTimestamp(event.time), 'datetime') : '',
      event.sourceLabel,
      event.identityType,
      event.principal,
      event.app,
      event.clientApp,
      event.device,
      event.platform,
      event.location,
      event.ip,
      event.caStatus,
      event.authenticationRequirement,
      event.decisionLabel,
      event.outcomeLabel,
      event.policySummary,
      event.unsatisfiedConditions,
      xlsxCell(event.representedEvents, 'integer'),
      event.groupedEvidence ? 'Yes' : 'No'
    ]);
    const retention = coverage.retention;
    const subtitle = `Security-sensitive event evidence: identities, IP addresses and device information are not masked. Retained ${retention.retainedRows.toLocaleString()} of ${retention.eligibleRows.toLocaleString()} qualifying imported rows, representing ${retention.retainedRepresentedEvents.toLocaleString()} of ${retention.representedEvents.toLocaleString()} events.${retention.truncated ? ` The ${retention.limit.toLocaleString()}-row browser safety limit omitted ${retention.omittedRows.toLocaleString()} rows representing ${retention.omittedRepresentedEvents.toLocaleString()} events; summary totals remain complete.` : ' The ledger is complete for the loaded evidence.'}`;
    return {
      name: 'Coverage Events',
      rows: [
        [xlsxCell('Successful access without enforcing CA - event evidence', 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')],
        [xlsxCell(subtitle, 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')],
        headers,
        ...rows
      ],
      widths: [24, 34, 21, 27, 18, 38, 40, 28, 34, 24, 28, 18, 18, 26, 34, 38, 64, 48, 18, 20],
      headerRow: 3,
      freezeRows: 3,
      merges: ['A1:T1', 'A2:T2']
    };
  }

  function recommendedPolicySheets(report) {
    const headers = ['Action tier', 'Policy ID', 'Policy name', 'Evidence basis', 'Capability', 'Coverage', 'Purpose', 'Applicability', 'Primary relationship', 'Secondary relationships', 'Controls', 'Reason labels', 'Affected activity', 'Prerequisites', 'Settings', 'Required objects', 'Replaces baseline policies'];
    const policyRows = report.policies.map(policy => [
      policy.actionTierLabel, policy.id, policy.name, policy.basis, policy.capability, policy.coverage, policy.purpose,
      policy.applicability, policy.primaryRelationship, policy.secondaryRelationships, policy.controls, policy.reasons,
      xlsxCell(policy.affected, 'integer'),
      policyOfficeList(policy.prerequisites, item => `${item.status}: ${item.label}${item.detail ? ` - ${item.detail}` : ''}`),
      policyOfficeList(policy.settings, item => `${item.label}: ${item.value}`), policy.requiredObjects, policy.replaces
    ]);
    const details = [];
    report.policies.forEach(policy => {
      policy.drivers.forEach(driver => details.push([
        policy.id, policy.name, 'Finding driver', driver.severity, driver.title, driver.detail,
        xlsxCell(driver.affected, 'integer'), xlsxCell((Number(driver.pct) || 0) / 100, 'percentage'), driver.scope || ''
      ]));
      policy.prerequisites.forEach(item => details.push([
        policy.id, policy.name, 'Prerequisite', item.status, item.label, item.detail, '', '', ''
      ]));
    });
    return [
      {
        name: 'Policies',
        rows: [[xlsxCell(report.title, 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')], [xlsxCell(report.caveat, 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')], headers, ...policyRows],
        widths: [18, 13, 42, 16, 30, 22, 48, 42, 24, 34, 42, 22, 15, 50, 50, 34, 30],
        headerRow: 3,
        freezeRows: 3,
        merges: [`A1:${xlsxColumnName(headers.length - 1)}1`, `A2:${xlsxColumnName(headers.length - 1)}2`]
      },
      {
        name: 'Drivers & Prerequisites',
        rows: [[xlsxCell('Finding drivers and prerequisites', 'text', XLSX_STYLES.title), '', '', '', '', '', '', '', ''], [xlsxCell('One row per linked finding or prerequisite. Percentage values are stored as real Excel percentages.', 'text', XLSX_STYLES.subtitle), '', '', '', '', '', '', '', ''], ['Policy ID', 'Policy name', 'Record type', 'Status / severity', 'Item', 'Detail', 'Affected', 'Percentage', 'Scope'], ...details],
        widths: [13, 42, 20, 18, 42, 65, 13, 13, 18],
        headerRow: 3,
        freezeRows: 3,
        merges: ['A1:I1', 'A2:I2']
      }
    ];
  }

  function mfaExclusionSheet(exclusions) {
    const headers = ['Review priority', 'Policy ID', 'Policy name', 'State', 'Rule categories', 'Rule observations', 'Evidence limitation', 'Observed identity', 'Object ID', 'Identity type', 'User type', 'Exclusion observations', 'Apps / resources', 'Locations', 'First observed UTC', 'Last observed UTC', 'Sources'];
    const rows = [];
    (exclusions || []).forEach(policy => {
      const rules = policy.rules.map(rule => rule.ruleLabel).join('; ');
      const ruleObservations = policy.rules.map(rule => `${rule.ruleLabel}: ${rule.count}`).join('; ');
      const limitation = [...new Set(policy.rules.map(rule => rule.detail))].join(' ');
      if (!policy.identities.length) {
        rows.push(['High review priority', policy.id, policy.name, policy.stateLabel, rules, ruleObservations, limitation, '', '', '', '', xlsxCell(policy.excludedEventCount, 'integer'), '', '', '', '', '']);
        return;
      }
      policy.identities.forEach(identity => rows.push([
        'High review priority', policy.id, policy.name, policy.stateLabel, rules, ruleObservations, limitation,
        identity.name, identity.objectId, identity.identityType, identity.userType, xlsxCell(identity.count, 'integer'),
        identity.apps.map(item => `${item.name} (${item.count})`).join('; '),
        identity.locations.map(item => `${item.name} (${item.count})`).join('; '),
        identity.from ? xlsxCell(identity.from, 'datetime') : '',
        identity.to ? xlsxCell(identity.to, 'datetime') : '',
        identity.sources.map(key => LOG_SOURCES[key]?.label || key).join('; ')
      ]));
    });
    return {
      name: 'MFA Exclusions',
      rows: [
        [xlsxCell('MFA exclusion risk - observed identities', 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')],
        [xlsxCell('One row per observed identity and MFA policy. Sign-in evidence identifies the affected identity and exclusion rule category; it does not return the configured role or group name/object ID. Event details may contain personal or network information.', 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')],
        headers,
        ...rows
      ],
      widths: [21, 24, 48, 16, 28, 28, 70, 38, 38, 18, 16, 20, 48, 40, 22, 22, 30],
      headerRow: 3,
      freezeRows: 3,
      merges: [`A1:${xlsxColumnName(headers.length - 1)}1`, `A2:${xlsxColumnName(headers.length - 1)}2`]
    };
  }

  function observedPolicySheets(report) {
    const headers = ['State', 'Policy ID', 'Policy name', 'Evaluated', 'Applied', 'Blocked', 'Report-only', 'Not applied', 'Hit rate', 'Controls', 'Authentication strength', 'Observed targeting and exclusions', 'Report-only results', 'Conditions not satisfied', 'Top identities', 'Top apps / resources', 'Top devices', 'Top locations', 'Sources', 'From', 'To'];
    const policyRows = report.policies.map(policy => [
      policy.stateLabel, policy.id, policy.name,
      xlsxCell(policy.evaluations, 'integer'), xlsxCell(policy.applied, 'integer'), xlsxCell(policy.blocked, 'integer'),
      xlsxCell(policy.reportOnly, 'integer'), xlsxCell(policy.notApplied, 'integer'), xlsxCell(policy.hitRate / 100, 'percentage'),
      policy.controls, policy.authenticationStrength, policy.observedScope, policy.reportOnlyResults, policy.notSatisfied,
      policy.topUsers, policy.topApps, policy.topDevices, policy.topLocations, policy.sources,
      policy.from ? xlsxCell(policy.from, 'date') : '', policy.to ? xlsxCell(policy.to, 'date') : ''
    ]);
    const samples = [];
    report.policies.forEach(policy => policy.samples.forEach(sample => samples.push([
      policy.name, policy.stateLabel,
      sample.time ? xlsxCell(policyOfficeUtcTimestamp(sample.time), 'datetime') : '', sample.source || '', sample.principal || '',
      sample.app || '', sample.device || '', sample.deviceDetail || '', sample.posture || '', sample.location || '', sample.ip || '',
      sample.clientApp || '', sample.result || '', xlsxCell(Number(sample.representedEvents) || 0, 'integer'),
      policyOfficeList(sample.grants), policyOfficeList(sample.sessions)
    ])));
    return [
      {
        name: 'Policies',
        rows: [[xlsxCell(report.title, 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')], [xlsxCell(report.caveat, 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')], headers, ...policyRows],
        widths: [16, 24, 48, 13, 13, 13, 13, 13, 13, 42, 30, 58, 42, 38, 42, 42, 38, 38, 28, 14, 14],
        headerRow: 3,
        freezeRows: 3,
        merges: [`A1:${xlsxColumnName(headers.length - 1)}1`, `A2:${xlsxColumnName(headers.length - 1)}2`]
      },
      {
        ...mfaExclusionSheet(report.mfaExclusions)
      },
      {
        name: 'Evidence Samples',
        rows: [[xlsxCell('Representative observed-policy evidence', 'text', XLSX_STYLES.title), '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''], [xlsxCell('Samples are bounded during local analysis and may contain identities, IP addresses and device information from the uploaded sign-in logs.', 'text', XLSX_STYLES.subtitle), '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''], ['Policy name', 'State', 'UTC time', 'Source', 'Identity', 'App / resource', 'Device', 'Device detail', 'Posture', 'Location', 'IP address', 'Client app', 'Result', 'Represented events', 'Grants', 'Sessions'], ...samples],
        widths: [48, 16, 20, 18, 38, 38, 32, 42, 26, 28, 18, 24, 22, 18, 36, 36],
        headerRow: 3,
        freezeRows: 3,
        merges: ['A1:P1', 'A2:P2']
      }
    ];
  }

  function buildPolicyOfficeXlsx(report) {
    const detailSheets = report.kind === 'recommended' ? recommendedPolicySheets(report) : observedPolicySheets(report);
    if (report.kind === 'recommended') return buildXlsx([policyOfficeSummarySheet(report), ...detailSheets]);
    return buildXlsx([
      policyOfficeSummarySheet(report),
      caCoverageSheet(report.coverage),
      caCoverageEventsSheet(report.coverage),
      ...detailSheets
    ]);
  }

  function downloadPolicyOfficeReport(kind, format) {
    const report = buildPolicyOfficeReport(kind);
    if (!report.policies.length) {
      toast(`No ${kind} policies are available to download`);
      return;
    }
    try {
      const blob = format === 'xlsx' ? buildPolicyOfficeXlsx(report) : buildPolicyOfficeDocx(report);
      const stamp = new Date().toISOString().slice(0, 10);
      downloadBlob(blob, `ca-architect-${kind}-policies-${stamp}.${format}`);
      toast(`${kind === 'recommended' ? 'Recommended' : 'Observed'} policies exported to ${format === 'xlsx' ? 'Excel' : 'Word'}`);
    } catch (err) {
      toast(`Could not build the ${kind} policy ${format.toUpperCase()} report: ${err.message}`);
    }
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

  // The legacy/basic-auth clients Microsoft lists under the Conditional Access "Other clients"
  // and "Exchange ActiveSync clients" conditions.
  const LEGACY_CLIENT_APPS = new Set([
    'exchangeactivesync', 'imap', 'imap4', 'pop', 'pop3', 'smtp', 'authenticatedsmtp',
    'mapi', 'mapioverhttp', 'otherclients', 'exchangewebservices', 'autodiscover', 'offlineaddressbook',
    'exchangeonlinepowershell', 'outlookanywhere', 'outlookanywhererpcoverhttp', 'outlookservice',
    'reportingwebservices'
  ]);
  const WEAK_MFA_METHODS = ['text message', 'sms', 'voice', 'phone call'];
  const LOG_SAMPLE_CAP = 25;
  const LOG_EXCLUSION_DISPLAY_CAP = 50;
  const LOG_EXCLUSION_DOCX_CAP = 25;
  const LOG_COVERAGE_EVENT_ROW_CAP = 50000;
  const LOG_LARGE_ANALYSIS_THRESHOLD = 25000;
  const LOG_TOP_CAP = 5;
  const LOG_TRAVEL_WINDOW_MS = 60 * 60 * 1000;
  const LOG_SOURCES = {
    interactive: { key: 'interactive', label: 'Interactive user sign-ins', short: 'Interactive', scope: 'interactive sign-ins', kind: 'user' },
    nonInteractive: { key: 'nonInteractive', label: 'Non-interactive sign-ins', short: 'Non-interactive', scope: 'non-interactive sign-ins', kind: 'user' },
    application: { key: 'application', label: 'Service principal sign-ins', short: 'Service principal', scope: 'service principal sign-ins', kind: 'workload' }
  };
  const LOG_SOURCE_ORDER = ['interactive', 'nonInteractive', 'application'];
  const LOG_USER_SOURCES = ['interactive', 'nonInteractive'];
  // Order matters: NonInteractiveSignIns_*.json contains the substring "InteractiveSignIns",
  // so the non-interactive pattern must be tested first or every file matches interactive.
  const LOG_SOURCE_FILENAME_HINTS = [
    { re: /noninteractive/i, source: 'nonInteractive' },
    { re: /managedidentit|msisignin|(^|[^a-z])msi([^a-z]|$)/i, source: 'msi' },
    { re: /applicationsignin|serviceprincipal/i, source: 'application' },
    { re: /interactive|usersignin/i, source: 'interactive' }
  ];
  const LOG_MAX_FILES = 8;
  const LOG_MAX_FILE_BYTES = 100 * 1024 * 1024;
  const LOG_MAX_RECORDS_PER_FILE = 500000;
  const LOG_DETECT_SAMPLE = 200;
  const LOG_SP_COUNTRY_THRESHOLD = 3;
  const LOG_COVERAGE_CAP = 20000;
  // Conditions the coverage evaluator cannot decide from sign-in logs. Any policy carrying
  // one is reported as conditional rather than counted as a match.
  const LOG_UNEVALUATED_CONDITIONS = ['clientApplications', 'agents', 'agentContext', 'agentIdRiskLevels', 'servicePrincipalRiskLevels', 'insiderRiskLevels', 'authenticationContextClassReferences'];
  // Only 7000222 and 700024 are genuine expiry. The rest are different faults and must not
  // be narrated as "a secret at or past expiry".
  const LOG_SP_CREDENTIAL_ERRORS = new Map([
    [7000215, { text: 'invalid client secret', kind: 'invalid' }],
    [7000222, { text: 'expired client secret', kind: 'expiry' }],
    [700027, { text: 'invalid client assertion or certificate', kind: 'invalid' }],
    [700024, { text: 'client assertion expired', kind: 'expiry' }],
    [7000112, { text: 'the application is disabled in the tenant', kind: 'config' }],
    [50146, { text: 'missing signing key configuration on the application', kind: 'config' }]
  ]);
  const spCredentialErrorText = code => (LOG_SP_CREDENTIAL_ERRORS.get(code) || {}).text || 'credential error';
  const spCredentialErrorKind = code => (LOG_SP_CREDENTIAL_ERRORS.get(code) || {}).kind || 'invalid';
  const LOG_CHECK_SOURCES = {
    'legacy-auth': LOG_USER_SOURCES,
    'single-factor-success': ['interactive'],
    'ca-not-applied': LOG_USER_SOURCES,
    'weak-mfa': ['interactive'],
    'noncompliant-device': ['interactive'],
    'risky-signin-success': LOG_USER_SOURCES,
    'guest-uncontrolled': LOG_USER_SOURCES,
    'outbound-b2b': LOG_USER_SOURCES,
    'outdated-os': ['interactive'],
    'report-only': ['interactive', 'nonInteractive', 'application'],
    'password-spray': LOG_USER_SOURCES,
    'impossible-travel': LOG_USER_SOURCES,
    'uncovered-apps': ['interactive'],
    'possible-exclusions': ['interactive'],
    'geo-spread': LOG_USER_SOURCES,
    'sp-ca-review': ['application'],
    'sp-report-only': ['application'],
    'sp-location-spread': ['application'],
    'sp-credential-hygiene': ['application']
  };

  // Per-finding remediation content. `flow` renders the sign-in path so the break is visible:
  // state 'ok' = working as intended, 'gap' = where protection is absent, 'result' = the outcome.
  const LOG_REMEDIATION = {
    'legacy-auth': {
      cause: 'Legacy protocols such as IMAP, POP, SMTP AUTH, MAPI and Exchange ActiveSync use basic authentication — the username and password are sent on every request. These protocols predate modern authentication and have no mechanism to present an MFA challenge or report device state, so Conditional Access grant controls simply cannot be enforced on them. Any account reachable this way is password-only in practice, no matter what MFA policies you have configured.',
      attack: 'Attackers target these endpoints precisely because MFA cannot fire. A single valid password gives full mailbox access — which means inbox forwarding rules, business email compromise, and a trusted internal address to phish the rest of your organisation from.',
      flow: [
        { label: 'Client connects over IMAP / POP / SMTP', state: 'ok' },
        { label: 'Basic auth — password only', state: 'gap' },
        { label: 'MFA cannot be challenged', state: 'gap' },
        { label: 'Mailbox access granted', state: 'result' }
      ],
      fix: [
        'Identify what is still using legacy auth from the top users and apps above. In practice this is almost always multifunction printers and scanners, old mail clients, monitoring scripts, or a line-of-business app with a hardcoded mailbox.',
        'Migrate each one to modern authentication (OAuth 2.0). For devices that can only send mail, the goal is authenticated SMTP submission using OAuth rather than basic auth — or a dedicated high-volume email service — scoped to a single mailbox rather than leaving basic auth enabled tenant-wide.',
        'Disable the protocols at source in Exchange Online as well as blocking them in Conditional Access — an authentication policy or per-mailbox Set-CASMailbox removes the attack surface entirely, whereas CA only blocks the sign-in attempt.',
        'Deploy the block policy in report-only first, confirm in the sign-in logs that nothing legitimate is caught, then switch it to On.'
      ],
      verify: 'Re-export your sign-in logs a week after enabling the block and re-run this analysis. Blocked attempts still appear in the logs, so what you want to see is legacy client entries showing as failures rather than successes — any remaining success is a system that has not been migrated.'
    },
    'single-factor-success': {
      cause: 'These sign-ins completed with an authentication requirement of single factor. Usually that means no Conditional Access policy requiring MFA applied to that combination of user and resource — either no policy targets them, the user sits in an exclusion group, or the policy is still in report-only mode and enforcing nothing. One documented caveat before treating every one as a gap: Entra also reports single factor when the MFA requirement was already satisfied by a claim in an earlier sign-in, so the resource provider did not ask for it again. Check a sample against the Conditional Access tab of the sign-in log rather than assuming all of them were unchallenged.',
      attack: 'A password is the one credential that can be phished, guessed, reused from a breach dump, or bought. Without a second factor, every one of these sign-ins is a single stolen string away from full account takeover — and the log shows the attacker would not have been challenged.',
      flow: [
        { label: 'User signs in with password', state: 'ok' },
        { label: 'No policy requires a second factor', state: 'gap' },
        { label: 'Session issued on password alone', state: 'gap' },
        { label: 'Full access granted', state: 'result' }
      ],
      fix: [
        'Check whether a policy already targets these users but is excluded or report-only — that is the most common cause and the fastest fix. Compare the accounts above against your policy exclusion groups.',
        'Deploy an all-user MFA baseline targeting All cloud apps rather than named apps, so new applications are covered automatically as they appear.',
        'Exclude only your documented break-glass accounts, and make sure those are monitored separately with alerting on any sign-in.',
        'Run it in report-only for a week, review the impact in the sign-in logs, then enable it.'
      ],
      verify: 'Re-run this analysis after enabling. Successful single-factor sign-ins should fall to zero apart from break-glass accounts.'
    },
    'ca-not-applied': {
      cause: 'A status of notApplied means the sign-in completed with no Conditional Access control on it. It has two quite different causes, and the breakdown below shows which applies to each of yours. Either Conditional Access was never engaged for that sign-in — Entra returns an empty policy list, which is normal for Windows primary refresh token issuance, device registration and broker flows that Conditional Access does not evaluate by design. Or policies were evaluated and every one was filtered out by a condition, in which case Entra records exactly which condition did it: users (the account was not in the assignment), application (the app was not in target resources), clientType, platform, location, or a risk level that was not met. The first cause cannot be fixed with policy. The second is a genuine scoping gap and is fixed by widening the assignment on the specific policy named below.',
      attack: 'These sign-ins are completely ungoverned — no MFA requirement, no device compliance check, no session limit. An attacker who finds one of these paths bypasses your entire Conditional Access design without having to defeat any of it.',
      flow: [
        { label: 'Sign-in evaluated by Conditional Access', state: 'ok' },
        { label: 'No policy assignment matches this user or app', state: 'gap' },
        { label: 'No controls applied at all', state: 'gap' },
        { label: 'Access granted ungoverned', state: 'result' }
      ],
      fix: [
        'Start with the split above. Sign-ins where no policy was evaluated at all, and which are Windows or token plumbing, need no action — discount them so they stop masking the real gaps.',
        'For sign-ins where policies ran but were filtered out, go to the specific policy named above and widen the condition that excluded them. If the blocking condition was "users", the account is missing from the assignment or sits in an exclusion group. If it was "application", the app is not in target resources.',
        'Target your baseline policies at All cloud apps and All users rather than named apps and specific groups. Named-app targeting is the biggest source of this gap because it silently fails to cover anything added later.',
        'For sign-ins where nothing was evaluated and it is not a platform flow, there is no policy to re-scope — you need to create coverage. An all-users, all-apps MFA baseline is what closes that.',
        'Keep only break-glass accounts excluded, and document why every other exclusion exists.'
      ],
      verify: 'After changing assignments, re-run this analysis. The notApplied count should drop to near zero; the remainder should be explainable break-glass or service activity.'
    },
    'weak-mfa': {
      cause: 'These sign-ins satisfied MFA using SMS codes or voice calls. Both are shared-secret methods delivered over the telephone network, which was never designed as a security channel. They satisfy the "MFA was used" requirement while providing materially weaker assurance than phishing-resistant methods.',
      attack: 'SIM swap, SS7 interception and real-time phishing proxies (Evilginx, EvilProxy and similar) all defeat SMS and voice. The attacker relays the code as the user types it and captures the resulting session token — the user sees a normal login and you see a successful MFA sign-in in the logs.',
      flow: [
        { label: 'User signs in', state: 'ok' },
        { label: 'MFA challenge issued', state: 'ok' },
        { label: 'Code sent by SMS or voice — interceptable and relayable', state: 'gap' },
        { label: 'Session token issued', state: 'result' }
      ],
      fix: [
        'Register phishing-resistant methods for the accounts above — FIDO2 security keys, Windows Hello for Business, or certificate-based authentication. These cryptographically bind the sign-in to the legitimate domain, so a proxy cannot relay them.',
        'Start with privileged accounts and anyone handling payments or sensitive data — these are the accounts real attacks target first.',
        'Use an Authentication Strength policy in Conditional Access to require phishing-resistant MFA for those roles, rather than accepting any MFA method.',
        'Disable SMS and voice as available methods in the Authentication Methods policy once registration is complete, so users cannot fall back to them.'
      ],
      verify: 'Re-run this analysis after migrating. The SMS/voice method count should fall to zero for the accounts you have covered.'
    },
    'noncompliant-device': {
      cause: 'These sign-ins came from devices whose security posture Entra could not vouch for, and no policy required otherwise. The split above matters because the three states have different causes. A sign-in with no device identity at all is usually a browser session on a machine that was never joined or registered — Entra has nothing to evaluate, so it reports not compliant by default rather than because anything failed. A registered device has an identity but no Intune enrolment, so no compliance policy ever runs against it. An enrolled device that is failing compliance is the only one where a policy actually evaluated and returned a fail, and that is a device to remediate rather than enrol.',
      attack: 'You have no visibility into the security posture of these devices — patch level, disk encryption, EDR presence, or whether the machine is already compromised. Corporate data downloaded onto them is outside your control entirely, and a keylogger on an unmanaged machine harvests credentials and session cookies regardless of how strong your MFA is.',
      flow: [
        { label: 'Sign-in from unmanaged device', state: 'ok' },
        { label: 'No device compliance requirement', state: 'gap' },
        { label: 'Device posture never evaluated', state: 'gap' },
        { label: 'Corporate data accessible and downloadable', state: 'result' }
      ],
      fix: [
        'Handle each state differently. Devices with no identity need joining or registering before any device control can work on them. Registered-but-unenrolled devices need Intune enrolment so a compliance policy runs. Enrolled devices failing compliance need the specific failing rule fixed — check the device in Intune to see which one.',
        'Look at the top users and devices above for concentration. A single user producing most of the volume usually means one unenrolled machine, or a browser that is not passing device identity, rather than a fleet-wide problem.',
        'Decide the access model per persona before writing policy: corporate devices get full access, personal devices get either app-protection-only access or browser-only access with no download.',
        'Require a compliant device for high-value applications first rather than everything at once, so you avoid a mass lockout on day one. Use "Require device to be marked as compliant" — not "Require hybrid joined device" unless your estate really is domain-joined, since that will block cloud-only Entra joined machines.',
        'For personal devices where blocking is impractical, apply app protection policies so corporate data is contained in managed apps and can be wiped independently.'
      ],
      verify: 'Re-run this analysis after enrolment. Non-compliant device sign-ins should drop as devices enrol; the remainder should map to your deliberate personal-device path.'
    },
    'risky-signin-success': {
      cause: 'Entra ID Identity Protection flagged these sign-ins as medium or high risk — anonymous IP, unfamiliar sign-in properties, malware-linked address, leaked credentials or similar — and they still completed successfully. The risk signal was generated but no policy acted on it.',
      attack: 'Identity Protection told you these sign-ins looked like an account takeover in progress, and nothing intervened. Risk detection without a risk-based policy is monitoring, not protection.',
      flow: [
        { label: 'Sign-in scored medium or high risk', state: 'ok' },
        { label: 'No risk-based policy configured', state: 'gap' },
        { label: 'No challenge or block triggered', state: 'gap' },
        { label: 'Risky sign-in succeeded', state: 'result' }
      ],
      fix: [
        'Investigate the specific sign-ins above first — these are potential live compromises, not just a configuration gap. Check Identity Protection for the detection type behind each one.',
        'Configure a sign-in risk policy: medium risk requires MFA, high risk blocks. This challenges the session in real time rather than after the fact.',
        'Configure a user risk policy requiring a secure password change, so a leaked-credential detection forces a reset rather than sitting in a report.',
        'Deploy both in report-only first and check the volume — tuning matters here, because an over-aggressive block on high risk can lock out travelling users.'
      ],
      verify: 'Risk-based policies require Entra ID P2. After enabling, re-run this analysis — risky sign-ins should show as blocked or MFA-challenged rather than plain successes.'
    },
    'guest-uncontrolled': {
      cause: 'Guest and external identities authenticate against their home tenant, not yours, so you do not control their password policy, their MFA registration, or whether their account has already been compromised. These guest sign-ins had no Conditional Access applied, or completed with a single factor — meaning your tenant accepted whatever assurance the other organisation happened to provide, which may be none.',
      attack: 'Guest accounts are a well-worn lateral path: compromise a small supplier with weak security, then use their legitimate guest access to reach your Teams channels, SharePoint sites and shared files. The sign-in looks entirely normal because the account is genuine — it is the other tenant that was breached.',
      flow: [
        { label: 'Guest authenticates at their home tenant', state: 'ok' },
        { label: 'Home tenant assurance unknown — may be password-only', state: 'gap' },
        { label: 'No guest policy applied in your tenant', state: 'gap' },
        { label: 'Access to Teams and SharePoint granted', state: 'result' }
      ],
      fix: [
        'Require MFA for guests in your own tenant rather than trusting the home tenant. Either target guest user types directly in Conditional Access, or configure Cross-Tenant Access Settings to trust MFA claims only from partners you have explicitly vetted.',
        'Restrict which applications guests can reach. Guests rarely need All cloud apps — scope them to the specific Teams, SharePoint and app surfaces they collaborate on and block the rest.',
        'Add a sign-in frequency limit and disable persistent browser sessions for guests, so a stolen session token expires quickly rather than lasting weeks.',
        'Run an access review over guest accounts. Guests accumulate silently and most tenants have a long tail of external accounts that should have been removed when a project ended.'
      ],
      verify: 'Re-run this analysis after applying the guest policies. Guest sign-ins should show Conditional Access as applied with multi-factor satisfied.'
    },
    'outbound-b2b': {
      caFixes: false,
      cause: 'These sign-ins are your own members authenticating into another organisation\'s tenant as guests. Entra records userType relative to the RESOURCE tenant, so one of your business accounts visiting a partner is logged as "guest" — it is not a guest account in your directory. The tenant ids make the direction unambiguous: the home tenant is yours, the resource tenant is theirs.',
      attack: 'There is no attack path in your tenant here. The risk is one of data flow rather than access control: your users are authenticating into organisations you may not have reviewed, and anything they upload or share there leaves your governance.',
      flow: [
        { label: 'Your member signs in with their own account', state: 'ok' },
        { label: 'Resource belongs to another tenant', state: 'ok' },
        { label: 'The other tenant\'s Conditional Access governs access, not yours', state: 'result' }
      ],
      fix: [
        'Confirm the external tenants your users are reaching are organisations you intend them to collaborate with — the tenant ids are listed above.',
        'Control this with Cross-Tenant Access Settings → Outbound access, which decides which external tenants, users and applications your people may reach. Conditional Access in your tenant cannot do it.',
        'If you need assurance about how the other organisation protects the session, that is a question for their tenant configuration and your partner agreement, not your policy set.'
      ],
      verify: 'This is informational. Success is that every external tenant listed is one you recognise and intend, and that outbound access settings match that list.'
    },
    'report-only': {
      cause: 'These policies are in report-only mode. Entra evaluates them and records what they would have done, but the report-only policy itself applies no control. Report-only is the correct way to test a policy before enforcement; another enabled policy may still protect the same sign-in.',
      attack: 'There is no attack path here specifically. The risk is treating a report-only evaluation as runtime protection without checking whether an enabled policy actually acted on the same route.',
      flow: [
        { label: 'Policy evaluated against the sign-in', state: 'ok' },
        { label: 'Report-only — result logged, not enforced', state: 'gap' },
        { label: 'No control applied', state: 'gap' },
        { label: 'Sign-in proceeds as if the policy did not exist', state: 'result' }
      ],
      fix: [
        'Review Success, Failure, User action required and Not applied separately for each policy in the sign-in logs. Also confirm whether another enabled policy protected the same event.',
        'Where the impact is acceptable, validate with pilot users and stage the policy to On. Retire it only when its intended control is no longer required or is demonstrably covered elsewhere.',
        'Where the impact is not acceptable, fix the exclusions or scope, retest with pilot users and stage enablement rather than leaving the policy indefinitely in report-only.'
      ],
      verify: 'After enabling, confirm in the sign-in logs that the policy now reports success or failure rather than a reportOnly result.'
    },
    'password-spray': {
      cause: 'One or more IP addresses generated invalid-password failures (error 50126) against many different accounts. That pattern is password spraying: rather than guessing many passwords against one account, which triggers lockout, the attacker tries one or two common passwords across your whole user list, staying under the lockout threshold on every account.',
      attack: 'Spraying only needs to succeed once. In a tenant of any size, someone is using a seasonal or predictable password. The attacker gets a valid credential — and if MFA is missing or weak on that account, that is straight through to a working session.',
      flow: [
        { label: 'Attacker enumerates usernames', state: 'ok' },
        { label: 'Common passwords tried once per account', state: 'gap' },
        { label: 'Stays below lockout threshold — no alert', state: 'gap' },
        { label: 'One valid password found', state: 'result' }
      ],
      fix: [
        'Confirm none of the sprayed accounts actually succeeded — filter the sign-in logs by those usernames and look for any success from the same address range. Treat a success as an incident, not a finding.',
        'Enforce MFA everywhere. A valid password from a spray is worthless without the second factor, which is why this finding maps to the MFA baselines.',
        'Block legacy authentication — spray campaigns overwhelmingly target legacy endpoints because MFA cannot fire there.',
        'Enable Entra Password Protection with a custom banned-password list including your company name, local sports teams and seasonal variants, so the passwords being sprayed cannot be set in the first place.',
        'Enable sign-in risk policies so the anomalous source is challenged automatically.'
      ],
      verify: 'Spray traffic will not stop — it is background internet noise. Success is that it stops mattering: MFA enforced, legacy auth blocked, and no successful sign-ins from those addresses.'
    },
    'impossible-travel': {
      cause: 'The same account signed in from two different countries closer together in time than the journey between them would physically allow. That usually means either the credentials are being used by two different people, or one of the sessions is behind a VPN, proxy or corporate egress point in another country.',
      attack: 'If it is not a VPN, it is a shared or stolen credential in active use. The attacker is signing in alongside the legitimate user, which is why the account shows activity from both places.',
      flow: [
        { label: 'Sign-in from country A', state: 'ok' },
        { label: 'Sign-in from country B minutes later', state: 'gap' },
        { label: 'No location or risk policy intervenes', state: 'gap' },
        { label: 'Both sessions remain valid', state: 'result' }
      ],
      fix: [
        'Investigate the accounts above before changing any policy — rule out corporate VPN egress and legitimate travel first, since those are the common benign explanations.',
        'If it is not explainable, treat it as a compromise: revoke sessions, reset the credential and check for new MFA methods, mailbox forwarding rules and OAuth app grants added by the attacker.',
        'Enable sign-in risk policies — impossible travel is exactly the signal Identity Protection is built to catch and challenge in real time.',
        'Define named locations for your offices and known egress points, so genuine corporate traffic stops generating noise and real anomalies stand out.'
      ],
      verify: 'After enabling risk policies, these events should appear as challenged or blocked rather than as successful pairs.'
    },
    'outdated-os': {
      cause: 'These sign-ins came from operating systems that no longer receive security updates. Conditional Access can see the platform but is not currently requiring a minimum version, so an unpatched machine gets the same access as a fully current one. How Windows is judged here matters: Entra reports the operating system as "Windows10" for both Windows 10 and Windows 11, because Windows 11 still identifies itself as NT 10.0 in the user agent. That string is therefore ignored entirely. Instead the build number is read from the user agent (the OS/10.0.<build> token) — build 22000 and above is Windows 11, below that is Windows 10. Sign-ins with no build number are reported as undetermined rather than guessed at.',
      attack: 'End-of-life operating systems accumulate unpatched vulnerabilities permanently — there is no fix coming. Malware on such a device harvests session tokens and credentials directly from memory, which defeats MFA entirely because the attacker inherits an already-authenticated session.',
      flow: [
        { label: 'Sign-in from unsupported OS version', state: 'ok' },
        { label: 'No minimum OS requirement enforced', state: 'gap' },
        { label: 'Known unpatched vulnerabilities present', state: 'gap' },
        { label: 'Access granted from a vulnerable endpoint', state: 'result' }
      ],
      fix: [
        'Identify whether these are managed devices pending an upgrade or unmanaged personal machines — the remediation is completely different for each.',
        'For Windows 10 specifically, do not rely on sign-in logs at all. Use the Intune device inventory or an Entra device report to check the real OS build number, since that is the only place Windows 10 and Windows 11 can be told apart.',
        'Set a minimum OS version in your Intune compliance policy, then require a compliant device in Conditional Access. The compliance policy sees the true build number and does the version enforcement; Conditional Access does the gating. This is the usual route.',
        'Alternatively, enforce it in Conditional Access directly with a device filter. Filters read the device object rather than the user agent, so device.operatingSystemVersion holds the real build — a rule such as device.operatingSystemVersion -startsWith "10.0.2" is evaluated against trustworthy data. Both routes only work for registered or joined devices, since an unregistered machine has no device object to read.',
        'Block unknown and unsupported platforms explicitly, so a device that reports no recognisable platform cannot slip through the gap between rules.',
        'Give users a grace period and a clear upgrade path before enforcing, or you will lock out people who cannot self-remediate.'
      ],
      verify: 'Re-run this analysis after the compliance policy is enforced. Outdated OS sign-ins should decline as devices upgrade or fall out of compliance and get blocked.'
    },
    'uncovered-apps': {
      cause: 'These resources had successful interactive sign-ins with no Conditional Access policy ever applying to them. Conditional Access targets resources rather than client applications — a policy set on Exchange applies to Outlook calling it — so this finding is keyed on the resource that was reached, with the client apps that reached it shown as context. The usual cause is policies scoped to selected resources: the policy protects what you listed when you wrote it and silently fails to cover anything added since. Bootstrap flows that Conditional Access never evaluates — the Windows sign-in process, device registration and the authentication broker — are excluded here, because no policy could ever cover them.',
      attack: 'An attacker does not need to attack your protected resources. They reach the same underlying data through one of these instead, with no MFA requirement and no device check in front of it.',
      flow: [
        { label: 'User signs in, client app requests the resource', state: 'ok' },
        { label: 'Resource not listed in any policy assignment', state: 'gap' },
        { label: 'No controls evaluated', state: 'gap' },
        { label: 'Access granted with no conditions', state: 'result' }
      ],
      fix: [
        "Switch your baseline policies from selected resources to All resources (formerly 'All cloud apps'). This is the single change that prevents the gap from recurring every time a new resource appears.",
        'Where a resource genuinely needs different handling, exclude it explicitly from the baseline and give it its own policy — an explicit exclusion is visible and reviewable, an implicit gap is not.',
        'Review the resources above and confirm each is one your organisation intends people to reach, and that each has a named owner.'
      ],
      verify: 'Re-run this analysis. Every resource with meaningful traffic should show Conditional Access applied. Bootstrap flows will continue to show notApplied and are excluded from this finding by design.'
    },
    'possible-exclusions': {
      cause: 'These accounts have significant sign-in volume but Conditional Access never applied to a single one, while most other traffic in the tenant is covered. That pattern strongly suggests the accounts sit in an exclusion group — often added temporarily to unblock someone and never removed.',
      attack: 'Exclusion groups are a standing bypass of every policy you have. They are also a known target: an attacker who compromises a lower-privileged account and can modify group membership simply adds themselves to the exclusion group and walks past your entire Conditional Access design.',
      flow: [
        { label: 'Account signs in', state: 'ok' },
        { label: 'Account matches a policy exclusion', state: 'gap' },
        { label: 'Every policy skipped for this account', state: 'gap' },
        { label: 'Unconditional access granted', state: 'result' }
      ],
      fix: [
        'Audit the membership of every exclusion group referenced by your policies and confirm each account there has a documented, current reason to be excluded.',
        'Keep only break-glass accounts permanently excluded. Everything else should be time-bound with a review date, not indefinite.',
        'Protect the exclusion groups themselves — restrict who can modify membership and alert on any change, since membership change is the bypass route.',
        'Alert on any sign-in by a break-glass account. These should be used effectively never, so any use is worth immediate investigation.'
      ],
      verify: 'After cleaning up exclusions, re-run this analysis. Only genuine break-glass accounts should still show no Conditional Access applied.'
    },
    'geo-spread': {
      cause: 'Sign-ins arrived from a wide spread of countries. This is informational rather than a fault — it is only a problem if the spread does not match where your people actually work.',
      attack: 'If your workforce is concentrated in a few countries, traffic from elsewhere is either VPN use or someone else using your credentials. Without named locations defined, you have no baseline to distinguish the two.',
      flow: [
        { label: 'Sign-ins arrive from many countries', state: 'ok' },
        { label: 'No named locations defined as a baseline', state: 'gap' },
        { label: 'Normal and anomalous traffic indistinguishable', state: 'result' }
      ],
      fix: [
        'Compare the country list above against where you actually operate, including staff who travel and any offshore suppliers.',
        'Define named locations for your offices and known VPN egress addresses — this gives every other policy a trusted baseline to work from.',
        'Consider blocking countries you never legitimately operate from, as a coarse but effective reduction in attack surface. Test in report-only first — travelling staff are the usual casualty.',
        'Prefer risk-based policies over pure geo-blocking for the general case, since location alone is a weak signal that VPNs trivially defeat.'
      ],
      verify: 'Once named locations exist, sign-ins from trusted locations can be treated differently and anomalies become visible in the logs.'
    },
    'sp-ca-review': {
      caFixes: false,
      cause: 'Workload Conditional Access policies were present in the event, but the recorded assignments or conditions did not match. This is useful scope evidence, but it does not prove the workload is eligible or that an absent match is a security gap.',
      attack: 'An eligible, organisation-owned service principal that falls outside an intended workload policy can retain access without the expected restriction. Microsoft, third-party and multitenant workloads remain outside workload Conditional Access and need different controls.',
      flow: [
        { label: 'Application authenticates with its own credential', state: 'ok' },
        { label: 'Non-interactive — no MFA possible by design', state: 'gap' },
        { label: 'Workload policy evaluated but did not match', state: 'gap' },
        { label: 'API access granted with application permissions', state: 'result' }
      ],
      fix: [
        'Inspect the event’s conditions not satisfied and confirm whether the mismatch was deliberate.',
        'Confirm the service principal is single-tenant and owned by your organisation before considering workload Conditional Access.',
        'Review application permissions and ownership even where the identity is outside Conditional Access eligibility.',
        'If eligible and licensed, pilot a workload identity policy in report-only mode and assign the service principal directly.'
      ],
      verify: 'Re-run the analysis with JSON policy detail. The intended eligible service principals should show an enforcing or validated report-only workload policy; explicitly ineligible workloads should remain labelled outside CA.'
    },
    'sp-report-only': {
      cause: 'A workload Conditional Access policy matched, but it remained report-only. The event therefore proves policy intent and evaluation, not enforcement.',
      attack: 'If no separate enabled workload policy acted, access could continue without the report-only control being enforced.',
      flow: [
        { label: 'Service principal requests a token', state: 'ok' },
        { label: 'Workload policy matches in report-only', state: 'gap' },
        { label: 'Configured control is not enforced', state: 'gap' },
        { label: 'Access continues', state: 'result' }
      ],
      fix: [
        'Review the exact report-only result and confirm whether another enabled policy protected the same event.',
        'Validate workload ownership, eligibility, licensing and exclusions before changing state.',
        'Pilot with representative service principals, monitor impact, then enable in stages.'
      ],
      verify: 'Re-run the analysis after staged enablement and confirm the intended workload policy is recorded enforcing on eligible service principals.'
    },
    'sp-location-spread': {
      caFixes: false,
      cause: 'These workload identities authenticated from an unusually wide range of countries. A service principal normally runs from a predictable place — one cloud region, one datacentre, one office egress. A broad spread suggests either a genuinely distributed SaaS platform, or a credential being used from somewhere it should not be.',
      attack: 'A leaked client secret works from anywhere in the world, and nothing about the sign-in looks unusual to a user-focused policy. Geographic spread is often the only visible signal that a workload credential is being used outside its intended infrastructure.',
      flow: [
        { label: 'Workload identity authenticates', state: 'ok' },
        { label: 'Source countries vary widely', state: 'gap' },
        { label: 'No location condition applies to workload identities', state: 'gap' },
        { label: 'Token issued regardless of origin', state: 'result' }
      ],
      fix: [
        'Check each service principal above against its vendor documentation. A global SaaS backup or security product legitimately egresses from many regions; an internal script does not.',
        'Where the vendor publishes fixed egress ranges, restrict access to them. Some APIs and the application itself may support IP restrictions independently of Conditional Access.',
        'For human-operated service accounts, the trusted-location baseline below blocks sign-ins from outside approved named locations.',
        'Where you cannot restrict by location, compensate by cutting permissions and rotating credentials more frequently.'
      ],
      verify: 'Re-run this analysis after any restriction. The country count per identity should narrow to the expected set.'
    },
    'sp-credential-hygiene': {
      caFixes: false,
      cause: 'These service principals authenticate with client secrets. A client secret is a long-lived password stored in a config file, pipeline variable or vault — it can be copied, committed to a repository or read from a log, and it works from anywhere until it expires. Conditional Access cannot see or enforce credential type; this is app registration governance, not a policy control.',
      attack: 'Leaked client secrets are one of the most reliable routes into a tenant precisely because they carry application permissions and bypass MFA entirely. Secrets are regularly found in public repositories, CI logs and configuration backups, and unlike a user password there is no second factor behind them and often no alerting when one is used.',
      flow: [
        { label: 'Application holds a client secret', state: 'ok' },
        { label: 'Secret is copyable and portable — works from anywhere', state: 'gap' },
        { label: 'No MFA and no device binding possible', state: 'gap' },
        { label: 'Anyone holding the string gets full API access', state: 'result' }
      ],
      fix: [
        'Where the workload runs somewhere OIDC-capable — GitHub Actions, Azure DevOps, Kubernetes, or Azure itself — move to workload identity federation. This removes the stored secret entirely: the platform presents a short-lived signed token instead, so there is nothing left to leak.',
        'Where federation is not possible, use a certificate credential rather than a secret. The private key can be held in a hardware module or key vault and is far harder to exfiltrate than a string in a config file.',
        'For third-party SaaS integrations that only support secrets, rotate them on a defined schedule and store them in a secrets manager rather than in application configuration.',
        'Apply an application management policy to cap secret lifetime tenant-wide, so nobody can create a credential that never expires.',
        'Credential errors such as 7000222 indicate secrets at or past expiry — these are an availability incident waiting to happen as well as a hygiene problem.'
      ],
      verify: 'Re-run this analysis after migrating. Identities using federation or certificates will no longer appear in this finding.'
    }
  };
  // Windows 11 starts at build 22000. Entra's deviceDetail.operatingSystem says "Windows10"
  // for BOTH 10 and 11 (Windows 11 still reports NT 10.0 in the user agent), so it must never
  // be matched on its own. The build number is the only reliable discriminator, and it appears
  // in the userAgent as "OS/10.0.<build>" or in the legacy browser string "Edge 18.<build>".
  // Where no build is present the version is genuinely unknowable and we report nothing.
  const LOG_WINDOWS_11_MIN_BUILD = 22000;
  const LOG_WINDOWS_BUILD_PATTERNS = [
    /\bOS\/10\.0\.(\d{4,6})\b/i,
    /\bEdge?\/18\.(\d{5,6})\b/i
  ];
  const LOG_WINDOWS_10_NAMES = new Map([
    [19045, '22H2'], [19044, '21H2'], [19043, '21H1'], [19042, '20H2'], [19041, '2004'],
    [18363, '1909'], [18362, '1903'], [17763, '1809'], [17134, '1803'], [16299, '1709']
  ]);

  function parseWindowsBuild(row) {
    const haystack = `${row.userAgent || ''} ${(row.deviceDetail || {}).browser || ''}`;
    for (const re of LOG_WINDOWS_BUILD_PATTERNS) {
      const m = haystack.match(re);
      if (m) {
        const build = Number(m[1]);
        if (Number.isFinite(build) && build > 0) return build;
      }
    }
    return null;
  }

  // Returns a resolved Windows version, or null when the log genuinely cannot tell.
  function windowsVersionFromBuild(build) {
    if (!build) return null;
    if (build >= LOG_WINDOWS_11_MIN_BUILD) return { label: `Windows 11 (build ${build})`, eol: false };
    const release = LOG_WINDOWS_10_NAMES.get(build);
    return {
      label: `Windows 10${release ? ` ${release}` : ''} (build ${build})`,
      eol: true,
      reason: 'Windows 10 mainstream support ended in October 2025'
    };
  }

  const LOG_EOL_OS_PATTERNS = [
    { re: /windows\s*7\b/i, label: 'Windows 7' },
    { re: /windows\s*8(\.1)?\b/i, label: 'Windows 8/8.1' },
    { re: /windows\s*vista\b/i, label: 'Windows Vista' },
    { re: /windows\s*xp\b/i, label: 'Windows XP' },
    { re: /\bos\s*x\s*10\.(?:[0-9]|1[0-5])\b/i, label: 'macOS 10.x' },
    { re: /macos\s*1[0-2]\b/i, label: 'macOS 12 or older' },
    { re: /android\s*[1-9](\.[0-9]+)?\b(?![0-9.])/i, label: 'Android 9 or older' },
    { re: /ios\s*(?:1[0-5]|[1-9])(\.[0-9]+)?\b(?![0-9.])/i, label: 'iOS 15 or older' }
  ];
  const LOG_CSV_HEADERS = {
    createdDateTime: ['dateutc', 'date', 'createddatetime'],
    userPrincipalName: ['username', 'userprincipalname'],
    userDisplayName: ['user', 'userdisplayname'],
    userType: ['usertype'],
    appDisplayName: ['application', 'appdisplayname'],
    resourceDisplayName: ['resource', 'resourcedisplayname'],
    ipAddress: ['ipaddress'],
    clientAppUsed: ['clientapp', 'clientappused'],
    conditionalAccessStatus: ['conditionalaccess', 'conditionalaccessstatus'],
    authenticationRequirement: ['authenticationrequirement'],
    mfaResult: ['multifactorauthenticationresult', 'mfaresult'],
    mfaAuthMethod: ['multifactorauthenticationauthmethod', 'mfaauthmethod'],
    operatingSystem: ['operatingsystem'],
    browser: ['browser'],
    isCompliant: ['compliant'],
    isManaged: ['managed'],
    trustType: ['jointype', 'trusttype'],
    deviceName: ['device', 'devicename', 'devicedisplayname'],
    deviceId: ['deviceid'],
    deviceOwnership: ['deviceownership', 'ownership'],
    operatingSystemVersion: ['operatingsystemversion', 'osversion'],
    mdmAppId: ['mdmappid', 'managementappid'],
    enrollmentProfileName: ['enrollmentprofilename', 'enrolmentprofilename'],
    location: ['location'],
    status: ['status'],
    errorCode: ['signinerrorcode', 'errorcode'],
    riskLevelDuringSignIn: ['risklevelduringsignin', 'signinrisk', 'risklevel'],
    riskLevelAggregated: ['risklevelaggregated'],
    riskState: ['riskstate'],
    servicePrincipalId: ['serviceprincipalid'],
    servicePrincipalName: ['serviceprincipalname', 'serviceprincipal'],
    appId: ['applicationid', 'appid'],
    eventCount: ['signins', 'numberofgroupedsignins', 'numberofsignins', 'signincount'],
    clientCredentialType: ['clientcredentialtype'],
    appOwnerTenantId: ['appownertenantid', 'applicationownertenantid'],
    resourceOwnerTenantId: ['resourceownertenantid', 'resourceownertenant'],
    federatedCredentialId: ['federatedcredentialid'],
    servicePrincipalCredentialKeyId: ['serviceprincipalcredentialkeyid', 'credentialkeyid'],
    servicePrincipalCredentialThumbprint: ['serviceprincipalcredentialthumbprint', 'credentialthumbprint']
  };

  const normToken = value => String(value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const representedEventCount = value => {
    const parsed = Number(String(value ?? '').replace(/,/g, '').trim());
    return Number.isFinite(parsed) && Number.isInteger(parsed) && parsed > 0 ? parsed : 1;
  };
  const recordEventCount = record => representedEventCount(record && record.eventCount);

  function logFilenameHint(fileName) {
    const name = String(fileName || '');
    const hit = LOG_SOURCE_FILENAME_HINTS.find(h => h.re.test(name));
    return hit ? hit.source : null;
  }

  // Maps the authoritative Graph signInEventTypes value onto our source keys.
  const LOG_EVENT_TYPE_SOURCES = {
    interactiveuser: 'interactive',
    noninteractiveuser: 'nonInteractive',
    serviceprincipal: 'application',
    managedidentity: 'msi'
  };

  function detectLogSource(rows, fileName) {
    const hint = logFilenameHint(fileName);
    const sample = rows.slice(0, LOG_DETECT_SAMPLE);
    if (!sample.length) return { source: hint || 'unknown', detectedBy: hint ? 'filename' : 'none' };
    // The portal export emits the full sign-in schema for every log type, with the
    // irrelevant fields present but null — so test VALUES, never key presence.
    const eventTypes = new Set();
    let hasUser = false;
    let hasSp = false;
    let interactiveTrue = false;
    let interactiveFalse = false;
    sample.forEach(row => {
      (Array.isArray(row.signInEventTypes) ? row.signInEventTypes : []).forEach(type => {
        const key = LOG_EVENT_TYPE_SOURCES[normToken(type)];
        if (key) eventTypes.add(key);
      });
      if (row.userPrincipalName || row.userId || row.clientAppUsed || row.userType) hasUser = true;
      if (row.servicePrincipalId || row.servicePrincipalName) hasSp = true;
      if (row.isInteractive === true) interactiveTrue = true;
      if (row.isInteractive === false) interactiveFalse = true;
    });
    // signInEventTypes is authoritative when the export carries it.
    if (eventTypes.size === 1) return { source: [...eventTypes][0], detectedBy: 'eventType' };
    if (eventTypes.size > 1) {
      const priority = ['application', 'msi', 'nonInteractive', 'interactive'].find(key => eventTypes.has(key));
      return { source: priority, detectedBy: 'eventType' };
    }
    if (hasSp && !hasUser) return { source: hint === 'msi' ? 'msi' : 'application', detectedBy: hint === 'msi' ? 'filename' : 'shape' };
    if (hasUser) {
      if (interactiveTrue) return { source: 'interactive', detectedBy: 'shape' };
      if (interactiveFalse) return { source: 'nonInteractive', detectedBy: 'shape' };
      return { source: hint || 'interactive', detectedBy: hint ? 'filename' : 'default' };
    }
    if (hasSp) return { source: hint === 'msi' ? 'msi' : 'application', detectedBy: hint === 'msi' ? 'filename' : 'shape' };
    return { source: null, detectedBy: 'none' };
  }

  // Every policy Entra evaluated for a sign-in, with what it actually enforced and — when it
  // did not match — the exact condition that stopped it. This is the raw material for both
  // the notApplied diagnosis and the deployed-policy inventory.
  function normalizeAppliedPolicies(row) {
    return (Array.isArray(row.appliedConditionalAccessPolicies) ? row.appliedConditionalAccessPolicies : [])
      .filter(p => p && p.displayName)
      .map(p => ({
        id: p.id || '',
        displayName: String(p.displayName),
        result: normToken(p.result),
        grants: (Array.isArray(p.enforcedGrantControls) ? p.enforcedGrantControls : []).map(String),
        sessions: (Array.isArray(p.enforcedSessionControls) ? p.enforcedSessionControls : []).map(String),
        authStrength: p.authenticationStrength && p.authenticationStrength.displayName
          ? String(p.authenticationStrength.displayName) : '',
        conditionsNotSatisfied: String(p.conditionsNotSatisfied || '').split(',').map(s => s.trim()).filter(s => s && s !== 'none'),
        // include/excludeRulesSatisfied reveal how the policy is actually scoped — and, when an
        // exclusion fires, that THIS sign-in was excluded. That is the only view of exclusions
        // the logs give, so it is worth keeping.
        includeRules: (Array.isArray(p.includeRulesSatisfied) ? p.includeRulesSatisfied : [])
          .filter(r => r && r.conditionalAccessCondition)
          .map(r => ({ condition: String(r.conditionalAccessCondition), rule: String(r.ruleSatisfied || '') })),
        excludeRules: (Array.isArray(p.excludeRulesSatisfied) ? p.excludeRulesSatisfied : [])
          .filter(r => r && r.conditionalAccessCondition)
          .map(r => ({ condition: String(r.conditionalAccessCondition), rule: String(r.ruleSatisfied || '') }))
      }));
  }

  function spCredentialType(row) {
    // The portal export states this outright in clientCredentialType; trust it first.
    const declared = normToken(row.clientCredentialType);
    if (declared === 'clientsecret') return 'secret';
    if (declared === 'certificate' || declared === 'signedassertion') return 'certificate';
    if (declared === 'federatedidentitycredential') return 'federated';
    if (declared === 'managedidentity') return 'managedIdentity';
    // Fall back to the credential fields. servicePrincipalCredentialKeyId is populated for
    // BOTH secrets and certificates — only the thumbprint distinguishes a certificate,
    // and no fields at all means unknown, never "secret".
    if (row.federatedCredentialId) return 'federated';
    if (row.servicePrincipalCredentialThumbprint) return 'certificate';
    if (row.servicePrincipalCredentialKeyId) return 'secret';
    return 'unknown';
  }

  function emptyLogAnalysis() {
    return {
      files: [],
      failures: [],
      sources: {},
      format: null,
      summary: null,
      findings: [],
      parseWarnings: [],
      filter: 'all',
      sourceFilter: 'all',
      expanded: new Set(),
      policyInventory: null,
      recommendedPolicySet: null,
      declarations: defaultDeclarations(),
      view: 'visual',
      journeySelected: null,
      journeyWorkspaceTab: 'controls',
      journeyPolicyTab: 'recommended',
      observedPoliciesExpanded: false,
      tenantAssumptionsExpanded: false,
      // Kept so a declaration change can re-simulate without re-reading the files.
      agg: null
    };
  }

  function handleLogFiles(fileList) {
    const files = [...(fileList || [])].filter(Boolean);
    if (!files.length) return;
    const batch = files.slice(0, LOG_MAX_FILES);
    const warnings = [];
    if (files.length > batch.length) {
      warnings.push(`Only the first ${LOG_MAX_FILES} files were analysed — ${files.length - batch.length} were skipped.`);
    }
    state.activeTab = 'log-analysis';
    state.logAnalysis = emptyLogAnalysis();
    renderAll();
    showLogStatus(`Preparing ${batch.length} file${batch.length === 1 ? '' : 's'} for analysis…`);
    const agg = createSignInAgg();
    const loaded = [];
    const failures = [];
    const sources = {};
    const formats = new Set();
    batch.reduce((chain, file, index) => chain.then(() => {
      showLogStatus(`Reading ${file.name} (${index + 1} of ${batch.length})…`);
      if (file.size > LOG_MAX_FILE_BYTES) {
        warnings.push(`${file.name} is ${Math.round(file.size / 1048576)} MB — very large files may exhaust browser memory.`);
      }
      return readLogFile(file)
        .then(text => {
          const info = ingestLogFile(agg, text, file, sources, warnings);
          if (!info.ignored) {
            loaded.push(info);
            formats.add(info.format);
          }
        })
        .catch(err => {
          failures.push({ name: file.name, message: err.message || 'Could not read this file.' });
        });
    }), Promise.resolve())
      .then(() => finaliseLogAnalysis(agg, loaded, failures, sources, formats, warnings))
      .catch(err => {
        state.logAnalysis = emptyLogAnalysis();
        renderAll();
        showLogStatus(err.message || 'Could not analyse the sign-in logs.');
        toast('Log analysis failed');
      })
      .then(() => { $('logFileInput').value = ''; });
  }

  function readLogFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error('The file could not be read.'));
      reader.onload = () => {
        try {
          resolve(decodeArrayBuffer(reader.result).replace(/^\uFEFF/, ''));
        } catch (_) {
          reject(new Error('The file could not be decoded.'));
        }
      };
      reader.readAsArrayBuffer(file);
    });
  }

  function ingestLogFile(agg, rawText, file, sources, warnings) {
    const text = rawText.trim();
    if (!text) throw new Error('The file is empty.');
    const isJson = text[0] === '{' || text[0] === '[';
    const parsed = isJson ? parseSignInJson(text, file.name) : normalizeCsvSignIns(parseCsv(text), file.name);
    if (!parsed.source || parsed.source === 'unknown') {
      throw new Error('Could not tell which sign-in log this is. Keep the original file name from the Entra download, or use the JSON export.');
    }
    if (parsed.source === 'msi') {
      warnings.push(`${file.name} is a managed-identity sign-in export and was not analysed. Managed identities are outside Conditional Access; review them through Azure RBAC, access reviews and workload monitoring instead.`);
      return {
        name: file.name,
        size: file.size,
        format: parsed.format,
        source: 'msi',
        importedRowCount: parsed.records.length,
        representedEvents: parsed.records.reduce((sum, record) => sum + recordEventCount(record), 0),
        ignored: true,
        detectedBy: parsed.detectedBy
      };
    }
    if (parsed.records.length > LOG_MAX_RECORDS_PER_FILE) {
      warnings.push(`${file.name} contained ${parsed.records.length} records — only the first ${LOG_MAX_RECORDS_PER_FILE} were analysed.`);
      parsed.records.length = LOG_MAX_RECORDS_PER_FILE;
    }
    const hint = logFilenameHint(file.name);
    if (hint && hint !== parsed.source && parsed.detectedBy === 'shape') {
      warnings.push(`${file.name} is named like a ${LOG_SOURCES[hint].short} export but its contents are ${LOG_SOURCES[parsed.source].short} — treating it as ${LOG_SOURCES[parsed.source].short}.`);
    }
    parsed.warnings.forEach(w => warnings.push(w));
    const representedEvents = parsed.records.reduce((sum, record) => sum + recordEventCount(record), 0);
    const entry = sources[parsed.source] || { fileNames: [], records: 0, importedRowCount: 0, representedEvents: 0, empty: true, format: parsed.format };
    if (entry.fileNames.length) {
      warnings.push(`Two files were detected as ${LOG_SOURCES[parsed.source].label} — records from both were merged.`);
    }
    entry.fileNames.push(file.name);
    entry.records += parsed.records.length;
    entry.importedRowCount += parsed.records.length;
    entry.representedEvents += representedEvents;
    entry.empty = entry.representedEvents === 0;
    entry.format = parsed.format;
    sources[parsed.source] = entry;
    ingestSignIns(agg, parsed.records, parsed.source);
    if (agg.sourceStats[parsed.source]) agg.sourceStats[parsed.source].format = parsed.format;
    // parsed.records goes out of scope here — raw records are never retained in state.
    return {
      name: file.name,
      size: file.size,
      format: parsed.format,
      source: parsed.source,
      records: parsed.records.length,
      importedRowCount: parsed.records.length,
      representedEvents,
      empty: parsed.records.length === 0,
      detectedBy: parsed.detectedBy
    };
  }

  function finaliseLogAnalysis(agg, loaded, failures, sources, formats, warnings) {
    if (!loaded.length) {
      state.logAnalysis = emptyLogAnalysis();
      state.logAnalysis.failures = failures;
      state.logAnalysis.parseWarnings = warnings;
      renderAll();
      showLogStatus(failures.length
        ? failures[0].message
        : warnings.find(message => /managed-identity/i.test(message)) || 'No supported sign-in records found. Add interactive, non-interactive or service-principal logs.');
      toast('Log analysis failed');
      return;
    }
    const totalRecords = loaded.reduce((sum, f) => sum + f.importedRowCount, 0);
    const findings = agg.total ? runLogChecks(agg) : [];
    state.logAnalysis = {
      ...emptyLogAnalysis(),
      files: loaded,
      failures,
      sources: buildSourceStats(agg, sources),
      policyInventory: buildPolicyInventory(agg),
      agg,
      recommendedPolicySet: buildRecommendedPolicySet(agg, findings, defaultDeclarations()),
      format: formats.size === 1 ? [...formats][0] : 'mixed',
      summary: buildLogSummary(agg, findings, sources),
      findings,
      parseWarnings: [
        ...warnings,
        ...failures.map(f => `${f.name} could not be read: ${f.message}`),
        ...degradationWarnings(agg, sources)
      ]
    };
    renderAll();
    if (!agg.total) {
      toast('No sign-in activity in the selected date range');
      return;
    }
    const failedNote = failures.length ? ` — ${failures.length} could not be read` : '';
    toast(`Analysed ${agg.total.toLocaleString()} represented sign-ins from ${totalRecords.toLocaleString()} imported row(s) across ${loaded.length} file(s)${failedNote}`);
  }

  // Friendly names for the grant/session control tokens Entra reports as enforced.
  const LOG_ENFORCED_CONTROLS = {
    mfa: 'Multifactor authentication',
    block: 'Block access',
    compliantdevice: 'Compliant device',
    domainjoineddevice: 'Hybrid joined device',
    approvedapplication: 'Approved client app',
    compliantapplication: 'App protection policy',
    passwordchange: 'Password change',
    requirepasswordchange: 'Password change',
    mfaandchangepassword: 'MFA + password change',
    unknownfuturevalue: 'Unrecognised control',
    signinfrequency: 'Sign-in frequency limit',
    signinfrequencysessionmode: 'Sign-in frequency limit',
    persistentbrowsersessionmode: 'Persistent browser control',
    cloudappsecuritysessionmode: 'Conditional Access App Control',
    applicationenforcedrestrictions: 'App-enforced restrictions'
  };
  // The controls a tenant should normally have something enforcing. Absence is reported as
  // an observation about this date range, never asserted as "the policy does not exist".
  const LOG_EXPECTED_CONTROLS = [
    { key: 'mfa', label: 'Multifactor authentication' },
    { key: 'compliantdevice', label: 'Compliant device' },
    { key: 'block', label: 'Block access (used by legacy-auth and risk blocks)' },
    { key: 'signinfrequency', label: 'Sign-in frequency limit' }
  ];

  const controlLabelFor = token => LOG_ENFORCED_CONTROLS[normToken(token)] || token;

  // Plain-language reading of the include/exclude rules Entra reports as satisfied.
  const LOG_RULE_LABELS = {
    allapps: 'All cloud apps',
    appid: 'Selected applications',
    allusers: 'All users',
    userid: 'Named user(s)',
    groupid: 'Group membership',
    roleid: 'Directory role',
    guestorexternaluser: 'Guest or external users',
    alldeviceplatforms: 'Any device platform',
    deviceplatform: 'Selected device platforms',
    alllocations: 'Any location',
    location: 'Selected named locations',
    allclienttypes: 'Any client app type',
    clienttype: 'Selected client app types',
    acr: 'Authentication context',
    deviceState: 'Device state'
  };
  const LOG_RULE_CONDITIONS = {
    users: 'Assigned to',
    application: 'Target resources',
    clienttype: 'Client apps',
    deviceplatform: 'Device platforms',
    location: 'Locations',
    devicestate: 'Device state',
    acr: 'Authentication context'
  };
  const LOG_EXCLUSION_RULE_NOTES = {
    roleid: 'The sign-in export identifies a directory-role exclusion, but does not return the configured role name, role template ID, or role assignment ID.',
    groupid: 'The sign-in export identifies a group exclusion, but does not return the configured group name or object ID.',
    userid: 'The sign-in export identifies a named-user exclusion. The affected sign-in identity and user object ID are shown where Entra returned them.',
    guestorexternaluser: 'The sign-in export identifies an external-user classification exclusion, not a named directory object.',
    internalguest: 'The sign-in export identifies an internal-guest classification exclusion, not a named directory object.',
    b2bcollaborationguest: 'The sign-in export identifies a B2B collaboration guest exclusion, not a named directory object.',
    b2bcollaborationmember: 'The sign-in export identifies a B2B collaboration member exclusion, not a named directory object.',
    b2bdirectconnectuser: 'The sign-in export identifies a B2B direct-connect exclusion, not a named directory object.',
    otherexternaluser: 'The sign-in export identifies an external-user classification exclusion, not a named directory object.',
    serviceprovider: 'The sign-in export identifies a service-provider classification exclusion, not a named directory object.'
  };

  function observedExclusionRules(inv) {
    const rows = [];
    inv.excludeRules.forEach((count, key) => {
      const [condition, rule] = key.split('|');
      const token = normToken(rule);
      rows.push({
        condition,
        conditionLabel: LOG_RULE_CONDITIONS[normToken(condition)] || condition,
        rule,
        ruleLabel: LOG_RULE_LABELS[token] || rule,
        count,
        identityAssignment: normToken(condition) === 'users',
        reviewPriority: normToken(condition) === 'users' ? 'High review priority' : 'Review',
        detail: LOG_EXCLUSION_RULE_NOTES[token] || 'The sign-in export records the exclusion rule category, not the authoritative stored Conditional Access policy assignment.'
      });
    });
    return rows.sort((a, b) => Number(b.identityAssignment) - Number(a.identityAssignment) || b.count - a.count || a.ruleLabel.localeCompare(b.ruleLabel));
  }

  function observedExclusionIdentities(inv) {
    return [...inv.exclusionIdentityDetails.values()].map(item => ({
      name: item.name,
      objectId: item.objectId,
      identityType: item.identityType,
      userType: item.userType,
      count: item.count,
      rules: [...item.rules.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, label: LOG_RULE_LABELS[normToken(name)] || name, count })),
      apps: [...item.apps.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
      locations: [...item.locations.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
      sources: [...item.sources],
      from: Number.isFinite(item.minTime) ? new Date(item.minTime).toISOString() : null,
      to: Number.isFinite(item.maxTime) ? new Date(item.maxTime).toISOString() : null
    })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  }

  // Reconstructs what a deployed policy targets, from the rules Entra reported as satisfied
  // across its evaluations. This is OBSERVED scope, not the policy definition — the tenant
  // export in the Audit tab remains the authoritative source.
  function observedPolicyConfig(inv) {
    const rows = [];
    const group = map => {
      const byCondition = new Map();
      map.forEach((count, key) => {
        const [condition, rule] = key.split('|');
        const list = byCondition.get(condition) || [];
        list.push({ rule, count });
        byCondition.set(condition, list);
      });
      return byCondition;
    };
    group(inv.includeRules).forEach((rules, condition) => {
      rows.push({
        label: LOG_RULE_CONDITIONS[normToken(condition)] || condition,
        value: rules.sort((a, b) => b.count - a.count)
          .map(r => `${LOG_RULE_LABELS[normToken(r.rule)] || r.rule} (${r.count})`).join(' · ')
      });
    });
    group(inv.excludeRules).forEach((rules, condition) => {
      const who = [...inv.excludedPrincipals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
      rows.push({
        label: `Excludes ${(LOG_RULE_CONDITIONS[normToken(condition)] || condition).toLowerCase()}`,
        value: rules.sort((a, b) => b.count - a.count)
          .map(r => `${LOG_RULE_LABELS[normToken(r.rule)] || r.rule} (${r.count})`).join(' · '),
        note: normToken(condition) === 'users' && who.length
          ? `Identities the exclusion spared: ${who.map(([name, n]) => `${name} (${n})`).join(', ')}`
          : ''
      });
    });
    return rows;
  }

  // Turns the raw per-policy tallies into a sorted inventory of what is actually deployed,
  // how hard each policy works, and where it never fires.
  function buildPolicyInventory(agg) {
    const top = (map, cap) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, cap || LOG_TOP_CAP)
      .map(([name, count]) => ({ name, count }));
    const policies = [...agg.policyInventory.values()].map(inv => {
      const state = inv.applied > 0 ? 'enforcing'
        : inv.reportOnly > 0 ? 'reportOnly'
          : 'neverMatched';
      return {
        id: inv.id || '',
        name: inv.name,
        state,
        evaluations: inv.evaluations,
        applied: inv.applied,
        blocked: inv.blocked,
        reportOnly: inv.reportOnly,
        notApplied: inv.notApplied,
        hitRate: logPct(inv.applied + inv.reportOnly, inv.evaluations),
        grants: top(inv.grants, 6).map(g => ({ ...g, label: controlLabelFor(g.name) })),
        sessions: top(inv.sessions, 6).map(s => ({ ...s, label: controlLabelFor(s.name) })),
        authStrength: top(inv.authStrength, 3),
        reportOnlyResults: top(inv.reportOnlyResults || new Map(), 8),
        topUsers: top(inv.users),
        topApps: top(inv.apps),
        topDevices: top(inv.devices),
        topLocations: top(inv.locations),
        notSatisfied: top(inv.notSatisfied, 6).map(c => ({ ...c, label: LOG_CA_CONDITIONS[c.name] || c.name })),
        observedConfig: observedPolicyConfig(inv),
        excludedPrincipals: top(inv.excludedPrincipals, 5),
        exclusionRules: observedExclusionRules(inv),
        exclusionIdentities: observedExclusionIdentities(inv),
        exclusionSamples: inv.exclusionSamples,
        excludedEventCount: inv.excludedEventCount,
        sources: [...inv.sources],
        samples: inv.samples,
        from: Number.isFinite(inv.minTime) ? new Date(inv.minTime).toISOString() : null,
        to: Number.isFinite(inv.maxTime) ? new Date(inv.maxTime).toISOString() : null,
        // A tenant policy whose name starts with CAnnn maps to a baseline policy of the same id.
        baselineId: (() => {
          const m = inv.name.match(/^CA(\d{3})/i);
          if (!m) return '';
          const id = `CA${m[1]}`;
          return baselinePolicies().some(p => p.id === id) ? id : '';
        })()
      };
    });
    policies.sort((a, b) => b.applied - a.applied || b.reportOnly - a.reportOnly || b.evaluations - a.evaluations);
    const enforcedControls = new Set();
    policies.forEach(p => {
      if (p.state !== 'enforcing') return;
      p.grants.forEach(g => enforcedControls.add(normToken(g.name)));
      p.sessions.forEach(s => enforcedControls.add(normToken(s.name)));
    });
    return {
      policies,
      summary: {
        total: policies.length,
        enforcing: policies.filter(p => p.state === 'enforcing').length,
        reportOnly: policies.filter(p => p.state === 'reportOnly').length,
        neverMatched: policies.filter(p => p.state === 'neverMatched').length,
        evaluations: policies.reduce((n, p) => n + p.evaluations, 0),
        controlsEnforced: [...enforcedControls].map(controlLabelFor).sort(),
        controlsMissing: LOG_EXPECTED_CONTROLS
          .filter(c => ![...enforcedControls].some(e => e.includes(c.key) || c.key.includes(e)))
          .map(c => c.label)
      }
    };
  }

  function policyHasMfaEvidence(policy) {
    const evidence = [
      policy.name,
      ...(policy.grants || []).flatMap(item => [item.name, item.label]),
      ...(policy.authStrength || []).map(item => item.name)
    ].filter(Boolean).join(' ');
    return /\bmfa\b|multifactor|multi-factor|authentication strength/i.test(evidence);
  }

  function mfaExclusionPolicies(policies) {
    return (policies || []).filter(policy => policyHasMfaEvidence(policy)
      && (policy.exclusionRules || []).some(rule => rule.identityAssignment));
  }

  function mfaExclusionSummary(policies) {
    const relevant = mfaExclusionPolicies(policies);
    const identities = new Map();
    relevant.forEach(policy => (policy.exclusionIdentities || []).forEach(identity => {
      const key = identity.objectId || `${identity.identityType}:${identity.name}`;
      const current = identities.get(key) || { ...identity, count: 0, policies: new Set() };
      current.count += identity.count;
      current.policies.add(policy.name);
      identities.set(key, current);
    }));
    return {
      policies: relevant,
      policyCount: relevant.length,
      identities: [...identities.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
      identityCount: identities.size,
      policyEventObservations: relevant.reduce((sum, policy) => sum + (policy.excludedEventCount || 0), 0),
      ruleCount: relevant.reduce((sum, policy) => sum + (policy.exclusionRules || []).filter(rule => rule.identityAssignment).length, 0)
    };
  }

  // Why a simulated verdict landed where it did, in the reader's language. `headline` is the
  // summary chip; `detail` answers the question a vague verdict leaves hanging — is this
  // policy actually relevant to me, and what do I check to find out?
  const LOG_COVERAGE_REASONS = {
    roles: {
      headline: 'applies by admin role',
      detail: 'This policy targets directory roles. Sign-in logs record who signed in, not which roles they hold, so coverage cannot be counted from logs alone — it applies to whoever holds those roles in your tenant today.',
      check: 'Check the role holders in Entra ID > Roles and administrators against the roles listed above.'
    },
    groups: {
      headline: 'applies by group membership',
      detail: 'This policy targets security groups. Sign-in logs do not carry group membership, so coverage depends entirely on who you put in those groups.',
      check: 'It applies to exactly the members of the groups listed above — no more, no less.'
    },
    namedUsers: {
      headline: 'applies to named users',
      detail: 'This policy targets specific user objects rather than a broad scope, so coverage is defined by that list rather than by traffic.',
      check: 'Confirm the named users are still the right ones.'
    },
    guestType: {
      headline: 'applies to guests',
      detail: 'This policy targets guest and external users. The user type on these sign-ins could not be resolved, so guest traffic cannot be counted reliably here.',
      check: 'Review your guest inventory in Entra ID > Users, filtered to external.'
    },
    locations: {
      headline: 'applies by named location',
      detail: 'This policy is scoped by named locations. Whether a sign-in falls inside or outside those locations depends on how you define them, which the log cannot tell us in advance.',
      check: 'Define the named locations in Entra ID > Named locations before enabling.'
    },
    deviceFilter: {
      headline: 'applies by device attributes',
      detail: 'This policy uses a device filter that reads device object attributes such as trust type and ownership. Sign-in logs do not carry those attributes in full, so coverage cannot be counted.',
      check: 'Confirm your device inventory matches the filter rule in Entra ID > Devices.'
    },
    appUnknown: { headline: 'app-scoped', detail: 'This policy targets specific applications and some sign-ins did not report an application id, so those cannot be counted either way.', check: 'Confirm the targeted applications are the right ones.' },
    clientAppUnknown: {
      headline: 'no legacy clients confirmed',
      detail: 'This policy targets specific client app types — typically legacy authentication clients. Service-principal sign-ins do not report a user client app, so those cannot be counted either way.',
      check: 'Check the Entra sign-in logs filtered to Client app = "Other clients" to confirm before enforcing.'
    },
    platformUnknown: { headline: 'platform scoped', detail: 'This policy targets specific device platforms and the platform was not reported on some sign-ins.', check: '' },
    signInRiskUnknown: { headline: 'risk scoped', detail: 'This policy triggers on sign-in risk. Risk was not evaluated on these sign-ins, which normally means Entra ID P2 is not licensed or risk detection is not running.', check: 'Confirm Entra ID P2 licensing before relying on this policy.' },
    userRiskUnknown: { headline: 'risk scoped', detail: 'This policy triggers on user risk. Risk was not evaluated on these sign-ins, which normally means Entra ID P2 is not licensed or risk detection is not running.', check: 'Confirm Entra ID P2 licensing before relying on this policy.' },
    authFlowUnknown: { headline: 'flow scoped', detail: 'This policy triggers on authentication transfer flows and the flow was not reported on some sign-ins.', check: '' },
    unevaluated: { headline: 'conditions not simulated', detail: 'This policy uses a condition the simulator deliberately will not guess at, so its coverage is reported as unconfirmed rather than assumed.', check: 'Run it in report-only mode to get real numbers.' },
    notGuest: { headline: 'no guest traffic', detail: 'Every analysed sign-in came from an internal account, so a guest-scoped policy had nothing to act on in this window.', check: 'It still matters the moment you invite a guest.' },
    appNotTargeted: { headline: 'targets other apps', detail: 'The applications this policy targets did not appear in the analysed sign-ins.', check: 'Confirm the targeted apps are ones your users actually reach.' },
    appExcluded: { headline: 'app excluded', detail: 'The applications seen in these logs sit in this policy\'s exclusion list.', check: 'Review whether that exclusion is still justified.' },
    clientAppType: { headline: 'no matching client apps', detail: 'This policy targets client app types — typically legacy authentication clients — that did not appear in the analysed sign-ins. For a block policy that is the healthy result.', check: 'Deploy it to keep that traffic at zero rather than to fix a live problem.' },
    platform: { headline: 'no matching platforms', detail: 'The device platforms this policy targets did not appear in the analysed sign-ins.', check: 'Confirm you have no devices on those platforms before dismissing it.' },
    signInRisk: { headline: 'no risky sign-ins seen', detail: 'No sign-in in this window carried a risk level that would trigger this policy. For a risk block policy that is the healthy result — it is a standing control, not a response to something already happening.', check: 'Deploy it so that a future risky sign-in is blocked automatically.' },
    userRisk: { headline: 'no risky users seen', detail: 'No account in this window carried an elevated user risk level. For a risk block policy that is the healthy result — it is a standing control, not a response to something already happening.', check: 'Deploy it so that a future compromised account is blocked automatically.' },
    authFlows: { headline: 'no risky flows seen', detail: 'No sign-in in this window used device code flow or authentication transfer. For a block policy that is the healthy result — these flows are a known phishing route and blocking them pre-emptively is the point.', check: 'Deploy it to keep that route closed.' }
  };

  // Coverage of a given policy set against the loaded logs: how much of this tenant's real
  // traffic each policy would have caught if deployed as shipped, and — just as important —
  // why the simulator could not count the rest.
  function computeCoverageFor(agg, items) {
    const facts = agg.coverageFacts;
    const out = {};
    items.forEach(item => {
      let yes = 0, conditional = 0, no = 0, notApplicable = 0;
      const samples = [];
      const condReasons = new Map();
      const noReasons = new Map();
      const bump = (map, key, amount) => map.set(key, (map.get(key) || 0) + amount);
      facts.forEach(f => {
        const weight = representedEventCount(f.eventCount);
        const sink = { c: null, n: null };
        const verdict = coverageVerdict(item, f, sink);
        if (verdict === 'n/a') {
          // Out of scope for this policy's identity class — excluded from the denominator
          // rather than counted as a miss, which would understate coverage just as badly.
          notApplicable += weight;
        } else if (verdict === 'yes') {
          yes += weight;
          if (samples.length < LOG_TOP_CAP) samples.push({ time: f.time, principal: f.principal, app: f.app, source: f.source });
        } else if (verdict === 'conditional') {
          conditional += weight;
          bump(condReasons, sink.c || 'unevaluated', weight);
        } else {
          no += weight;
          bump(noReasons, sink.n || 'appNotTargeted', weight);
        }
      });
      const totalFacts = facts.reduce((sum, fact) => sum + representedEventCount(fact.eventCount), 0);
      const applicable = totalFacts - notApplicable;
      const top = map => [...map.entries()].sort((a, b) => b[1] - a[1])[0] || null;
      out[item.id] = {
        evaluated: applicable,
        totalFacts,
        notApplicable,
        // What the applicable population actually is, so the denominator can be named rather
        // than left as a bare count the reader has to interpret.
        scope: notApplicable
          ? (item.policy || {}).conditions && (item.policy || {}).conditions.clientApplications
            ? 'workload identity sign-ins' : 'user sign-ins'
          : 'analysed sign-ins',
        wouldApply: yes,
        conditional,
        wouldNot: no,
        pct: logPct(yes, applicable),
        pctWithConditional: logPct(yes + conditional, applicable),
        // The single reason that decided most of the uncounted traffic, which is what the
        // reader needs to judge relevance.
        reason: (conditional > no ? top(condReasons) : top(noReasons) || top(condReasons)),
        samples
      };
    });
    return {
      policies: out,
      evaluated: facts.reduce((sum, fact) => sum + representedEventCount(fact.eventCount), 0),
      importedRows: facts.length,
      capped: facts.length >= LOG_COVERAGE_CAP
    };
  }

  // The policy set "Build this strategy" would actually create from these findings, with
  // each policy's real configuration and its coverage against the loaded logs. Built here
  // (not at render time) so the two views cannot drift apart.
  // What this specific tenant actually looks like, read from the logs. A recommended policy
  // that says "select your platforms" is a template; one that says "select Windows, iOS and
  // macOS, because that is what signed in" is an assessment.
  function tenantProfile(agg) {
    const platforms = new Map();
    const osNames = new Map();
    (agg.coverageFacts || []).forEach(f => {
      const weight = representedEventCount(f.eventCount);
      const token = logPlatformToken(f.operatingSystem);
      if (token) platforms.set(token, (platforms.get(token) || 0) + weight);
      const label = logOsLabel(f);
      if (label) osNames.set(label, (osNames.get(label) || 0) + weight);
    });
    // Some aggregate maps hold a counter object rather than a bare number.
    const size = value => (value && typeof value === 'object' ? value.count || 0 : value || 0);
    const rank = map => [...map.entries()]
      .map(([name, value]) => ({ name, count: size(value) }))
      .sort((a, b) => b.count - a.count);
    return {
      tenantId: agg.tenantId || '',
      platforms: rank(platforms),
      operatingSystems: rank(osNames).slice(0, 12),
      countries: rank(agg.countries || new Map()),
      externalTenants: rank((agg.outboundB2B || {}).tenants || new Map()),
      servicePrincipals: [...(agg.spPrincipals || new Map()).keys()],
      apps: rank(agg.apps || new Map()).slice(0, 12),
      userCount: (agg.users || new Map()).size
    };
  }

  // The tenant-specific values to enter for a given policy — only where the policy actually
  // has that condition, plus the cases where the observed environment says a condition SHOULD
  // be set and the shipped baseline leaves it open.
  function policyTailoring(item, profile) {
    const c = (item.policy || {}).conditions || {};
    const list = v => (Array.isArray(v) ? v : []).filter(Boolean);
    const rows = [];
    const names = entries => entries.map(e => `${e.name} (${e.count})`).join(', ');

    if (c.platforms) {
      const included = list(c.platforms.includePlatforms).map(normToken);
      const wildcard = !included.length || included.includes('all');
      const seen = profile.platforms.map(p => p.name);
      const uncovered = wildcard ? [] : seen.filter(p => !included.includes(normToken(p)));
      // App protection policies are mobile-only by design — Intune MAM does not target
      // Windows or macOS — so an uncovered desktop platform is not a hole in this policy.
      const mobileOnly = (item.controls || []).includes('app_protection');
      rows.push({
        label: 'Device platforms to select',
        value: wildcard
          ? `Your users signed in from ${seen.length ? seen.join(', ') : 'no resolvable platform'}. Select those explicitly rather than leaving "Any device" set.`
          : `Policy targets ${included.join(', ')}. Observed in your logs: ${seen.join(', ') || 'none resolvable'}.`,
        warn: !uncovered.length ? ''
          : mobileOnly
            ? `${uncovered.join(', ')} also signed in, but app protection policies only apply to iOS and Android — that is by design. Cover desktop platforms with the device compliance policy and app-enforced restrictions instead.`
            : `${uncovered.join(', ')} signed in during this window but ${uncovered.length === 1 ? 'is' : 'are'} not in this policy's platform list — those sign-ins would not be covered by it.`
      });
      if (profile.operatingSystems.length) {
        rows.push({
          label: 'Operating systems seen',
          value: names(profile.operatingSystems),
          warn: 'Conditional Access matches on platform, not build. Use a device compliance policy in Intune to enforce a minimum OS build.'
        });
      }
    }

    if (c.locations) {
      rows.push({
        label: 'Named locations to define',
        value: profile.countries.length
          ? `Sign-ins came from ${names(profile.countries)}. Define a named location covering the countries you operate in before enabling this policy.`
          : 'No country data in these logs — define your named locations from your own knowledge of where staff work.',
        warn: 'A location policy enabled before its named locations exist will block everyone.'
      });
    }

    const includeGroups = list((c.users || {}).includeGroups);
    if (includeGroups.length && (item.controls || []).includes('service_account_protection')) {
      const workload = profile.servicePrincipals;
      rows.push({
        label: 'What this policy actually covers',
        value: 'Human-operated service accounts — user objects in the group above. It is scoped through conditions.users and grants MFA, so it applies to user identities only.',
        warn: workload.length
          ? `It does NOT cover the ${workload.length} workload ${workload.length === 1 ? 'identity' : 'identities'} in your logs (${workload.join(', ')}). A service principal cannot perform MFA and is never matched by a user-scoped policy — do not add them to this group expecting coverage.`
          : ''
      });
      if (workload.length) {
        rows.push({
          label: 'How to cover the workload identities instead',
          value: `Conditional Access reaches service principals only through a workload identity policy (conditions.clientApplications), which requires Microsoft Entra Workload ID Premium and covers single-tenant service principals registered in your own tenant. Target them directly — policies assigned to a group containing a service principal are not enforced for it.`,
          warn: `Microsoft and third-party multitenant applications cannot be covered by Conditional Access at all. Check which of ${workload.join(', ')} are third-party: for those, the controls available to you are credential hygiene, least-privilege API permissions, and removing the app if it is unused.`
        });
      }
    }

    if (profile.externalTenants.length && (item.controls || []).some(id => ['mfa', 'guest_access', 'session_controls'].includes(id))) {
      rows.push({
        label: 'External organisations seen',
        value: `Your users authenticated into ${profile.externalTenants.length} external ${profile.externalTenants.length === 1 ? 'tenant' : 'tenants'}: ${names(profile.externalTenants)}.`,
        warn: 'Those sign-ins are governed by the other tenant\'s Conditional Access, not yours. Control them through Cross-tenant access settings > Outbound access instead.'
      });
    }

    if (list((c.users || {}).includeRoles).length) {
      rows.push({
        label: 'Role holders to confirm',
        value: `This policy targets ${list(c.users.includeRoles).length} directory roles. Sign-in logs never carry role membership, so confirm the holders in Entra ID > Roles and administrators.`,
        warn: 'Include every eligible PIM assignment, not just active ones — an eligible admin who activates later must still be covered.'
      });
    }

    return rows;
  }

  // Which identity type a consolidated policy protects, taken from its id band. The band
  // matches the name the user sees (CA2xx = Workforce, CA3xx = ServiceAccounts); the inherited
  // `persona` does not, because a clone keeps the persona of its source — CA202C is named
  // Workforce but clones a Global policy.
  // `requirements` scopes which findings may be cited as evidence for a policy in this band.
  // Without it, a guest policy granting MFA collects single-factor findings measured on
  // member sign-ins, because almost every policy shares the generic `mfa` control.
  const LOG_POLICY_CATEGORIES = [
    { key: 'tenant', band: '0', label: 'Tenant-wide', identity: 'Applies to every identity in the tenant, whoever they are.', requirements: [] },
    { key: 'admins', band: '1', label: 'Privileged administrators', identity: 'Applies to accounts holding directory roles.', requirements: ['admins'] },
    { key: 'workforce', band: '2', label: 'Workforce', identity: 'Applies to your internal user accounts.', requirements: ['internals', 'managedDevices'] },
    { key: 'service', band: '3', label: 'Service accounts', identity: 'Applies to human-operated service accounts — user objects, not workload identities.', requirements: ['serviceAccounts'] },
    { key: 'guests', band: '4', label: 'Guests and external users', identity: 'Applies to B2B guests invited into your tenant.', requirements: ['guests'] },
    { key: 'agents', band: '5', label: 'Agent identities', identity: 'Applies to agent identities and agent resources. Preview/beta targeting.', requirements: ['agents'] }
  ];

  function policyCategory(id) {
    const band = (String(id).match(/^CA(\d)/) || [])[1];
    return LOG_POLICY_CATEGORIES.find(c => c.band === band) || LOG_POLICY_CATEGORIES[0];
  }

  // Groups a recommended set into identity-type sections, in escalating scope order, so the
  // reader can see at a glance what each policy protects.
  function groupPoliciesByCategory(policies) {
    return LOG_POLICY_CATEGORIES
      .map(category => ({
        ...category,
        policies: policies
          .filter(p => policyCategory(p.id).key === category.key)
          .sort((a, b) => a.id.localeCompare(b.id))
      }))
      .filter(group => group.policies.length);
  }

  function logRecommendationPrimaryElement(item) {
    const mapped = (item.controls || []).map(control => LOG_RECOMMENDATION_PRIMARY_ELEMENT[control]).filter(Boolean);
    if (mapped.length) return mapped[0];
    const category = policyCategory(item.id).key;
    return {
      admins: 'identity-scope', workforce: 'identity-scope', guests: 'guest-scope',
      service: 'service-account-scope', agents: 'managed-identities', tenant: 'applied-path'
    }[category] || 'applied-path';
  }

  function logRecommendationDeclarationKeys(item) {
    const keys = new Set();
    (item.controls || []).forEach(control => (LOG_RECOMMENDATION_CONTROL_DECLARATIONS[control] || []).forEach(key => keys.add(key)));
    const categoryKey = policyCategory(item.id).key;
    if (categoryKey === 'guests') keys.add('guests');
    if (categoryKey === 'service') keys.add('serviceAccounts');
    if (categoryKey === 'agents') keys.add('agents');
    return [...keys];
  }

  function logRecommendationPrerequisites(item, answers) {
    const controls = item.controls || [];
    const declarations = answers || defaultDeclarations();
    const records = [];
    logRecommendationDeclarationKeys(item).forEach(key => {
      const declaration = LOG_DECLARATIONS.find(entry => entry.key === key);
      const answer = declarations[key] || 'unknown';
      records.push({
        key: `declaration:${key}`,
        declarationKey: key,
        label: declaration ? declaration.question.replace(/\?$/, '') : key,
        status: answer === 'yes' ? 'confirmed' : answer === 'no' ? 'incompatible' : 'unresolved',
        detail: answer === 'yes'
          ? 'Confirmed by the tenant assumption answer.'
          : answer === 'no'
            ? 'The tenant answer makes this policy family incompatible; do not deploy it while that answer remains no.'
            : declaration?.unknownNote || 'This prerequisite has not been confirmed.'
      });
    });
    [...new Set(controls)].forEach(control => {
      const label = LOG_RECOMMENDATION_CAPABILITY_PREREQUISITES[control];
      if (!label) return;
      records.push({
        key: `capability:${control}`,
        control,
        label,
        status: 'unresolved',
        detail: 'Validate support against the exact applications, clients and platforms in scope.'
      });
    });
    if (controls.some(control => control.startsWith('agent_')) || /^CA5/.test(item.id) || isPreviewPolicy(item)) {
      records.push({
        key: 'capability:preview',
        label: 'Confirm preview capability, licensing and production support boundaries.',
        status: 'unresolved',
        detail: 'Preview features require an explicit design and support decision before production use.'
      });
    }
    return [...new Map(records.map(record => [record.key, record])).values()];
  }

  function logRecommendationMetadata(item, drivers, basis, answers) {
    const controls = item.controls || [];
    const primaryElementId = logRecommendationPrimaryElement(item);
    const secondaryElementIds = [...new Set(controls.map(control => LOG_RECOMMENDATION_PRIMARY_ELEMENT[control]).filter(id => id && id !== primaryElementId))];
    const declarationKeys = logRecommendationDeclarationKeys(item);
    const prerequisites = logRecommendationPrerequisites(item, answers);
    const unresolvedPrerequisites = prerequisites.filter(item => item.status === 'unresolved');
    const incompatiblePrerequisites = prerequisites.filter(item => item.status === 'incompatible');
    const preview = controls.some(control => control.startsWith('agent_')) || /^CA5/.test(item.id) || isPreviewPolicy(item);
    const outsideCa = primaryElementId === 'sp-credentials';
    const reasonLabels = [];
    if (drivers.length) reasonLabels.push('Evidence-led');
    if (basis.kind === 'declared') reasonLabels.push('Tenant choice');
    if (basis.kind === 'unconfirmed' || unresolvedPrerequisites.length || incompatiblePrerequisites.length) reasonLabels.push('Prerequisite');
    if (controls.some(control => ['sign_in_risk', 'user_risk', 'agent_risk', 'agent_user_risk'].includes(control))) reasonLabels.push('Licence required');
    if (preview) reasonLabels.push('Preview');
    if (outsideCa) reasonLabels.push('Outside CA');
    let actionTier = 'actNow';
    if (!drivers.length && (basis.kind === 'unconfirmed' || preview || outsideCa)) actionTier = 'optionalAdvanced';
    else if (unresolvedPrerequisites.length || incompatiblePrerequisites.length) actionTier = 'validateFirst';
    const linkKeys = new Set(['deployment']);
    const relatedElementIds = new Set([primaryElementId, ...secondaryElementIds]);
    if (['device-identity', 'device-compliance', 'byod-protection'].some(id => relatedElementIds.has(id))) ['deviceFilters', 'grantControls'].forEach(key => linkKeys.add(key));
    if (relatedElementIds.has('session-protection')) linkKeys.add('sessionControls');
    if (relatedElementIds.has('guest-scope')) linkKeys.add('externalDeviceTrust');
    return {
      actionTier,
      actionTierLabel: LOG_RECOMMENDATION_ACTION_TIERS[actionTier].label,
      reasonLabels: [...new Set(reasonLabels.length ? reasonLabels : ['Baseline'])],
      primaryElementId,
      secondaryElementIds,
      declarationKeys,
      applicability: drivers.length ? 'Directly connected to measured finding evidence.' : basis.detail,
      prerequisites,
      unresolvedPrerequisites,
      incompatiblePrerequisites,
      capabilityStatus: incompatiblePrerequisites.length
        ? 'Incompatible with a current tenant assumption'
        : preview
          ? 'Preview or capability-limited'
          : unresolvedPrerequisites.length
            ? 'Supported when prerequisites and tenant intent are confirmed'
            : 'Broadly applicable supported control',
      guidanceUrls: [...linkKeys].map(key => LOG_LEARN_GUIDANCE[key]).filter(Boolean)
    };
  }

  function logRecommendationPriority(policy) {
    const severity = { high: 4, medium: 3, low: 2, info: 1 };
    const findingScore = policy.drivers.reduce((score, driver) => Math.max(score, severity[driver.severity] || 0), 0);
    const affected = policy.drivers.reduce((sum, driver) => sum + (Number(driver.affected) || 0), 0);
    const tierRank = LOG_RECOMMENDATION_ACTION_TIERS[policy.actionTier]?.rank || 0;
    return tierRank * 1000000000 + findingScore * 100000000 + Math.min(affected, 99999999);
  }

  function buildRecommendedPolicySet(agg, findings, declarations) {
    const handoff = strategyHandOffFromFindings(findings, declarations);
    if (!handoff.requirementKeys.length) return null;
    const requirements = { ...STRATEGY_DEFAULTS, protection: handoff.protection };
    handoff.requirementKeys.forEach(key => { requirements[key] = true; });
    const preview = strategyPlan(requirements);
    const items = (preview.policies || [])
      // A control the user explicitly declined must not reappear via the protection level.
      .filter(item => !(item.controls || []).some(id => handoff.declinedControls.includes(id)));
    const coverage = computeCoverageFor(agg, items);
    const profile = tenantProfile(agg);

    // Which of this tenant's own findings put each policy in the list. This is the only
    // honest answer to "why is this policy relevant to me" — coverage percentages describe
    // reach, not need.
    // A shared control id is not enough on its own: nearly every policy grants MFA, so
    // matching on control alone credited the guest policy with single-factor findings measured
    // on member sign-ins. The finding's requirement must also cover this policy.
    const requirementsOwningItem = item => {
      const controls = item.controls || [];
      return handoff.requirementKeys.filter(key =>
        strategyControlsForRequirement(STRATEGY_REQUIREMENTS[key], requirements.protection).some(id => controls.includes(id)));
    };
    const driversFor = item => {
      const controls = item.controls || [];
      // Identity-scoped policies may only cite findings about that identity type. Tenant-wide
      // policies declare no scope and may cite any finding.
      const scope = policyCategory(item.id).requirements || [];
      return findings
        .filter(f => (f.controlIds || []).some(id => controls.includes(id)))
        .filter(f => !scope.length || (f.requirements || []).some(key => scope.includes(key)))
        .map(f => ({ id: f.id, title: f.title, severity: f.severity, affected: f.metric.affected, pct: f.metric.pct, scope: f.metric.scope }));
    };

    // Policies carrying controls that no single finding named are here because the protection
    // level pulled them in. Saying so beats showing nothing under "why this is recommended" —
    // which is worst on the block policies, whose relevance is least self-evident.
    const levelLabel = (STRATEGY_LEVELS[requirements.protection] || {}).label || requirements.protection;
    const answers = declarations || defaultDeclarations();

    // Why this policy is in the list. Evidence beats assumption: where the logs proved the
    // gap, say so, because that is the stronger claim. Where they could not, say that too
    // rather than presenting an assumption as a finding.
    // Same scoping as driversFor: an admin policy is owned by the admin requirement, not by
    // whichever other requirement happens to share `session_controls`.
    const requirementsOwning = item => {
      const scope = policyCategory(item.id).requirements || [];
      const owning = requirementsOwningItem(item);
      const scoped = owning.filter(key => scope.includes(key));
      return scope.length && scoped.length ? scoped : owning;
    };
    const basisFor = (item, drivers) => {
      if (drivers.length) {
        return { kind: 'evidenced', label: 'Evidenced', detail: `Your own sign-in logs show the gap this policy closes — ${drivers.length === 1 ? 'the finding is' : 'the findings are'} listed below.` };
      }
      const owners = requirementsOwning(item);
      // A declaration the user answered "yes" to is a stated fact about the tenant.
      const declaredOwner = owners.find(key => handoff.basis.declared.includes(key));
      if (declaredOwner) {
        const d = LOG_DECLARATIONS.find(x => (x.requirements || []).includes(declaredOwner));
        return { kind: 'declared', label: 'Declared', detail: `You told us: ${d ? d.question.replace(/\?$/, '') : 'this applies'} — yes. ${d ? d.why : ''}`.trim() };
      }
      // An unanswered declaration means the logs could not confirm the need either way.
      const assumedOwner = owners.find(key => handoff.basis.assumed.includes(key) && !handoff.basis.evidenced.includes(key) && !LOG_STANDARD_REQUIREMENTS.includes(key));
      if (assumedOwner) {
        const d = LOG_DECLARATIONS.find(x => (x.requirements || []).includes(assumedOwner));
        return { kind: 'unconfirmed', label: 'Unconfirmed', detail: d ? `${d.unknownNote} ${d.why}` : 'Included because these logs cannot confirm whether you need it.' };
      }
      const labels = owners.map(key => STRATEGY_REQUIREMENTS[key].label);
      return {
        kind: 'standard',
        label: 'Standard',
        detail: `Baseline practice for any tenant${labels.length ? ` covering ${labels.join(' and ')}` : ''}, at protection level "${levelLabel}". It closes a route before it is used, so it is here whether or not your logs show it being exploited.`
      };
    };

    // CONTROLS is the authority on which baseline policy delivers which control; baseline
    // policy objects do not carry the mapping themselves.
    const controlsForBaseline = id => Object.keys(CONTROLS)
      .filter(key => preview.controls.includes(key) && (CONTROLS[key].policyIds || []).includes(id));

    // The consolidated set REPLACES the baselines it names, so anything the selected controls
    // imply but no policy here delivers is a silent downgrade. Computed, never hand-listed,
    // so it cannot drift from what the builder actually emits.
    const represented = new Set(items.flatMap(item => item.represents || []));
    const seenGap = new Set();
    const uncovered = (preview.equivalentPolicies || [])
      // baselinePolicies() ships a few ids twice (CA005/CA006), so dedupe or the gap list
      // double-counts them.
      .filter(p => !represented.has(p.id) && (seenGap.has(p.id) ? false : (seenGap.add(p.id), true)))
      .map(p => ({ id: p.id, displayName: p.displayName, controls: controlsForBaseline(p.id) }));

    return {
      mode: requirements.mode,
      evaluated: coverage.evaluated,
      capped: coverage.capped,
      replaces: [...represented].sort(),
      uncovered,
      profile,
      declarations: answers,
      // What the user turned off, and whether the logs disagreed with them.
      declined: LOG_DECLARATIONS.filter(d => answers[d.key] === 'no').map(d => ({
        key: d.key,
        question: d.question,
        contradictsEvidence: (d.requirements || []).some(key => handoff.declinedDespiteEvidence.includes(key)),
        findings: findings
          .filter(f => (f.requirements || []).some(key => (d.requirements || []).includes(key)))
          .map(f => ({ title: f.title, affected: f.metric.affected, scope: f.metric.scope }))
      })),
      policies: items.map(item => {
        const drivers = driversFor(item);
        const basis = basisFor(item, drivers);
        const recommendation = logRecommendationMetadata(item, drivers, basis, answers);
        return {
        id: item.id,
        displayName: item.displayName,
        summary: item.summary || '',
        represents: item.represents || [],
        controls: item.controls || [],
        blocks: ((item.policy || {}).grantControls || {}).builtInControls
          ? (item.policy.grantControls.builtInControls || []).map(normToken).includes('block')
          : false,
        mergeReason: item.mergeReason || item.separateReason || '',
        consolidated: Boolean(item.consolidated || item.kind === 'consolidated'),
        settings: policyFixSettings(item),
        drivers,
        basis,
        ...recommendation,
        tailoring: policyTailoring(item, profile),
        requiredObjects: item.requiredObjects || [],
        // The original strategy item, so the Word guide can reuse manualGuideSections()
        // rather than re-deriving the build steps and drifting from the app.
        source: item,
        coverage: coverage.policies[item.id] || null
        };
      }).sort((a, b) => logRecommendationPriority(b) - logRecommendationPriority(a) || a.id.localeCompare(b.id))
    };
  }

  function buildSourceStats(agg, sources) {
    const out = {};
    Object.keys(sources).forEach(key => {
      const stats = agg.sourceStats[key] || {};
      out[key] = {
        fileNames: sources[key].fileNames,
        format: sources[key].format,
        records: sources[key].representedEvents,
        importedRowCount: sources[key].importedRowCount,
        representedEvents: sources[key].representedEvents,
        empty: sources[key].representedEvents === 0,
        success: stats.success || 0,
        failure: stats.failure || 0,
        users: stats.users ? stats.users.size : 0,
        apps: stats.apps ? stats.apps.size : 0,
        guests: stats.guests || 0,
        from: Number.isFinite(stats.minTime) ? new Date(stats.minTime).toISOString() : null,
        to: Number.isFinite(stats.maxTime) ? new Date(stats.maxTime).toISOString() : null
      };
    });
    return out;
  }

  function buildLogSummary(agg, findings, sources) {
    return {
      total: agg.total,
      success: agg.success,
      failure: agg.failure,
      bySource: { ...agg.totals },
      importedRowCount: agg.importedRowCount,
      groupedRowCount: agg.groupedRowCount,
      users: agg.users.size,
      apps: agg.apps.size,
      workloads: agg.spPrincipals.size,
      guests: agg.guests,
      from: Number.isFinite(agg.minTime) ? new Date(agg.minTime).toISOString() : null,
      to: Number.isFinite(agg.maxTime) ? new Date(agg.maxTime).toISOString() : null,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      sourcesLoaded: LOG_SOURCE_ORDER.filter(key => key in sources),
      sourcesMissing: LOG_SOURCE_ORDER.filter(key => !(key in sources))
    };
  }

  function parseSignInJson(text, fileName) {
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      throw new Error('Could not parse JSON. Export sign-in logs from Entra ID (portal Download JSON, or Graph auditLogs/signIns).');
    }
    let rows = Array.isArray(data) ? data : Array.isArray(data?.value) ? data.value : data && typeof data === 'object' ? [data] : [];
    rows = rows.filter(row => row && typeof row === 'object');
    // An empty array is legitimate for an export with no sign-in activity.
    if (!rows.length) {
      const hint = logFilenameHint(fileName);
      return { records: [], warnings: [], format: 'json', source: hint || 'unknown', detectedBy: hint ? 'filename' : 'none' };
    }
    const detected = detectLogSource(rows, fileName);
    if (!detected.source) {
      const policyLike = rows.some(row => 'conditions' in row || 'grantControls' in row);
      throw new Error(policyLike
        ? 'This looks like a Conditional Access policy export, not sign-in logs. Export Entra sign-in records instead.'
        : 'No sign-in records recognised. Expected an Entra ID sign-in log export (portal JSON download or Graph auditLogs/signIns).');
    }
    if (detected.source === 'msi') {
      return {
        records: rows.map(row => ({ eventCount: representedEventCount(row.eventCount || row.signInCount || row.numberOfSignIns) })),
        warnings: [],
        format: 'json',
        source: 'msi',
        detectedBy: detected.detectedBy
      };
    }
    const isWorkload = LOG_SOURCES[detected.source].kind === 'workload';
    const signInLike = rows.filter(row =>
      'createdDateTime' in row || 'userPrincipalName' in row || 'clientAppUsed' in row ||
      'conditionalAccessStatus' in row || 'appDisplayName' in row ||
      'servicePrincipalId' in row || 'servicePrincipalName' in row
    );
    const records = signInLike.map(row => (isWorkload
      ? normalizeWorkloadSignIn(row, detected.source)
      : normalizeGraphSignIn(row, detected.source)));
    return { records, warnings: [], format: 'json', source: detected.source, detectedBy: detected.detectedBy };
  }

  function normalizeWorkloadSignIn(row, source) {
    const status = row.status || {};
    const location = row.location || {};
    const errorCode = Number.isFinite(Number(status.errorCode)) ? Number(status.errorCode) : null;
    const name = row.servicePrincipalName || row.servicePrincipalId || '';
    return {
      eventCount: representedEventCount(row.eventCount || row.signInCount || row.numberOfSignIns),
      groupedEvidence: representedEventCount(row.eventCount || row.signInCount || row.numberOfSignIns) > 1,
      source,
      identityType: 'servicePrincipal',
      principal: name || 'unknown identity',
      time: Date.parse(row.createdDateTime || ''),
      userId: '',
      userPrincipalName: '',
      userDisplayName: '',
      userType: '',
      appDisplayName: '',
      resourceDisplayName: row.resourceDisplayName || '',
      resourceId: row.resourceId || '',
      servicePrincipalId: row.servicePrincipalId || '',
      servicePrincipalName: name,
      appId: row.appId || '',
      appDisplayNameRaw: row.appDisplayName || '',
      credentialType: spCredentialType(row),
      appOwnerTenantId: row.appOwnerTenantId || '',
      resourceOwnerTenantId: row.resourceOwnerTenantId || row.resourceTenantId || '',
      ipAddress: row.ipAddress || '',
      clientAppUsed: '',
      conditionalAccessStatus: normToken(row.conditionalAccessStatus),
      appliedPolicies: normalizeAppliedPolicies(row),
      authenticationRequirement: '',
      authMethods: [],
      isCompliant: null,
      isManaged: null,
      operatingSystem: '',
      trustType: '',
      deviceName: '',
      deviceId: '',
      deviceOwnership: '',
      operatingSystemVersion: '',
      mdmAppId: '',
      enrollmentProfileName: '',
      browser: '',
      deviceState: 'unknown',
      incomingTokenType: normToken(row.incomingTokenType),
      originalTransferMethod: normToken(row.originalTransferMethod),
      homeTenantId: row.homeTenantId || row.appOwnerTenantId || '',
      resourceTenantId: row.resourceTenantId || row.resourceOwnerTenantId || '',
      crossTenantAccessType: normToken(row.crossTenantAccessType),
      country: location.countryOrRegion || '',
      city: location.city || '',
      region: location.state || '',
      riskLevelDuringSignIn: normToken(row.riskLevelDuringSignIn),
      riskLevelAggregated: normToken(row.riskLevelAggregated),
      riskState: normToken(row.riskState),
      errorCode,
      failureReason: status.failureReason || '',
      success: errorCode === 0,
      isInteractive: null
    };
  }

  function normalizeGraphSignIn(row, source) {
    const status = row.status || {};
    const device = row.deviceDetail || {};
    const location = row.location || {};
    const errorCode = Number.isFinite(Number(status.errorCode)) ? Number(status.errorCode) : null;
    const authMethods = [];
    (Array.isArray(row.authenticationDetails) ? row.authenticationDetails : []).forEach(detail => {
      if (detail && detail.authenticationMethod) authMethods.push(String(detail.authenticationMethod).toLowerCase());
    });
    if (row.mfaDetail && row.mfaDetail.authMethod) authMethods.push(String(row.mfaDetail.authMethod).toLowerCase());
    const isWindows = /windows/i.test(device.operatingSystem || '');
    const osBuild = isWindows ? parseWindowsBuild(row) : null;
    const windowsVersion = isWindows ? windowsVersionFromBuild(osBuild) : null;
    const hasDeviceIdentity = Boolean(device.deviceId || device.displayName || device.trustType);
    const deviceState = device.isCompliant === true ? 'compliant'
      : device.isCompliant !== false ? 'unknown'
        : !hasDeviceIdentity ? 'unregistered'
          : device.isManaged === true ? 'enrolledNotCompliant'
            : device.isManaged === false ? 'registeredNotCompliant' : 'unknown';
    return {
      eventCount: representedEventCount(row.eventCount || row.signInCount || row.numberOfSignIns),
      groupedEvidence: representedEventCount(row.eventCount || row.signInCount || row.numberOfSignIns) > 1,
      deviceState,
      source: source || 'interactive',
      identityType: 'user',
      // Entra redacts the UPN of cross-tenant B2B guests — fall back to the identifier or the
      // object id so distinct anonymous users are not collapsed into one bucket.
      principal: row.userPrincipalName || row.userDisplayName || row.signInIdentifier ||
        (row.userId ? `user ${row.userId}` : 'unknown user'),
      time: Date.parse(row.createdDateTime || ''),
      userId: row.userId || '',
      userPrincipalName: row.userPrincipalName || '',
      userDisplayName: row.userDisplayName || '',
      userType: String(row.userType || '').toLowerCase(),
      appDisplayName: row.appDisplayName || '',
      resourceDisplayName: row.resourceDisplayName || '',
      resourceId: row.resourceId || '',
      servicePrincipalId: '',
      servicePrincipalName: '',
      appId: row.appId || '',
      credentialType: null,
      ipAddress: row.ipAddress || '',
      clientAppUsed: row.clientAppUsed || '',
      conditionalAccessStatus: normToken(row.conditionalAccessStatus),
      appliedPolicies: normalizeAppliedPolicies(row),
      authenticationRequirement: normToken(row.authenticationRequirement),
      authMethods,
      isCompliant: typeof device.isCompliant === 'boolean' ? device.isCompliant : null,
      isManaged: typeof device.isManaged === 'boolean' ? device.isManaged : null,
      operatingSystem: device.operatingSystem || '',
      trustType: device.trustType || '',
      deviceName: device.displayName || '',
      deviceId: device.deviceId || '',
      deviceOwnership: device.deviceOwnership || row.deviceOwnership || '',
      operatingSystemVersion: device.operatingSystemVersion || row.operatingSystemVersion || '',
      mdmAppId: device.mdmAppId || row.mdmAppId || '',
      enrollmentProfileName: device.enrollmentProfileName || row.enrollmentProfileName || '',
      browser: device.browser || '',
      osBuild,
      osVersion: windowsVersion ? windowsVersion.label : '',
      incomingTokenType: normToken(row.incomingTokenType),
      originalTransferMethod: normToken(row.originalTransferMethod),
      // userType is relative to the RESOURCE tenant: one of your own users accessing another
      // organisation is logged as "guest". Direction is resolved from these tenant ids.
      homeTenantId: row.homeTenantId || '',
      resourceTenantId: row.resourceTenantId || '',
      crossTenantAccessType: normToken(row.crossTenantAccessType),
      country: location.countryOrRegion || '',
      city: location.city || '',
      region: location.state || '',
      riskLevelDuringSignIn: normToken(row.riskLevelDuringSignIn),
      riskLevelAggregated: normToken(row.riskLevelAggregated),
      riskState: normToken(row.riskState),
      errorCode,
      failureReason: status.failureReason || '',
      success: errorCode === 0,
      isInteractive: typeof row.isInteractive === 'boolean' ? row.isInteractive : null
    };
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let field = '';
    let inQuotes = false;
    for (let i = 0; i < text.length; i += 1) {
      const c = text[i];
      if (inQuotes) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 1; }
          else inQuotes = false;
        } else field += c;
      } else if (c === '"') {
        inQuotes = true;
      } else if (c === ',') {
        row.push(field); field = '';
      } else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i += 1;
        row.push(field); field = '';
        if (row.length > 1 || row[0] !== '') rows.push(row);
        row = [];
      } else field += c;
    }
    row.push(field);
    if (row.length > 1 || row[0] !== '') rows.push(row);
    return rows;
  }

  function normalizeCsvSignIns(rows, fileName) {
    if (rows.length < 2) throw new Error('The CSV has no data rows. Export sign-in logs from Entra ID with Download > CSV.');
    const headers = rows[0].map(normToken);
    const columns = {};
    const claimed = new Set();
    Object.entries(LOG_CSV_HEADERS).forEach(([field, aliases]) => {
      for (const alias of aliases) {
        const idx = headers.findIndex((h, i) => h === alias && !claimed.has(i));
        if (idx !== -1) { columns[field] = idx; claimed.add(idx); return; }
      }
    });
    const hasSpColumns = 'servicePrincipalId' in columns || 'servicePrincipalName' in columns;
    if (!hasSpColumns && !('createdDateTime' in columns) && !('userPrincipalName' in columns) && !('appDisplayName' in columns)) {
      throw new Error('No recognisable sign-in log columns found. Expected an Entra ID sign-in log CSV export.');
    }
    const warnings = [];
    const hint = logFilenameHint(fileName);
    let source;
    let detectedBy;
    if (hasSpColumns) {
      const workloadHint = hint === 'msi' || hint === 'application' ? hint : null;
      source = workloadHint || 'application';
      detectedBy = workloadHint ? 'shape+filename' : 'shape';
      warnings.push(source === 'msi'
        ? `${fileName || 'CSV export'} was detected as a managed-identity log and will be ignored because managed identities are outside Conditional Access.`
        : `${fileName || 'CSV export'} was read as a service-principal log — the JSON export carries the policy detail needed to determine workload Conditional Access applicability.`);
    } else if (hint === 'application' || hint === 'msi') {
      source = hint;
      detectedBy = 'filename';
    } else {
      source = hint || 'interactive';
      detectedBy = hint ? 'filename' : 'default';
    }
    if (source === 'msi') {
      const records = rows.slice(1).map(cells => ({ eventCount: representedEventCount('eventCount' in columns ? cells[columns.eventCount] : 1) }));
      return { records, warnings, format: 'csv', source, detectedBy };
    }
    const isWorkload = LOG_SOURCES[source].kind === 'workload';
    const unmapped = rows[0].filter((h, i) => !claimed.has(i) && normToken(h)).slice(0, 10);
    if (unmapped.length) warnings.push(`Ignored ${unmapped.length} unrecognised CSV column(s): ${unmapped.join(', ')}.`);
    const col = (cells, field) => (field in columns ? String(cells[columns[field]] ?? '').trim() : '');
    const yesNo = value => {
      const v = normToken(value);
      return v === 'yes' || v === 'true' ? true : v === 'no' || v === 'false' ? false : null;
    };
    let invalidGroupedCountRows = 0;
    const records = rows.slice(1).map(cells => {
      const statusText = normToken(col(cells, 'status'));
      const errorRaw = col(cells, 'errorCode');
      const errorCode = errorRaw !== '' && Number.isFinite(Number(errorRaw)) ? Number(errorRaw) : null;
      const locationText = col(cells, 'location');
      const method = col(cells, 'mfaAuthMethod').toLowerCase();
      const spName = col(cells, 'servicePrincipalName') || col(cells, 'servicePrincipalId');
      const upn = col(cells, 'userPrincipalName');
      const rawEventCount = col(cells, 'eventCount');
      const parsedEventCount = Number(rawEventCount.replace(/,/g, ''));
      if ('eventCount' in columns && rawEventCount && (!Number.isFinite(parsedEventCount) || parsedEventCount <= 0 || !Number.isInteger(parsedEventCount))) invalidGroupedCountRows += 1;
      const eventCount = representedEventCount(rawEventCount);
      return {
        eventCount,
        groupedEvidence: eventCount > 1,
        source,
        identityType: isWorkload ? 'servicePrincipal' : 'user',
        principal: (isWorkload ? spName : upn || col(cells, 'userDisplayName')) || (isWorkload ? 'unknown identity' : 'unknown user'),
        time: Date.parse(col(cells, 'createdDateTime')),
        userId: '',
        userPrincipalName: isWorkload ? '' : upn,
        userDisplayName: isWorkload ? '' : col(cells, 'userDisplayName'),
        userType: isWorkload ? '' : normToken(col(cells, 'userType')),
        appDisplayName: isWorkload ? '' : col(cells, 'appDisplayName'),
        resourceDisplayName: col(cells, 'resourceDisplayName'),
        resourceId: '',
        servicePrincipalId: col(cells, 'servicePrincipalId'),
        servicePrincipalName: spName,
        appId: col(cells, 'appId'),
        credentialType: source === 'application' ? spCredentialType({
          clientCredentialType: col(cells, 'clientCredentialType'),
          federatedCredentialId: col(cells, 'federatedCredentialId'),
          servicePrincipalCredentialThumbprint: col(cells, 'servicePrincipalCredentialThumbprint'),
          servicePrincipalCredentialKeyId: col(cells, 'servicePrincipalCredentialKeyId')
        }) : null,
        appOwnerTenantId: col(cells, 'appOwnerTenantId'),
        resourceOwnerTenantId: col(cells, 'resourceOwnerTenantId'),
        ipAddress: col(cells, 'ipAddress'),
        clientAppUsed: isWorkload ? '' : col(cells, 'clientAppUsed'),
        conditionalAccessStatus: normToken(col(cells, 'conditionalAccessStatus')),
        appliedPolicies: [],
        authenticationRequirement: normToken(col(cells, 'authenticationRequirement')),
        authMethods: method ? [method] : [],
        isCompliant: yesNo(col(cells, 'isCompliant')),
        isManaged: yesNo(col(cells, 'isManaged')),
        operatingSystem: col(cells, 'operatingSystem'),
        trustType: col(cells, 'trustType'),
        deviceName: col(cells, 'deviceName'),
        deviceId: col(cells, 'deviceId'),
        deviceOwnership: col(cells, 'deviceOwnership'),
        operatingSystemVersion: col(cells, 'operatingSystemVersion'),
        mdmAppId: col(cells, 'mdmAppId'),
        enrollmentProfileName: col(cells, 'enrollmentProfileName'),
        browser: col(cells, 'browser'),
        originalTransferMethod: '',
        homeTenantId: '',
        resourceTenantId: '',
        crossTenantAccessType: '',
        deviceState: yesNo(col(cells, 'isCompliant')) === true ? 'compliant'
          : yesNo(col(cells, 'isCompliant')) !== false ? 'unknown'
            : (col(cells, 'deviceName') || col(cells, 'deviceId') || col(cells, 'trustType'))
              ? (yesNo(col(cells, 'isManaged')) === true ? 'enrolledNotCompliant'
                : yesNo(col(cells, 'isManaged')) === false ? 'registeredNotCompliant' : 'unknown')
              : 'unregistered',
        incomingTokenType: '',
        country: locationText ? locationText.split(',').pop().trim() : '',
        city: locationText ? locationText.split(',')[0].trim() : '',
        region: '',
        riskLevelDuringSignIn: normToken(col(cells, 'riskLevelDuringSignIn')),
        riskLevelAggregated: normToken(col(cells, 'riskLevelAggregated')),
        riskState: normToken(col(cells, 'riskState')),
        errorCode,
        failureReason: '',
        success: statusText ? statusText === 'success' : errorCode === 0,
        isInteractive: null
      };
    });
    const groupedRows = records.filter(record => record.groupedEvidence).length;
    if (groupedRows) {
      const represented = records.reduce((sum, record) => sum + record.eventCount, 0);
      warnings.push(`${fileName || 'CSV export'} contains ${groupedRows} grouped row${groupedRows === 1 ? '' : 's'} representing ${represented.toLocaleString()} sign-in events. Volumes are weighted by the portal count; time sequencing remains limited to one observation per grouped row.`);
    }
    if (invalidGroupedCountRows) warnings.push(`${invalidGroupedCountRows} row(s) contained an invalid sign-in count and were conservatively treated as one represented event.`);
    return { records, warnings, format: 'csv', source, detectedBy };
  }

  function createSignInAgg() {
    return {
      total: 0,
      success: 0,
      failure: 0,
      interactive: 0,
      guests: 0,
      minTime: Infinity,
      maxTime: -Infinity,
      timeParseFailures: 0,
      importedRowCount: 0,
      groupedRowCount: 0,
      totals: { interactive: 0, nonInteractive: 0, application: 0 },
      sourceStats: {},
      users: new Map(),
      apps: new Map(),
      interactiveResources: new Map(),
      interactiveUsers: new Map(),
      countries: new Map(),
      sprayIps: new Map(),
      travel: new Map(),
      reportOnly: new Map(),
      spPrincipals: new Map(),
      spWithCountry: 0,
      windowsUndetermined: 0,
      // Diagnosis for ca-not-applied: was Conditional Access engaged at all, and if it was,
      // which condition stopped each policy matching?
      caGap: { notEngaged: 0, evaluated: 0, platformFlow: 0, conditions: new Map(), policies: new Map() },
      deviceGap: new Map(),
      deviceContext: {
        total: 0,
        bySource: new Map(),
        byState: new Map(LOG_DEVICE_CONTEXT_STATES.map(item => [item.id, 0])),
        findingStates: new Map(LOG_DEVICE_CONTEXT_STATES.slice(0, 3).map(item => [item.id, 0])),
        joinStates: new Map(),
        platforms: new Map(),
        ownership: new Map(),
        browsers: new Map(),
        clientApps: new Map(),
        attributes: new Set(),
        attributeValues: new Map(),
        deviceCodeFlows: 0,
        inboundGuests: 0,
        samples: []
      },
      tenantId: '',
      outboundB2B: { count: 0, users: new Map(), tenants: new Map() },
      guestDirectionUnknown: 0,
      policyInventory: new Map(),
      journey: {
        total: 0,
        sources: new Map(LOG_SOURCE_ORDER.map(key => [key, 0])),
        decisions: new Map(LOG_JOURNEY_DECISIONS.map(item => [item.id, 0])),
        outcomes: new Map(LOG_JOURNEY_OUTCOMES.map(item => [item.id, 0])),
        sourceDecision: new Map(),
        decisionOutcome: new Map(),
        routes: new Map(),
        coverageEvents: [],
        coverageEventRows: 0,
        coverageRepresentedEvents: 0,
        coverageRetainedRepresentedEvents: 0,
        coverageOmittedRows: 0,
        coverageOmittedRepresentedEvents: 0
      },
      coverageFacts: [],
      fieldsSeen: new Set(),
      tallies: {}
    };
  }

  function aggregateSignIns(records) {
    const agg = createSignInAgg();
    ingestSignIns(agg, records, 'interactive');
    return agg;
  }

  // Which tenant owns these logs. Members are, by definition, your own users, so the tenant
  // their sign-ins call home is yours. Needed to tell an inbound guest (external user
  // arriving at your tenant) from an outbound one (your user visiting another tenant) —
  // Entra labels BOTH userType "guest", because the label is relative to the resource tenant.
  function resolveTenantId(agg, records) {
    if (agg.tenantId) return;
    const votes = new Map();
    records.forEach(rec => {
      if (rec.userType === 'member' && rec.homeTenantId) {
        votes.set(rec.homeTenantId, (votes.get(rec.homeTenantId) || 0) + recordEventCount(rec));
      }
    });
    const top = [...votes.entries()].sort((a, b) => b[1] - a[1])[0];
    if (top) agg.tenantId = top[0];
  }

  // 'inbound'  — an external identity arriving at your tenant; your CA policies govern it.
  // 'outbound' — one of your users visiting another tenant; the OTHER tenant's CA governs
  //              access, and your control is Cross-Tenant Access outbound settings.
  // 'unknown'  — tenant ids absent (CSV export), so direction cannot be established.
  function guestDirection(agg, rec) {
    if (rec.userType !== 'guest') return '';
    if (!agg.tenantId || !rec.resourceTenantId) return 'unknown';
    if (rec.resourceTenantId === agg.tenantId) return 'inbound';
    return 'outbound';
  }

  function workloadOutsideCa(rec) {
    if (rec.identityType !== 'servicePrincipal') return '';
    const appOwner = String(rec.appOwnerTenantId || rec.homeTenantId || '').toLowerCase();
    const resourceOwner = String(rec.resourceOwnerTenantId || rec.resourceTenantId || '').toLowerCase();
    if (appOwner && resourceOwner && appOwner !== resourceOwner) {
      return 'The application owner tenant differs from the resource tenant, explicitly identifying a third-party or multitenant workload outside workload Conditional Access eligibility.';
    }
    return '';
  }

  function classifyLogJourneyDecision(rec, source) {
    const policies = rec.appliedPolicies || [];
    const hasEnforcing = rec.conditionalAccessStatus === 'success'
      || rec.conditionalAccessStatus === 'failure'
      || policies.some(policy => policy.result === 'success' || policy.result === 'failure');
    if (hasEnforcing) return 'enforcing';
    const hasReportOnlyMatch = policies.some(policy => policy.result.startsWith('reportonly') && policy.result !== 'reportonlynotapplied');
    if (hasReportOnlyMatch) return source === 'application' ? 'workloadReportOnly' : 'reportOnly';
    if (source === 'application' && workloadOutsideCa(rec)) return 'outsideCa';
    if (source === 'application' && !policies.length) return 'workloadBlindspot';
    if (isPlatformFlow(rec)) return 'byDesign';
    if (policies.some(policy => policy.result === 'notapplied' || policy.result === 'reportonlynotapplied')) {
      return source === 'application' ? 'workloadReview' : 'filtered';
    }
    return 'noEvaluation';
  }

  function classifyLogJourneyOutcome(rec, decision) {
    const blocked = rec.conditionalAccessStatus === 'failure'
      || (rec.appliedPolicies || []).some(policy => policy.result === 'failure');
    if (decision === 'enforcing' && blocked) return 'blocked';
    if (decision === 'enforcing' && rec.success) return 'protectedSuccess';
    if (decision === 'reportOnly' && rec.success) return 'allowedReportOnly';
    if (decision === 'workloadReportOnly' && rec.success) return 'workloadReportOnlyFlow';
    if (decision === 'byDesign' && rec.success) return 'byDesignFlow';
    if (decision === 'outsideCa' && rec.success) return 'outsideCaFlow';
    if (decision === 'workloadBlindspot' && rec.success) return 'workloadUnknownFlow';
    if (decision === 'workloadReview' && rec.success) return 'workloadReviewFlow';
    if ((decision === 'filtered' || decision === 'noEvaluation') && rec.success) return 'allowedWithoutCa';
    return 'otherFailure';
  }

  function caCoverageCategoryId(decision, outcome) {
    if (outcome === 'allowedWithoutCa' && decision === 'filtered') return 'confirmedGap';
    if ((decision === 'reportOnly' && outcome === 'allowedReportOnly')
      || (decision === 'workloadReportOnly' && outcome === 'workloadReportOnlyFlow')) return 'reportOnlyExposure';
    if ((decision === 'noEvaluation' && outcome === 'allowedWithoutCa')
      || (decision === 'workloadBlindspot' && outcome === 'workloadUnknownFlow')
      || (decision === 'workloadReview' && outcome === 'workloadReviewFlow')) return 'evidenceUnknown';
    if ((decision === 'byDesign' && outcome === 'byDesignFlow')
      || (decision === 'outsideCa' && outcome === 'outsideCaFlow')) return 'expectedOutsideCa';
    return '';
  }

  function recordCaCoverageEvent(journey, rec, source, decision, outcome, weight) {
    const category = caCoverageCategoryId(decision, outcome);
    if (!rec.success || !category) return;
    journey.coverageEventRows += 1;
    journey.coverageRepresentedEvents += weight;
    if (journey.coverageEvents.length >= LOG_COVERAGE_EVENT_ROW_CAP) {
      journey.coverageOmittedRows += 1;
      journey.coverageOmittedRepresentedEvents += weight;
      return;
    }
    const evaluatedPolicies = (rec.appliedPolicies || []).map(policy => ({
      name: policy.displayName || 'Unnamed policy',
      result: policy.result || 'not returned',
      conditions: (policy.conditionsNotSatisfied || []).slice(0, 12)
    }));
    journey.coverageEvents.push({
      time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString() : '',
      category,
      decision,
      outcome,
      source,
      identityType: rec.identityType || (source === 'application' ? 'servicePrincipal' : 'user'),
      principal: rec.principal || rec.userPrincipalName || rec.userDisplayName || 'Unknown identity',
      app: rec.resourceDisplayName || rec.appDisplayName || 'Unknown app or resource',
      clientApp: rec.appDisplayName && rec.resourceDisplayName && rec.appDisplayName !== rec.resourceDisplayName ? rec.appDisplayName : (rec.clientAppUsed || ''),
      device: logDeviceLabel(rec) || '',
      platform: [rec.operatingSystem, rec.operatingSystemVersion || rec.osVersion].filter(Boolean).join(' '),
      location: logLocationLabel(rec) || 'Unknown location',
      ip: rec.ipAddress || '',
      caStatus: rec.conditionalAccessStatus || 'not returned',
      authenticationRequirement: rec.authenticationRequirement || 'not returned',
      evaluatedPolicies,
      representedEvents: weight,
      groupedEvidence: Boolean(rec.groupedEvidence)
    });
    journey.coverageRetainedRepresentedEvents += weight;
  }

  function incrementJourneyMap(map, key, amount) {
    map.set(key, (map.get(key) || 0) + (amount || 1));
  }

  function logDeviceJoinState(rec) {
    const trust = normToken(rec.trustType);
    if (trust === 'serverad' || trust.includes('hybrid')) return 'Microsoft Entra hybrid joined';
    if (trust === 'azuread' || trust === 'entrajoined') return 'Microsoft Entra joined';
    if (trust === 'workplace' || trust.includes('registered')) return 'Microsoft Entra registered';
    if (rec.deviceId || rec.deviceName) return 'Registered, join type not returned';
    if (rec.deviceState === 'unregistered') return 'No device identity';
    return 'Join state not returned';
  }

  function recordDeviceContext(agg, rec, source) {
    if (rec.identityType !== 'user') return;
    const weight = recordEventCount(rec);
    const context = agg.deviceContext;
    const stateKey = LOG_DEVICE_CONTEXT_STATES.some(item => item.id === rec.deviceState) ? rec.deviceState : 'unknown';
    context.total += weight;
    incrementJourneyMap(context.bySource, source, weight);
    incrementJourneyMap(context.byState, stateKey, weight);
    if (rec.success && (LOG_CHECK_SOURCES['noncompliant-device'] || []).includes(source) && context.findingStates.has(stateKey)) {
      incrementJourneyMap(context.findingStates, stateKey, weight);
    }
    incrementJourneyMap(context.joinStates, logDeviceJoinState(rec), weight);
    incrementJourneyMap(context.platforms, rec.operatingSystem || 'Platform not returned', weight);
    incrementJourneyMap(context.ownership, rec.deviceOwnership || 'Ownership not returned', weight);
    incrementJourneyMap(context.browsers, rec.browser || 'Browser not returned', weight);
    incrementJourneyMap(context.clientApps, rec.clientAppUsed || 'Client app not returned', weight);
    if (normToken(rec.originalTransferMethod).includes('devicecode')) context.deviceCodeFlows += weight;
    if (rec.userType === 'guest' && guestDirection(agg, rec) !== 'outbound') context.inboundGuests += weight;
    const attributes = {
      isCompliant: rec.isCompliant,
      trustType: rec.trustType,
      deviceOwnership: rec.deviceOwnership,
      operatingSystemVersion: rec.operatingSystemVersion,
      mdmAppId: rec.mdmAppId,
      enrollmentProfileName: rec.enrollmentProfileName
    };
    Object.entries(attributes).forEach(([name, value]) => {
      const returned = typeof value === 'boolean' || (typeof value === 'string' && value.trim());
      if (!returned) return;
      context.attributes.add(name);
      if (!context.attributeValues.has(name)) context.attributeValues.set(name, new Map());
      incrementJourneyMap(context.attributeValues.get(name), typeof value === 'boolean' ? String(value) : value, weight);
    });
    if (context.samples.length < LOG_SAMPLE_CAP) {
      context.samples.push({
        time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString().replace('T', ' ').slice(0, 16) : 'unknown time',
        principal: rec.principal || 'unknown identity',
        app: rec.appDisplayName || rec.resourceDisplayName || 'unknown app',
        location: logLocationLabel(rec) || 'Unknown location',
        source,
        state: stateKey,
        joinState: logDeviceJoinState(rec),
        platform: rec.operatingSystem || 'not returned',
        ownership: rec.deviceOwnership || 'not returned',
        browser: rec.browser || rec.clientAppUsed || 'not returned',
        deviceId: rec.deviceId || '',
        representedEvents: weight
      });
    }
  }

  function recordLogJourneyEvent(agg, rec, source) {
    const weight = recordEventCount(rec);
    const journey = agg.journey;
    const decision = classifyLogJourneyDecision(rec, source);
    const outcome = classifyLogJourneyOutcome(rec, decision);
    const sourceDecisionKey = `${source}|${decision}`;
    const decisionOutcomeKey = `${decision}|${outcome}`;
    const routeKey = `${source}|${decision}|${outcome}`;
    recordCaCoverageEvent(journey, rec, source, decision, outcome, weight);
    journey.total += weight;
    incrementJourneyMap(journey.sources, source, weight);
    incrementJourneyMap(journey.decisions, decision, weight);
    incrementJourneyMap(journey.outcomes, outcome, weight);
    incrementJourneyMap(journey.sourceDecision, sourceDecisionKey, weight);
    incrementJourneyMap(journey.decisionOutcome, decisionOutcomeKey, weight);
    const route = journey.routes.get(routeKey) || {
      source,
      decision,
      outcome,
      count: 0,
      success: 0,
      failure: 0,
      policies: new Map(),
      evaluatedPolicies: new Map(),
      conditions: new Map(),
      identities: new Map(),
      apps: new Map(),
      locations: new Map(),
      samples: []
    };
    route.count += weight;
    route.success += rec.success ? weight : 0;
    route.failure += rec.success ? 0 : weight;
    incrementJourneyMap(route.identities, rec.principal || rec.userPrincipalName || rec.userDisplayName || 'Unknown identity', weight);
    incrementJourneyMap(route.apps, rec.appDisplayName || rec.resourceDisplayName || 'Unknown app', weight);
    incrementJourneyMap(route.locations, logLocationLabel(rec) || 'Unknown location', weight);
    (rec.appliedPolicies || []).forEach(policy => {
      incrementJourneyMap(route.evaluatedPolicies, policy.displayName, weight);
      const matched = policy.result === 'success' || policy.result === 'failure'
        || (policy.result.startsWith('reportonly') && policy.result !== 'reportonlynotapplied');
      if (matched) incrementJourneyMap(route.policies, policy.displayName, weight);
      (policy.conditionsNotSatisfied || []).forEach(condition => incrementJourneyMap(route.conditions, condition, weight));
    });
    if (route.samples.length < 8) {
      route.samples.push({
        time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString().replace('T', ' ').slice(0, 16) : 'unknown time',
        source,
        principal: rec.principal || rec.userPrincipalName || rec.userDisplayName || 'unknown identity',
        app: rec.appDisplayName || rec.resourceDisplayName || 'unknown app',
        location: logLocationLabel(rec) || 'Unknown location',
        caStatus: rec.conditionalAccessStatus || 'not returned',
        authenticationRequirement: rec.authenticationRequirement || 'not returned',
        representedEvents: weight,
        policies: (rec.appliedPolicies || []).slice(0, 8).map(policy => ({
          name: policy.displayName,
          result: policy.result,
          conditions: (policy.conditionsNotSatisfied || []).slice(0, 5)
        }))
      });
    }
    journey.routes.set(routeKey, route);
  }

  function ingestSignIns(agg, records, source) {
    const isUserSource = LOG_SOURCES[source].kind === 'user';
    if (isUserSource) resolveTenantId(agg, records);
    const representedTotal = records.reduce((sum, record) => sum + recordEventCount(record), 0);
    agg.importedRowCount += records.length;
    agg.groupedRowCount += records.filter(record => record.groupedEvidence).length;
    agg.total += representedTotal;
    agg.totals[source] += representedTotal;
    if (!agg.sourceStats[source]) {
      agg.sourceStats[source] = {
        total: 0, success: 0, failure: 0, guests: 0,
        users: new Set(), apps: new Set(),
        minTime: Infinity, maxTime: -Infinity,
        fieldsSeen: new Set()
      };
    }
    const stats = agg.sourceStats[source];
    stats.total += representedTotal;
    const tally = id => {
      if (!agg.tallies[id]) {
        agg.tallies[id] = { count: 0, users: new Map(), apps: new Map(), devices: new Map(), locations: new Map(), samples: [], sources: new Set(), platformFlow: 0 };
      }
      return agg.tallies[id];
    };
    const record = (id, rec, extra) => {
      const allowed = LOG_CHECK_SOURCES[id];
      if (allowed && !allowed.includes(rec.source)) return;
      const t = tally(id);
      const weight = recordEventCount(rec);
      t.count += weight;
      t.sources.add(rec.source);
      const who = rec.principal || rec.userPrincipalName || rec.userDisplayName || 'unknown identity';
      const app = rec.appDisplayName || rec.resourceDisplayName || 'unknown app';
      const device = logDeviceLabel(rec);
      const place = logLocationLabel(rec);
      t.users.set(who, (t.users.get(who) || 0) + weight);
      t.apps.set(app, (t.apps.get(app) || 0) + weight);
      if (device) t.devices.set(device, (t.devices.get(device) || 0) + weight);
      if (place) t.locations.set(place, (t.locations.get(place) || 0) + weight);
      if (isPlatformFlow(rec)) t.platformFlow += weight;
      if (t.samples.length < LOG_SAMPLE_CAP) {
        t.samples.push({
          time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString().replace('T', ' ').slice(0, 16) : 'unknown time',
          source: LOG_SOURCES[rec.source].short,
          principal: who,
          app,
          device: device || 'No device recorded',
          deviceDetail: [rec.osVersion || rec.operatingSystem, rec.browser, rec.trustType].filter(Boolean).join(' · '),
          posture: rec.isCompliant === null && rec.isManaged === null
            ? ''
            : `${rec.isCompliant ? 'compliant' : 'not compliant'} · ${rec.isManaged ? 'managed' : 'unmanaged'}`,
          location: place || 'Unknown location',
          ip: rec.ipAddress || '',
          clientApp: rec.clientAppUsed || '',
          note: extra || '',
          representedEvents: weight,
          // Triage facts — the per-event analysis fields, kept separate from the display
          // fields above so the evidence table stays regression-stable.
          t: {
            sourceKey: rec.source,
            authenticationRequirement: rec.authenticationRequirement,
            authMethods: rec.authMethods.slice(0, 6),
            appliedPolicies: rec.appliedPolicies.slice(0, 10).map(p => ({
              name: p.displayName, result: p.result, conditions: (p.conditionsNotSatisfied || []).slice()
            })),
            incomingTokenType: rec.incomingTokenType,
            deviceState: rec.deviceState,
            trustType: rec.trustType,
            isCompliant: rec.isCompliant,
            isManaged: rec.isManaged,
            deviceName: rec.deviceName,
            deviceId: rec.deviceId,
            deviceOwnership: rec.deviceOwnership,
            operatingSystemVersion: rec.operatingSystemVersion,
            mdmAppId: rec.mdmAppId,
            enrollmentProfileName: rec.enrollmentProfileName,
            browser: rec.browser,
            operatingSystem: rec.operatingSystem,
            osVersion: rec.osVersion,
            errorCode: rec.errorCode,
            failureReason: rec.failureReason || '',
            riskSignIn: rec.riskLevelDuringSignIn,
            riskAggregated: rec.riskLevelAggregated,
            userType: rec.userType,
            homeTenantId: rec.homeTenantId,
            resourceTenantId: rec.resourceTenantId,
            credentialType: rec.credentialType,
            appId: rec.appId,
            success: rec.success,
            platformFlow: isPlatformFlow(rec)
          }
        });
      }
    };
    const seen = field => { agg.fieldsSeen.add(field); stats.fieldsSeen.add(field); };
    records.forEach(rec => {
      const weight = recordEventCount(rec);
      recordLogJourneyEvent(agg, rec, source);
      recordDeviceContext(agg, rec, source);
      if (rec.success) { agg.success += weight; stats.success += weight; }
      else { agg.failure += weight; stats.failure += weight; }
      if (rec.isInteractive === true) agg.interactive += weight;
      // Count only guests arriving at YOUR tenant — an outbound sign-in is one of your own
      // members visiting elsewhere, and counting it as a guest overstates external access.
      if (rec.userType === 'guest' && guestDirection(agg, rec) !== 'outbound') { agg.guests += weight; stats.guests += weight; }
      if (Number.isFinite(rec.time)) {
        if (rec.time < agg.minTime) agg.minTime = rec.time;
        if (rec.time > agg.maxTime) agg.maxTime = rec.time;
        if (rec.time < stats.minTime) stats.minTime = rec.time;
        if (rec.time > stats.maxTime) stats.maxTime = rec.time;
      } else agg.timeParseFailures += weight;
      if (rec.conditionalAccessStatus) seen('conditionalAccessStatus');
      if (rec.authenticationRequirement) seen('authenticationRequirement');
      if (rec.appliedPolicies.length) seen('appliedPolicies');
      if (rec.userType) seen('userType');
      if (rec.isCompliant !== null || rec.isManaged !== null) seen('devicePosture');
      if (rec.deviceId || rec.deviceName || rec.trustType || rec.deviceState === 'unregistered') seen('deviceIdentity');
      if (rec.deviceOwnership) seen('deviceOwnership');
      if (rec.operatingSystemVersion) seen('operatingSystemVersion');
      if (rec.mdmAppId) seen('mdmAppId');
      if (rec.enrollmentProfileName) seen('enrollmentProfileName');
      if (rec.riskLevelDuringSignIn || rec.riskLevelAggregated) seen('riskLevels');
      if (rec.authMethods.length) seen('authMethods');
      const user = isUserSource ? rec.principal : '';
      const app = rec.appDisplayName || rec.resourceDisplayName;
      const caApplied = rec.conditionalAccessStatus === 'success' || rec.conditionalAccessStatus === 'failure';
      if (user) stats.users.add(user);
      if (app) stats.apps.add(app);
      if (isUserSource && user) {
        const u = agg.users.get(user) || { count: 0, caApplied: 0 };
        u.count += weight;
        if (caApplied) u.caApplied += weight;
        agg.users.set(user, u);
      }
      if (isUserSource && app) {
        const a = agg.apps.get(app) || { count: 0, success: 0, caApplied: 0 };
        a.count += weight;
        if (rec.success) a.success += weight;
        if (caApplied) a.caApplied += weight;
        agg.apps.set(app, a);
      }
      // Coverage checks are interactive-only (their thresholds are calibrated on interactive
      // volume) and must exclude bootstrap flows, which Conditional Access never evaluates.
      // Keyed on the RESOURCE, because Conditional Access targets resources, not client apps.
      if (source === 'interactive' && !isPlatformFlow(rec)) {
        const resource = rec.resourceDisplayName || rec.appDisplayName;
        if (resource) {
          const r = agg.interactiveResources.get(resource) || { count: 0, success: 0, caApplied: 0, clients: new Map() };
          r.count += weight;
          if (rec.success) r.success += weight;
          if (caApplied) r.caApplied += weight;
          const client = rec.appDisplayName || 'unknown client';
          r.clients.set(client, (r.clients.get(client) || 0) + weight);
          agg.interactiveResources.set(resource, r);
        }
        if (user) {
          const iu = agg.interactiveUsers.get(user) || { count: 0, caApplied: 0 };
          iu.count += weight;
          if (caApplied) iu.caApplied += weight;
          agg.interactiveUsers.set(user, iu);
        }
      }
      if (isUserSource && rec.country) agg.countries.set(rec.country, (agg.countries.get(rec.country) || 0) + weight);
      if (isUserSource && rec.errorCode === 50126 && rec.ipAddress && agg.sprayIps.size < 5000) {
        const ip = agg.sprayIps.get(rec.ipAddress) || { users: new Set(), count: 0 };
        if (user) ip.users.add(user);
        ip.count += weight;
        agg.sprayIps.set(rec.ipAddress, ip);
      }
      if (isUserSource && user && rec.country && Number.isFinite(rec.time)) {
        const timeline = agg.travel.get(user) || [];
        const last = timeline[timeline.length - 1];
        if ((!last || last.country !== rec.country) && timeline.length < 1000) {
          timeline.push({ time: rec.time, country: rec.country });
          agg.travel.set(user, timeline);
        }
      }
      if (source === 'application') {
        const name = rec.servicePrincipalName || rec.principal;
        const sp = agg.spPrincipals.get(name) || {
          id: rec.servicePrincipalId, count: 0, success: 0, failure: 0, caApplied: 0, reportOnly: 0,
          evaluatedNoMatch: 0, noPolicyDetail: 0, outsideCa: 0,
          countries: new Map(), credential: { federated: 0, certificate: 0, secret: 0, managedIdentity: 0, unknown: 0 },
          resources: new Map(), credErrors: new Map()
        };
        sp.count += weight;
        if (rec.success) sp.success += weight; else sp.failure += weight;
        if (caApplied) sp.caApplied += weight;
        const hasReportOnlyMatch = rec.appliedPolicies.some(policy => policy.result.startsWith('reportonly') && policy.result !== 'reportonlynotapplied');
        const hasEvaluatedNoMatch = rec.appliedPolicies.some(policy => policy.result === 'notapplied' || policy.result === 'reportonlynotapplied');
        const explicitlyOutsideCa = workloadOutsideCa(rec);
        if (hasReportOnlyMatch && rec.success) sp.reportOnly += weight;
        else if (hasEvaluatedNoMatch) sp.evaluatedNoMatch += weight;
        else if (!rec.appliedPolicies.length) sp.noPolicyDetail += weight;
        if (explicitlyOutsideCa) sp.outsideCa += weight;
        if (rec.country) { sp.countries.set(rec.country, (sp.countries.get(rec.country) || 0) + weight); agg.spWithCountry += weight; }
        if (rec.credentialType && rec.credentialType in sp.credential) sp.credential[rec.credentialType] += weight;
        if (rec.resourceDisplayName) sp.resources.set(rec.resourceDisplayName, (sp.resources.get(rec.resourceDisplayName) || 0) + weight);
        if (!rec.success && LOG_SP_CREDENTIAL_ERRORS.has(rec.errorCode)) {
          sp.credErrors.set(rec.errorCode, (sp.credErrors.get(rec.errorCode) || 0) + weight);
        }
        agg.spPrincipals.set(name, sp);
        if (hasReportOnlyMatch && rec.success) {
          record('sp-report-only', rec, 'A matching workload Conditional Access policy remained report-only, so it recorded intent without enforcing the configured control.');
        }
        if (hasEvaluatedNoMatch) {
          record('sp-ca-review', rec, 'Workload Conditional Access policies were evaluated but did not match this event. Review scope and eligibility before treating it as a gap.');
        }
      }
      rec.appliedPolicies.forEach(policy => {
        if (policy.result.startsWith('reportonly')) {
          const entry = agg.reportOnly.get(policy.displayName) || { total: 0, wouldBlockOrGrant: 0 };
          entry.total += weight;
          if (policy.result === 'reportonlyfailure' || policy.result === 'reportonlyinterrupted') entry.wouldBlockOrGrant += weight;
          agg.reportOnly.set(policy.displayName, entry);
        }
        // Deployed-policy inventory: what exists in the tenant, how often it fires, on what.
        const inv = agg.policyInventory.get(policy.displayName) || {
          id: policy.id, name: policy.displayName,
          evaluations: 0, applied: 0, blocked: 0, reportOnly: 0, notApplied: 0,
          grants: new Map(), sessions: new Map(), authStrength: new Map(),
          reportOnlyResults: new Map(),
          users: new Map(), apps: new Map(), devices: new Map(), locations: new Map(),
          notSatisfied: new Map(), sources: new Set(), samples: [],
          includeRules: new Map(), excludeRules: new Map(), excludedPrincipals: new Map(),
          exclusionIdentityDetails: new Map(), exclusionSamples: [], excludedEventCount: 0,
          minTime: Infinity, maxTime: -Infinity
        };
        inv.evaluations += weight;
        inv.sources.add(rec.source);
        if (!inv.id && policy.id) inv.id = policy.id;
        if (Number.isFinite(rec.time)) {
          if (rec.time < inv.minTime) inv.minTime = rec.time;
          if (rec.time > inv.maxTime) inv.maxTime = rec.time;
        }
        const enforced = policy.result === 'success' || policy.result === 'failure';
        if (enforced) inv.applied += weight;
        if (policy.result === 'failure') inv.blocked += weight;
        if (policy.result.startsWith('reportonly')) {
          inv.reportOnly += weight;
          incrementJourneyMap(inv.reportOnlyResults, policy.result, weight);
        }
        if (policy.result === 'notapplied') {
          inv.notApplied += weight;
          policy.conditionsNotSatisfied.forEach(cond => {
            const key = normToken(cond);
            inv.notSatisfied.set(key, (inv.notSatisfied.get(key) || 0) + weight);
          });
        }
        policy.includeRules.forEach(r => {
          const k = `${r.condition}|${r.rule}`;
          inv.includeRules.set(k, (inv.includeRules.get(k) || 0) + weight);
        });
        policy.excludeRules.forEach(r => {
          const k = `${r.condition}|${r.rule}`;
          inv.excludeRules.set(k, (inv.excludeRules.get(k) || 0) + weight);
        });
        const identityExclusionRules = policy.excludeRules.filter(r => normToken(r.condition) === 'users');
        if (identityExclusionRules.length) {
          const who = rec.principal || 'unknown identity';
          const identityKey = rec.userId || `${rec.identityType || 'identity'}:${who}`;
          const app = rec.appDisplayName || rec.resourceDisplayName || 'unknown app';
          const place = logLocationLabel(rec) || 'Unknown location';
          const detail = inv.exclusionIdentityDetails.get(identityKey) || {
            name: who,
            objectId: rec.userId || '',
            identityType: rec.identityType || 'user',
            userType: rec.userType || '',
            count: 0,
            rules: new Map(),
            apps: new Map(),
            locations: new Map(),
            sources: new Set(),
            minTime: Infinity,
            maxTime: -Infinity
          };
          detail.count += weight;
          identityExclusionRules.forEach(r => incrementJourneyMap(detail.rules, r.rule, weight));
          incrementJourneyMap(detail.apps, app, weight);
          incrementJourneyMap(detail.locations, place, weight);
          detail.sources.add(rec.source);
          if (Number.isFinite(rec.time)) {
            if (rec.time < detail.minTime) detail.minTime = rec.time;
            if (rec.time > detail.maxTime) detail.maxTime = rec.time;
          }
          inv.exclusionIdentityDetails.set(identityKey, detail);
          inv.excludedPrincipals.set(who, (inv.excludedPrincipals.get(who) || 0) + weight);
          inv.excludedEventCount += weight;
          if (inv.exclusionSamples.length < LOG_SAMPLE_CAP) {
            inv.exclusionSamples.push({
              time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString() : '',
              source: LOG_SOURCES[rec.source].short,
              principal: who,
              objectId: rec.userId || '',
              identityType: rec.identityType || 'user',
              userType: rec.userType || '',
              app,
              location: place,
              ipAddress: rec.ipAddress || '',
              clientApp: rec.clientAppUsed || '',
              result: policy.result,
              rules: identityExclusionRules.map(r => LOG_RULE_LABELS[normToken(r.rule)] || r.rule),
              representedEvents: weight
            });
          }
        }
        policy.grants.forEach(g => inv.grants.set(g, (inv.grants.get(g) || 0) + weight));
        policy.sessions.forEach(s => inv.sessions.set(s, (inv.sessions.get(s) || 0) + weight));
        if (policy.authStrength) inv.authStrength.set(policy.authStrength, (inv.authStrength.get(policy.authStrength) || 0) + weight);
        // Who/what actually hits it — only counted where the policy really engaged.
        if (enforced || policy.result.startsWith('reportonly')) {
          const who = rec.principal || 'unknown identity';
          const app = rec.appDisplayName || rec.resourceDisplayName || 'unknown app';
          const device = logDeviceLabel(rec);
          const place = logLocationLabel(rec);
          inv.users.set(who, (inv.users.get(who) || 0) + weight);
          inv.apps.set(app, (inv.apps.get(app) || 0) + weight);
          if (device) inv.devices.set(device, (inv.devices.get(device) || 0) + weight);
          if (place) inv.locations.set(place, (inv.locations.get(place) || 0) + weight);
          if (inv.samples.length < LOG_SAMPLE_CAP) {
            inv.samples.push({
              time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString().replace('T', ' ').slice(0, 16) : 'unknown time',
              source: LOG_SOURCES[rec.source].short,
              principal: who,
              app,
              device: device || 'No device recorded',
              deviceDetail: [rec.osVersion || rec.operatingSystem, rec.browser, rec.trustType].filter(Boolean).join(' · '),
              posture: rec.isCompliant === null && rec.isManaged === null
                ? ''
                : `${rec.isCompliant ? 'compliant' : 'not compliant'} · ${rec.isManaged ? 'managed' : 'unmanaged'}`,
              location: place || 'Unknown location',
              ip: rec.ipAddress || '',
              clientApp: rec.clientAppUsed || '',
              result: policy.result,
              representedEvents: weight,
              grants: policy.grants.slice(0, 6),
              sessions: policy.sessions.slice(0, 6)
            });
          }
        }
        agg.policyInventory.set(policy.displayName, inv);
      });
      // Retain a bounded set of compact facts so ANY policy set can be simulated after
      // ingest — including the consolidated policies, which are only known once the
      // findings have produced a recommended strategy. Nine short fields per record,
      // capped, so memory stays flat on very large exports.
      if (agg.coverageFacts.length < LOG_COVERAGE_CAP) {
        agg.coverageFacts.push({
          // User-scoped policies never apply to workload identities and vice versa, so the
          // identity class decides whether a policy is even applicable to this sign-in.
          identityType: rec.identityType,
          userType: rec.userType,
          appId: rec.appId,
          clientAppUsed: rec.clientAppUsed,
          operatingSystem: rec.operatingSystem,
          // Needed to name the real Windows version: Entra labels Windows 11 as "Windows10",
          // and only the build number separates them.
          osBuild: rec.osBuild,
          riskLevelDuringSignIn: rec.riskLevelDuringSignIn,
          riskLevelAggregated: rec.riskLevelAggregated,
          originalTransferMethod: rec.originalTransferMethod,
          principal: rec.principal,
          app: rec.appDisplayName || rec.resourceDisplayName || 'unknown app',
          source: LOG_SOURCES[rec.source].short,
          eventCount: weight,
          time: Number.isFinite(rec.time) ? new Date(rec.time).toISOString().replace('T', ' ').slice(0, 16) : 'unknown time'
        });
      }
      const clientNorm = normToken(rec.clientAppUsed);
      if (clientNorm && LEGACY_CLIENT_APPS.has(clientNorm)) record('legacy-auth', rec, rec.clientAppUsed);
      if (rec.success && rec.authenticationRequirement === 'singlefactorauthentication') record('single-factor-success', rec);
      if (rec.success && rec.conditionalAccessStatus === 'notapplied') {
        record('ca-not-applied', rec, describeCaGap(agg, rec));
      }
      if (rec.authMethods.some(m => WEAK_MFA_METHODS.some(w => m.includes(w)))) record('weak-mfa', rec, rec.authMethods.join(', '));
      // Any sign-in whose device posture cannot be vouched for — not just unmanaged ones.
      // An enrolled device actively failing a compliance rule was previously missed entirely.
      if (rec.success && (rec.deviceState === 'unregistered' || rec.deviceState === 'registeredNotCompliant' || rec.deviceState === 'enrolledNotCompliant')) {
        record('noncompliant-device', rec, describeDeviceGap(agg, rec));
      }
      const riskLevel = ['high', 'medium'].find(level => rec.riskLevelDuringSignIn === level || rec.riskLevelAggregated === level);
      if (rec.success && riskLevel) record('risky-signin-success', rec, `${riskLevel} risk`);
      const direction = guestDirection(agg, rec);
      if (direction === 'outbound') {
        // Your own user visiting another tenant. Your Conditional Access does not govern
        // access over there, so this is never a gap in YOUR policy set.
        agg.outboundB2B.count += weight;
        agg.outboundB2B.users.set(rec.principal, (agg.outboundB2B.users.get(rec.principal) || 0) + weight);
        if (rec.resourceTenantId) agg.outboundB2B.tenants.set(rec.resourceTenantId, (agg.outboundB2B.tenants.get(rec.resourceTenantId) || 0) + weight);
        record('outbound-b2b', rec, `to tenant ${(rec.resourceTenantId || '').slice(0, 8)}`);
      } else if ((direction === 'inbound' || direction === 'unknown')
        && (rec.conditionalAccessStatus === 'notapplied' || (rec.success && rec.authenticationRequirement === 'singlefactorauthentication'))) {
        if (direction === 'unknown') agg.guestDirectionUnknown += weight;
        record('guest-uncontrolled', rec);
      }
      if (rec.operatingSystem) {
        if (/windows/i.test(rec.operatingSystem)) {
          // Never trust the "Windows10" string — only the build number can tell 10 from 11.
          const version = windowsVersionFromBuild(rec.osBuild);
          if (!version) agg.windowsUndetermined += weight;
          else if (version.eol) record('outdated-os', rec, `${version.label} — ${version.reason}`);
        } else {
          const eol = LOG_EOL_OS_PATTERNS.find(p => p.re.test(rec.operatingSystem));
          if (eol) record('outdated-os', rec, `${rec.operatingSystem} — ${eol.label}`);
        }
      }
    });
    return agg;
  }

  // Windows/device-plumbing sign-ins that Conditional Access does not govern: primary refresh
  // token issuance, device registration and the broker. These legitimately show notApplied and
  // are separated out so they don't send you chasing a gap that cannot be closed with policy.
  // Microsoft calls these "bootstrap scenarios": sign-ins exempted from Conditional Access
  // evaluation to avoid a circular dependency (device registration, device compliance, NPS
  // connectors), plus the Windows sign-in process itself — "Conditional Access policies
  // protect sign-in attempts to cloud resources, not the device sign-in process".
  // Deliberately NOT listed: "Windows Azure Active Directory". That is the directory
  // *resource* on huge volumes of perfectly ordinary sign-ins; treating it as plumbing
  // would mask real gaps.
  const LOG_PLATFORM_APPS = new Set([
    'windowssignin', 'microsoftauthenticationbroker', 'microsoftdeviceregistrationclient',
    'deviceregistrationservice'
  ]);

  function isPlatformFlow(rec) {
    if (rec.incomingTokenType === 'primaryrefreshtoken') return true;
    // Check both: a bootstrap event can carry the service as its resource with no app name.
    return LOG_PLATFORM_APPS.has(normToken(rec.appDisplayName))
      || LOG_PLATFORM_APPS.has(normToken(rec.resourceDisplayName));
  }

  // Human-readable names for the Entra condition tokens in conditionsNotSatisfied.
  // Keys are normToken() of the Graph `conditionalAccessConditions` enum members exactly as
  // documented: none, application, users, devicePlatform, location, clientType, signInRisk,
  // userRisk, time, deviceState, client, ipAddressSeenByAzureAD, ipAddressSeenByResourceProvider,
  // servicePrincipals, servicePrincipalRisk, authenticationFlows, insiderRisk.
  const LOG_CA_CONDITIONS = {
    users: 'the user was not in scope (assignment)',
    application: 'the resource was not in scope (target resources)',
    clienttype: 'the client app type was not in scope',
    userrisk: 'the user risk level condition was not met',
    signinrisk: 'the sign-in risk level condition was not met',
    deviceplatform: 'the device platform was not in scope',
    location: 'the location condition was not met',
    devicestate: 'the device state condition was not met (this condition is deprecated — use Filter for devices)',
    client: 'the client condition was not met',
    time: 'the time-based condition was not met',
    authenticationflows: 'the authentication flow was not in scope',
    serviceprincipals: 'the service principal was not in scope',
    serviceprincipalrisk: 'the service principal risk condition was not met',
    insiderrisk: 'the insider risk condition was not met',
    ipaddressseenbyazuread: 'the IP address seen by Entra ID was not in scope',
    ipaddressseenbyresourceprovider: 'the IP address seen by the resource provider was not in scope'
  };

  // Classifies WHY a sign-in ended up with no Conditional Access applied. Two very different
  // causes: CA was never engaged (empty policy list), or policies ran but every one was
  // filtered out by a condition — in which case Entra names the condition.
  function describeCaGap(agg, rec) {
    // This mutates counters, and it is called as an argument to record() — which applies its
    // own source guard only after arguments are evaluated. Guard here too, or workload
    // sign-ins (which are almost all notApplied) inflate the user-scoped diagnosis.
    const allowed = LOG_CHECK_SOURCES['ca-not-applied'];
    if (allowed && !allowed.includes(rec.source)) return '';
    const gap = agg.caGap;
    const weight = recordEventCount(rec);
    const evaluated = rec.appliedPolicies.filter(p => p.result === 'notapplied');
    if (!rec.appliedPolicies.length) {
      gap.notEngaged += weight;
      if (isPlatformFlow(rec)) {
        gap.platformFlow += weight;
        return 'no policy evaluated — platform/token flow outside Conditional Access';
      }
      return 'no policy evaluated — Conditional Access was not engaged for this sign-in';
    }
    gap.evaluated += weight;
    const reasons = [];
    evaluated.forEach(p => {
      p.conditionsNotSatisfied.forEach(cond => {
        const key = normToken(cond);
        gap.conditions.set(key, (gap.conditions.get(key) || 0) + weight);
        const pkey = `${p.displayName} — ${LOG_CA_CONDITIONS[key] || cond}`;
        gap.policies.set(pkey, (gap.policies.get(pkey) || 0) + weight);
        if (reasons.length < 2) reasons.push(`${p.displayName}: ${LOG_CA_CONDITIONS[key] || cond}`);
      });
    });
    return reasons.length
      ? `closest policy — ${reasons.join('; ')}`
      : `${evaluated.length} policy(ies) evaluated, none matched`;
  }

  const LOG_DEVICE_STATES = {
    unregistered: {
      label: 'No device identity at all',
      detail: 'the sign-in carried no device object — the machine or browser session is not joined or registered, so Entra has nothing to evaluate'
    },
    registeredNotCompliant: {
      label: 'Registered, but not enrolled in management',
      detail: 'the device has an identity in Entra but is not Intune-managed, so no compliance policy evaluates it'
    },
    enrolledNotCompliant: {
      label: 'Enrolled but failing compliance',
      detail: 'the device is managed and a compliance policy did evaluate it — and it failed'
    }
  };

  // Same shape of mistake as the notApplied conflation: "non-compliant" covers three very
  // different situations with three different fixes. Classify rather than merge them.
  function describeDeviceGap(agg, rec) {
    const allowed = LOG_CHECK_SOURCES['noncompliant-device'];
    if (allowed && !allowed.includes(rec.source)) return '';
    const meta = LOG_DEVICE_STATES[rec.deviceState];
    if (!meta) return '';
    agg.deviceGap.set(rec.deviceState, (agg.deviceGap.get(rec.deviceState) || 0) + recordEventCount(rec));
    return meta.label.toLowerCase();
  }

  function logDeviceLabel(rec) {
    if (rec.deviceName) return rec.deviceName;
    // Prefer the build-resolved version — rec.operatingSystem says "Windows10" on Windows 11.
    if (rec.osVersion) return `Unnamed ${rec.osVersion.replace(/\s*\(build \d+\)/, '')} device`;
    if (rec.operatingSystem) return `Unnamed ${rec.operatingSystem} device`;
    return '';
  }

  function logLocationLabel(rec) {
    return [rec.city, rec.region, rec.country].filter(Boolean).join(', ');
  }

  function logSourceTotal(agg, sources) {
    return (sources || LOG_SOURCE_ORDER).reduce((sum, key) => sum + (agg.totals[key] || 0), 0);
  }

  function logScopeLabel(agg, sources) {
    const present = (sources || LOG_SOURCE_ORDER).filter(key => agg.totals[key] > 0);
    const loaded = LOG_SOURCE_ORDER.filter(key => agg.totals[key] > 0);
    if (!present.length || present.length === loaded.length) return 'sign-ins';
    if (present.length === 1) return LOG_SOURCES[present[0]].scope;
    const names = present.map(key => LOG_SOURCES[key].short.toLowerCase());
    const last = names.pop();
    return `${names.join(', ')} and ${last} sign-ins`;
  }

  function policiesForControlIds(controlIds) {
    const ids = [...new Set(controlIds.flatMap(id => (CONTROLS[id] ? CONTROLS[id].policyIds : [])))];
    return ids.map(id => {
      const item = baselinePolicies().find(policy => policy.id === id);
      return item ? { id: item.id, displayName: item.displayName, summary: item.summary } : { id, displayName: id, summary: '' };
    });
  }

  function logPct(count, total) {
    if (!total) return 0;
    return Math.round((count / total) * 1000) / 10;
  }

  const CONTROL_LABELS = {
    mfa: 'Require multifactor authentication',
    block: 'Block access',
    compliantDevice: 'Require device to be marked compliant',
    domainJoinedDevice: 'Require Microsoft Entra hybrid joined device',
    approvedApplication: 'Require approved client app',
    compliantApplication: 'Require app protection policy',
    passwordChange: 'Require password change'
  };

  // Plain-language summary of what a baseline policy actually configures, read from the
  // pinned Graph JSON so the guidance always matches the policy the tool would export.
  function policyFixSettings(item) {
    const p = item.policy || {};
    const c = p.conditions || {};
    const users = c.users || {};
    const apps = c.applications || {};
    const grant = p.grantControls || {};
    const session = p.sessionControls || {};
    const rows = [];
    const list = v => (Array.isArray(v) ? v : []).filter(Boolean);
    const named = ids => ids.map(id => (id === 'All' ? 'All' : id === 'None' ? 'None' : objectName(id))).join(', ');

    const include = [];
    if (list(users.includeUsers).length) include.push(list(users.includeUsers).includes('All') ? 'All users' : `${list(users.includeUsers).length} named user(s)`);
    if (list(users.includeGroups).length) include.push(`${list(users.includeGroups).length} group(s)`);
    if (list(users.includeRoles).length) include.push(`${list(users.includeRoles).length} directory role(s)`);
    if (users.includeGuestsOrExternalUsers) include.push('Guest and external users');
    const exclude = [];
    if (list(users.excludeGroups).length) exclude.push(`${list(users.excludeGroups).length} group(s)`);
    if (list(users.excludeUsers).length) exclude.push(`${list(users.excludeUsers).length} user(s)`);
    if (list(users.excludeRoles).length) exclude.push(`${list(users.excludeRoles).length} role(s)`);
    rows.push({
      label: 'Assign to',
      value: include.length ? include.join(' + ') : 'Not set',
      note: exclude.length ? `Excluding ${exclude.join(', ')}${(item.requiredObjects || []).length ? ` — ${item.requiredObjects.join(', ')}` : ''}` : ''
    });

    if (list(apps.includeApplications).length) {
      rows.push({
        label: 'Target resources',
        value: list(apps.includeApplications).includes('All') ? 'All cloud apps' : named(list(apps.includeApplications)),
        note: list(apps.excludeApplications).length ? `Excluding ${named(list(apps.excludeApplications))}` : ''
      });
    }

    const conditions = [];
    if (list(c.clientAppTypes).length && !list(c.clientAppTypes).includes('all')) conditions.push(`Client apps: ${list(c.clientAppTypes).join(', ')}`);
    if (list(c.signInRiskLevels).length) conditions.push(`Sign-in risk: ${list(c.signInRiskLevels).join(', ')}`);
    if (list(c.userRiskLevels).length) conditions.push(`User risk: ${list(c.userRiskLevels).join(', ')}`);
    if (c.platforms) {
      const inc = list(c.platforms.includePlatforms).join(', ');
      const exc = list(c.platforms.excludePlatforms).join(', ');
      conditions.push(`Platforms: include ${inc || 'any'}${exc ? `, exclude ${exc}` : ''}`);
    }
    if (c.locations) {
      const inc = list(c.locations.includeLocations).join(', ');
      const exc = list(c.locations.excludeLocations).join(', ');
      conditions.push(`Locations: include ${inc || 'any'}${exc ? `, exclude ${exc}` : ''}`);
    }
    if (conditions.length) rows.push({ label: 'Conditions', value: conditions.join(' · '), note: '' });

    const controls = grantSummary(item);
    if (controls.length) {
      rows.push({
        label: 'Grant',
        value: controls.join(` ${String(grant.operator || 'OR').toUpperCase()} `),
        note: controls.includes('Block access') ? 'This policy blocks — test in report-only before enabling.' : ''
      });
    }

    const sessions = [];
    if (session.signInFrequency && session.signInFrequency.value) sessions.push(`Sign-in frequency: ${session.signInFrequency.value} ${session.signInFrequency.type || ''}`.trim());
    if (session.persistentBrowser && session.persistentBrowser.mode) sessions.push(`Persistent browser: ${session.persistentBrowser.mode}`);
    if (session.applicationEnforcedRestrictions && session.applicationEnforcedRestrictions.isEnabled) sessions.push('App-enforced restrictions on');
    if (session.cloudAppSecurity && session.cloudAppSecurity.cloudAppSecurityType) sessions.push(`Conditional Access App Control: ${session.cloudAppSecurity.cloudAppSecurityType}`);
    if (sessions.length) rows.push({ label: 'Session', value: sessions.join(' · '), note: '' });

    if ((item.prerequisites || []).length) rows.push({ label: 'Before you enable', value: item.prerequisites.join('; '), note: '' });
    return rows;
  }

  function objectName(id) {
    const entry = [...state.objectCatalog.values()].find(o => o.id === id);
    if (entry) return entry.name;
    const stat = STATIC_OBJECT_LOOKUP.get(objectCatalogKey(id, 'application'));
    if (stat) return stat.name;
    return id;
  }

  // What a policy would enforce once its conditions match — shared vocabulary between the
  // policy settings table and the per-event simulation.
  function grantSummary(item) {
    const grant = (item.policy || {}).grantControls || {};
    const session = (item.policy || {}).sessionControls || {};
    const out = (Array.isArray(grant.builtInControls) ? grant.builtInControls : []).map(ctrl => CONTROL_LABELS[ctrl] || ctrl);
    if (grant.authenticationStrength && grant.authenticationStrength.displayName) {
      out.push(`Authentication strength: ${grant.authenticationStrength.displayName}`);
    }
    if (session.signInFrequency && session.signInFrequency.value) {
      out.push(`Sign-in frequency limit: ${session.signInFrequency.value} ${session.signInFrequency.type || ''}`.trim());
    }
    if (session.persistentBrowser && session.persistentBrowser.mode) {
      out.push(`Persistent browser: ${session.persistentBrowser.mode}`);
    }
    return out;
  }

  // ---- Per-sign-in-event triage engine -------------------------------------------------
  // Given ONE evidence row, explain end-to-end what happened, name the root cause with a
  // confidence level, and name the one control that fixes THIS event. Confidence is
  // load-bearing: 'definite' = the log alone proves it; 'likely' = one stated assumption;
  // 'verify' = the log cannot distinguish two causes — portal steps are supplied instead
  // of advice that might be wrong.

  const LOG_TRIAGE_CONFIDENCE = {
    definite: { label: 'Definite', hint: 'the log alone proves this' },
    likely: { label: 'Likely', hint: 'strongly indicated — one assumption, stated in the narrative' },
    verify: { label: 'Verify first', hint: 'the log cannot distinguish two causes — check the portal before acting' }
  };

  // Maps an event's clientAppUsed string onto the Graph clientAppTypes condition tokens.
  // Maps clientAppUsed onto the Graph `conditionalAccessClientApp` enum:
  // all, browser, mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other.
  // Exchange ActiveSync must be tested BEFORE the generic legacy set, or it is coerced to
  // 'other' and never matches a policy that targets exchangeActiveSync specifically.
  function logClientAppType(sample) {
    const raw = normToken(sample.clientApp);
    if (!raw) return '';
    if (raw === 'browser') return 'browser';
    if (raw === 'mobileappsanddesktopclients' || raw === 'modernclients') return 'mobileAppsAndDesktopClients';
    if (raw === 'exchangeactivesync' || raw === 'exchangeactivesyncclients') return 'exchangeActiveSync';
    if (LEGACY_CLIENT_APPS.has(raw)) return 'other';
    return '';
  }

  // A human OS label for the environment summary. For Windows the reported string is
  // unreliable ("Windows10" covers 11 too), so prefer the build-derived version.
  function logOsLabel(fact) {
    const os = fact && fact.operatingSystem;
    if (!os) return '';
    if (/windows/i.test(os)) {
      const version = windowsVersionFromBuild(fact.osBuild);
      if (version) return version.label;
      return 'Windows (version not reported)';
    }
    return String(os);
  }

  function logPlatformToken(operatingSystem) {
    const os = normToken(operatingSystem);
    if (!os) return '';
    if (os.startsWith('windows')) return 'windows';
    if (os.startsWith('macos') || os.startsWith('osx')) return 'macOS';
    if (os.startsWith('ios')) return 'iOS';
    if (os.startsWith('android')) return 'android';
    if (os.startsWith('linux')) return 'linux';
    return '';
  }

  // Statically evaluates a pinned BASELINE policy against one event. Every leg reports
  // matched true/false/null — null means "not verifiable from sign-in logs" and always
  // carries a note. The output is a recommendation simulation, never tenant fact.
  function simulateBaselinePolicy(item, sample) {
    const t = sample.t || {};
    const c = (item.policy || {}).conditions || {};
    const list = v => (Array.isArray(v) ? v : []).filter(Boolean);
    const chain = [];
    const caveats = [];
    const push = (condition, eventValue, policyValue, matched, note) =>
      chain.push({ condition, eventValue: String(eventValue), policyValue: String(policyValue), matched, note: note || '' });

    const users = c.users || {};
    if (list(users.includeUsers).includes('All')) {
      push('User assignment', sample.principal, 'All users', true);
    } else if (users.includeGuestsOrExternalUsers) {
      if (t.userType === 'guest') push('User assignment', `${sample.principal} (guest)`, 'Guest and external users', true);
      else if (!t.userType) push('User assignment', sample.principal, 'Guest and external users', null, 'the user type is not present in this export');
      else push('User assignment', `${sample.principal} (${t.userType})`, 'Guest and external users', false);
    } else if (list(users.includeGroups).length || list(users.includeRoles).length) {
      const bits = [];
      if (list(users.includeGroups).length) bits.push(`${list(users.includeGroups).length} group(s)`);
      if (list(users.includeRoles).length) bits.push(`${list(users.includeRoles).length} directory role(s)`);
      push('User assignment', sample.principal, bits.join(' + '), null,
        'group and role membership cannot be verified from sign-in logs — check the assignment in the portal');
    } else if (list(users.includeUsers).length) {
      push('User assignment', sample.principal, `${list(users.includeUsers).length} named user(s)`, null, 'named-user assignment — verify in the portal');
    }
    if (list(users.excludeGroups).length || list(users.excludeUsers).length || list(users.excludeRoles).length) {
      caveats.push("unless the account sits in the policy's exclusion group(s) — exclusions are not visible in sign-in logs");
    }

    const apps = c.applications || {};
    const includeApps = list(apps.includeApplications);
    if (includeApps.includes('All')) {
      push('Target resources', sample.app, 'All cloud apps', true);
    } else if (includeApps.length) {
      if (t.appId) {
        const hit = includeApps.some(id => String(id).toLowerCase() === String(t.appId).toLowerCase());
        push('Target resources', sample.app, includeApps.map(objectName).join(', '), hit);
      } else {
        push('Target resources', sample.app, includeApps.map(objectName).join(', '), null, 'the app id is not present in this export');
      }
    }
    const excludeApps = list(apps.excludeApplications);
    if (excludeApps.length) {
      if (t.appId && excludeApps.some(id => String(id).toLowerCase() === String(t.appId).toLowerCase())) {
        push('Excluded resources', sample.app, excludeApps.map(objectName).join(', '), false, 'this app is explicitly excluded from the policy');
      } else {
        caveats.push(`the policy excludes ${excludeApps.length} named app(s)`);
      }
    }

    const clientTypes = list(c.clientAppTypes);
    if (clientTypes.length && !clientTypes.map(normToken).includes('all')) {
      const eventType = logClientAppType(sample);
      if (!eventType) push('Client app types', sample.clientApp || 'not recorded', clientTypes.join(', '), null, 'the client app type is not present for this event');
      else push('Client app types', sample.clientApp || eventType, clientTypes.join(', '), clientTypes.map(normToken).includes(normToken(eventType)));
    }

    if (c.platforms) {
      const inc = list(c.platforms.includePlatforms);
      const exc = list(c.platforms.excludePlatforms);
      const token = logPlatformToken(t.operatingSystem);
      const policyValue = `include ${inc.join(', ') || 'any'}${exc.length ? `, exclude ${exc.join(', ')}` : ''}`;
      if (!token) push('Device platforms', t.operatingSystem || 'not recorded', policyValue, null, 'the device platform could not be determined from this event');
      else {
        const normInc = inc.map(normToken);
        const matched = exc.map(normToken).includes(normToken(token)) ? false
          : (!normInc.length || normInc.includes('all') || normInc.includes(normToken(token)));
        push('Device platforms', token, policyValue, matched);
      }
    }

    if (c.locations) {
      push('Locations', sample.location || 'unknown', 'named location list', null,
        'named locations are tenant objects the log does not carry — verify the location list in the portal');
    }

    if (list(c.signInRiskLevels).length) {
      const levels = list(c.signInRiskLevels);
      if (!t.riskSignIn) push('Sign-in risk', 'no risk data', levels.join(', '), null, 'risk levels need Entra ID P2 and appear in the JSON export');
      else push('Sign-in risk', t.riskSignIn, levels.join(', '), levels.map(normToken).includes(normToken(t.riskSignIn)));
    }
    if (list(c.userRiskLevels).length) {
      const levels = list(c.userRiskLevels);
      if (!t.riskAggregated) push('User risk', 'no risk data', levels.join(', '), null, 'risk levels need Entra ID P2 and appear in the JSON export');
      else push('User risk', t.riskAggregated, levels.join(', '), levels.map(normToken).includes(normToken(t.riskAggregated)));
    }

    chain.forEach(r => { if (r.matched === null && r.note) caveats.push(r.note); });
    const verdict = chain.some(r => r.matched === false) ? 'would-not-apply'
      : chain.some(r => r.matched === null) ? 'would-apply-if' : 'would-apply';
    return {
      policyId: item.id,
      displayName: item.displayName,
      matchChain: chain,
      verdict,
      caveats: [...new Set(caveats)],
      enforced: grantSummary(item)
    };
  }

  // Lean corpus evaluator: same rules as simulateBaselinePolicy but returns only a verdict,
  // with no chain allocation, so it can run against every record for every baseline policy.
  // Kept deliberately in step with simulateBaselinePolicy — the harness cross-checks the two
  // agree on every sampled event, which is what catches drift between them.
  // `sink` is optional. When passed, it collects WHY the verdict came out as it did, so the
  // UI can say "applies by admin role membership" instead of the useless "depends on group or
  // role membership". First reason wins — it is the one that actually decided the outcome.
  function coverageVerdict(item, rec, sink) {
    const c = (item.policy || {}).conditions || {};
    const list = v => (Array.isArray(v) ? v : []).filter(Boolean);
    let conditional = false;
    const why = (bucket, key) => { if (sink && !sink[bucket]) sink[bucket] = key; };
    const unknown = key => { conditional = true; why('c', key); };
    const nope = key => { why('n', key); return 'no'; };

    // Applicability comes before matching. A policy scoped through conditions.users cannot
    // apply to a service-principal sign-in at all — Conditional Access
    // covers workload identities only through conditions.clientApplications, under a separate
    // licence. Counting workload sign-ins against a user policy reported CA200C as matching
    // 100% of 4127 sign-ins when 3333 of them were service principals it could never touch.
    const isWorkload = rec.identityType === 'servicePrincipal';
    const workloadScoped = Boolean(c.clientApplications);
    if (isWorkload !== workloadScoped) return 'n/a';

    const users = c.users || {};
    if (list(users.includeUsers).includes('All')) { /* matches */ }
    else if (users.includeGuestsOrExternalUsers) {
      if (rec.userType === 'guest') { /* matches */ }
      else if (!rec.userType) unknown('guestType');
      else return nope('notGuest');
    } else if (list(users.includeRoles).length) unknown('roles');
    else if (list(users.includeGroups).length) unknown('groups');
    else if (list(users.includeUsers).length) unknown('namedUsers');

    const apps = c.applications || {};
    const includeApps = list(apps.includeApplications);
    if (includeApps.length && !includeApps.includes('All')) {
      if (!rec.appId) unknown('appUnknown');
      else if (!includeApps.some(id => String(id).toLowerCase() === String(rec.appId).toLowerCase())) return nope('appNotTargeted');
    }
    const excludeApps = list(apps.excludeApplications);
    if (excludeApps.length && rec.appId
      && excludeApps.some(id => String(id).toLowerCase() === String(rec.appId).toLowerCase())) return nope('appExcluded');

    const clientTypes = list(c.clientAppTypes);
    if (clientTypes.length && !clientTypes.map(normToken).includes('all')) {
      const eventType = logClientAppType({ clientApp: rec.clientAppUsed });
      if (!eventType) unknown('clientAppUnknown');
      else if (!clientTypes.map(normToken).includes(normToken(eventType))) return nope('clientAppType');
    }

    if (c.platforms) {
      const token = logPlatformToken(rec.operatingSystem);
      if (!token) unknown('platformUnknown');
      else {
        const inc = list(c.platforms.includePlatforms).map(normToken);
        if (list(c.platforms.excludePlatforms).map(normToken).includes(normToken(token))) return nope('platform');
        if (inc.length && !inc.includes('all') && !inc.includes(normToken(token))) return nope('platform');
      }
    }

    if (c.locations) unknown('locations');

    const signInRisk = list(c.signInRiskLevels);
    if (signInRisk.length) {
      if (!rec.riskLevelDuringSignIn) unknown('signInRiskUnknown');
      else if (!signInRisk.map(normToken).includes(normToken(rec.riskLevelDuringSignIn))) return nope('signInRisk');
    }
    const userRisk = list(c.userRiskLevels);
    if (userRisk.length) {
      if (!rec.riskLevelAggregated) unknown('userRiskUnknown');
      else if (!userRisk.map(normToken).includes(normToken(rec.riskLevelAggregated))) return nope('userRisk');
    }

    // Device code flow / authentication transfer. The log reports this as
    // originalTransferMethod, so it is genuinely checkable rather than assumed.
    if (c.authenticationFlows) {
      const methods = String(c.authenticationFlows.transferMethods || '').split(',').map(normToken).filter(Boolean);
      const used = normToken(rec.originalTransferMethod);
      if (!used) unknown('authFlowUnknown');
      else if (used === 'none' || !methods.includes(used)) return nope('authFlows');
    }

    // Device filter rules reference device object attributes (ownership, filters) that
    // sign-in logs do not carry in full.
    if (c.devices && c.devices.deviceFilter) unknown('deviceFilter');

    // Anything left that this evaluator does not understand must downgrade the verdict.
    // Silently ignoring an unknown condition is what made an authentication-flows policy
    // read as a 100% match against traffic it would never have touched.
    if (LOG_UNEVALUATED_CONDITIONS.some(key => c[key])) unknown('unevaluated');

    // Exclusion groups are a caveat, not an unknown — simulateBaselinePolicy treats them the
    // same way (a note, never a null leg), so this must not demote the verdict or the two
    // evaluators disagree and every policy reads as "conditional".
    return conditional ? 'conditional' : 'yes';
  }

  // baselinePolicies() contains a few duplicate ids (CA005/CA006 ship twice); coverage must
  // count each policy once or its totals come out as a multiple of the record count.
  function uniqueBaselinePolicies() {
    const seen = new Set();
    return baselinePolicies().filter(p => (seen.has(p.id) ? false : (seen.add(p.id), true)));
  }

  // Simulates each candidate baseline policy against the event and returns the single best
  // fit, so a triage panel names ONE policy rather than the whole control's list.
  function pickBestPolicy(sample, policyIds, preferStrength) {
    const rank = { 'would-apply': 0, 'would-apply-if': 1 };
    const results = [...new Set(policyIds || [])]
      .map(id => baselinePolicies().find(p => p.id === id))
      .filter(Boolean)
      .map(item => ({ item, simulation: simulateBaselinePolicy(item, sample) }))
      .filter(r => r.simulation.verdict !== 'would-not-apply');
    results.sort((a, b) =>
      rank[a.simulation.verdict] - rank[b.simulation.verdict] ||
      a.simulation.caveats.length - b.simulation.caveats.length ||
      (preferStrength ? Number(/authentication strength/i.test(b.simulation.enforced.join(' '))) - Number(/authentication strength/i.test(a.simulation.enforced.join(' '))) : 0));
    return results[0] || null;
  }

  // -- shared narrative pieces --

  function eventIntro(sample) {
    const t = sample.t || {};
    const deviceBit = sample.device && sample.device !== 'No device recorded'
      ? `from the device "${sample.device}"${sample.posture ? ` (${sample.posture})` : ''}`
      : 'from a machine or browser session that presented no device identity to Entra';
    return `On ${sample.time} UTC, ${sample.principal} signed in to ${sample.app} ${deviceBit}, from ${sample.location}${sample.ip ? ` (IP ${sample.ip})` : ''}.${t.success === false ? ' The sign-in FAILED.' : ''}`;
  }

  function eventAuthSummary(sample) {
    const t = sample.t || {};
    const parts = [];
    if (t.authenticationRequirement === 'multifactorauthentication') parts.push('The token was issued under a multifactor requirement');
    else if (t.authenticationRequirement === 'singlefactorauthentication') parts.push('Only a single factor — the password or an existing token — was required');
    if (t.authMethods && t.authMethods.length) parts.push(`authentication methods recorded: ${t.authMethods.join(', ')}`);
    return parts.length ? `${parts.join('; ')}.` : '';
  }

  function eventCaSummary(sample) {
    const t = sample.t || {};
    if (!t.appliedPolicies || !t.appliedPolicies.length) {
      return 'Entra recorded an empty Conditional Access policy list for this event — no policy was evaluated at all, which is different from policies evaluating and not matching.';
    }
    const enforced = t.appliedPolicies.filter(p => p.result === 'success' || p.result === 'failure');
    const filtered = t.appliedPolicies.filter(p => p.result === 'notapplied');
    const bits = [];
    if (enforced.length) bits.push(`${enforced.length} policy(ies) applied (${enforced.slice(0, 3).map(p => p.name).join('; ')})`);
    if (filtered.length) bits.push(`${filtered.length} evaluated but did not match`);
    return `Conditional Access evaluation: ${bits.join('; ')}.`;
  }

  function policyFixFor(sample, policyIds, preferStrength) {
    const best = pickBestPolicy(sample, policyIds, preferStrength);
    if (!best) return { policyId: null, simulation: null };
    return { policyId: best.item.id, simulation: best.simulation };
  }

  // -- per-check handlers --

  function triageCaNotApplied(sample, ctx) {
    const t = sample.t;
    if (!ctx.caDetail) {
      return {
        rootCause: { id: 'csv-no-detail', title: 'Cause cannot be determined from a CSV export', confidence: 'verify' },
        narrative: [
          eventIntro(sample),
          'The CSV export does not carry per-policy evaluation results, so it is impossible to tell whether Conditional Access was never engaged for this sign-in or whether policies were evaluated and filtered out. Those two causes need opposite responses, so no fix is suggested from this data.'
        ],
        fix: {
          kind: 'verify', confidence: 'verify', entity: sample.principal,
          headline: 'Re-export this log as JSON to diagnose this event',
          steps: ['Download the JSON version of the sign-in log from Entra and re-run this analysis — the JSON carries the per-policy evaluation detail this diagnosis needs.'],
          verifyInPortal: ['Entra admin centre → Monitoring → Sign-in logs → open this event → Conditional Access tab shows every policy and why it did or did not apply.']
        }
      };
    }
    const evaluated = (t.appliedPolicies || []).filter(p => p.result === 'notapplied' && p.conditions.length);
    if (!t.appliedPolicies.length) {
      if (t.platformFlow) {
        const flowExplain = {
          'windowssignin': 'This is the Windows lock-screen/logon flow: when you sign in to Windows itself, the operating system obtains a primary refresh token (PRT) — the long-lived token Windows holds after device logon and uses to silently sign you in to apps later. PRT issuance happens below Conditional Access: CA governs access to applications, and this event is the operating system authenticating, not an app being accessed.',
          'microsoftauthenticationbroker': 'The Microsoft Authentication Broker is the on-device component that brokers sign-ins for apps using the device\'s primary refresh token (PRT) — the long-lived token issued when you first signed in to the device. Broker token plumbing is not an application sign-in, so Conditional Access does not evaluate it.',
          'microsoftdeviceregistrationclient': 'This is the device registering (or renewing its registration) with Entra ID so it has a device identity at all. Device registration is governed by its own controls (including the "Register or join devices" user action in CA), and the registration client\'s token exchange itself reports as notApplied.'
        }[normToken(sample.app)] || 'This is a Windows/token platform flow (primary refresh token issuance or renewal). Conditional Access governs application access, and this event is device-level token plumbing, so no policy is ever evaluated for it.';
        return {
          rootCause: { id: 'platform-flow', title: 'Platform/token plumbing — outside Conditional Access by design', confidence: 'definite' },
          narrative: [eventIntro(sample), flowExplain, 'Because no policy can ever apply to this flow, its notApplied status is permanent and harmless. Treat it as background noise, not a gap.'],
          fix: {
            kind: 'none', confidence: 'definite', entity: sample.app,
            headline: `No action needed — ${sample.app} is platform plumbing Conditional Access never evaluates`,
            steps: ['Nothing to change. If you want this noise out of future reviews, filter these applications out when reading the sign-in log.']
          }
        };
      }
      const silentLikely = t.sourceKey === 'interactive' && (t.deviceState === 'compliant');
      const fixPick = policyFixFor(sample, ctx.policyIds, false);
      return {
        rootCause: { id: 'not-engaged', title: 'Conditional Access was never engaged for this sign-in', confidence: 'likely' },
        narrative: [
          eventIntro(sample),
          eventAuthSummary(sample),
          eventCaSummary(sample),
          silentLikely
            ? 'The device was compliant and Entra-joined, and the empty policy list on an interactive event like this is most consistent with silent token issuance: the app obtained a token off an existing signed-in session (via the device\'s primary refresh token), where Conditional Access was satisfied when the original session was created. That is an assumption — the log does not say it outright.'
            : 'No Conditional Access policy was evaluated for this event at all. There is no policy to re-scope here: either coverage genuinely does not exist for this path, or the token was issued from an existing session without a fresh evaluation.'
        ],
        fix: {
          kind: fixPick.policyId ? 'policy' : 'verify', confidence: 'likely', entity: sample.app,
          headline: fixPick.policyId
            ? `Create all-user coverage so this path is always evaluated — ${fixPick.policyId} does that`
            : 'Create all-user, all-app coverage so this path is always evaluated',
          steps: [
            'There is no tenant policy to widen for this event — nothing was evaluated. The fix is coverage that catches every sign-in path by construction: assign to All users, target All cloud apps, require MFA.',
            'Deploy in report-only first and watch this same sign-in path in the logs: once coverage exists, this event should show the policy as applied (or report-only) instead of an empty list.'
          ],
          policyId: fixPick.policyId || undefined
        },
        simulation: fixPick.simulation || undefined
      };
    }
    const registerOrJoin = evaluated.find(p => /register|join/i.test(p.name) && p.conditions.map(normToken).includes('application'));
    if (registerOrJoin) {
      return {
        rootCause: { id: 'user-action-policy', title: `"${registerOrJoin.name}" did not match — possibly by design`, confidence: 'verify' },
        narrative: [
          eventIntro(sample),
          `Entra evaluated the tenant policy "${registerOrJoin.name}" and reports it did not match because of the application condition. That reading is ambiguous: policies protecting device registration usually target the "Register or join devices" user action rather than cloud applications, and the log reports a user-action mismatch as an application mismatch. If that is the case here, this policy is working exactly as intended and re-scoping it would be wrong.`
        ],
        fix: {
          kind: 'verify', confidence: 'verify', entity: registerOrJoin.name,
          headline: `Check what "${registerOrJoin.name}" targets before changing anything`,
          steps: ['Do not re-scope this policy on the strength of this log line alone.'],
          verifyInPortal: [
            `Entra admin centre → Protection → Conditional Access → "${registerOrJoin.name}" → Target resources.`,
            'If it targets the "Register or join devices" user action: this event is expected — the policy applies at the registration action, and this sign-in is adjacent plumbing. No change needed.',
            'If it targets cloud apps and you intended it to cover this app: add the app to Target resources, test in report-only, then enable.'
          ]
        }
      };
    }
    const blockers = evaluated.slice(0, 2);
    return {
      rootCause: { id: 'filtered-out', title: 'Policies evaluated, but a condition excluded this sign-in', confidence: 'likely' },
      narrative: [
        eventIntro(sample),
        eventCaSummary(sample),
        ...blockers.map(p => `"${p.name}" did not apply because ${p.conditions.map(cond => LOG_CA_CONDITIONS[normToken(cond)] || cond).join(' and ')}.`),
        'This is a genuine scoping gap: a policy exists and could have covered this sign-in, but its assignment excluded it.'
      ],
      fix: {
        kind: 'action', confidence: 'likely', entity: blockers[0] ? blockers[0].name : sample.app,
        headline: blockers[0] ? `Re-scope the tenant policy "${blockers[0].name}"` : 'Re-scope the closest tenant policy',
        steps: blockers.map(p => `Open "${p.name}" and widen the condition that excluded this event: ${p.conditions.map(cond => LOG_CA_CONDITIONS[normToken(cond)] || cond).join('; ')}. If the blocking condition was the user assignment, check whether ${sample.principal} sits in an exclusion group; if it was target resources, add ${sample.app}.`)
          .concat(['Test the change in report-only mode and confirm this sign-in path now shows the policy as applied before enabling.'])
      }
    };
  }

  function triageSingleFactor(sample, ctx) {
    const t = sample.t;
    const applied = (t.appliedPolicies || []).filter(p => p.result === 'success');
    const fixPick = policyFixFor(sample, ctx.policyIds, false);
    const covered = applied.length > 0;
    return {
      rootCause: covered
        ? { id: 'covered-but-no-mfa', title: 'Conditional Access applied — but nothing in it required MFA', confidence: 'verify' }
        : { id: 'no-mfa-coverage', title: 'No policy required a second factor for this sign-in', confidence: 'likely' },
      narrative: [
        eventIntro(sample),
        eventAuthSummary(sample),
        eventCaSummary(sample),
        covered
          ? `Policies did apply to this sign-in (${applied.slice(0, 2).map(p => p.name).join('; ')}), yet the session was issued on a single factor — so whichever policies matched enforce session or other controls rather than an MFA grant, or the MFA requirement was satisfied by a previous sign-in and not re-challenged. The applied policies’ grant controls are the thing to check.`
          : 'Nothing in the evaluation required a second factor, so this account’s password was the only barrier. Anyone holding that password — from phishing, reuse or a breach dump — could have produced this exact sign-in.'
      ],
      fix: {
        kind: 'policy', confidence: covered ? 'verify' : 'likely', entity: sample.principal,
        headline: fixPick.policyId
          ? `Require MFA on this path — ${fixPick.policyId} would have challenged this sign-in`
          : 'Require MFA on this path with an all-user baseline policy',
        steps: covered
          ? [`Open the applied policies (${applied.slice(0, 2).map(p => p.name).join('; ')}) and check their Grant controls — none of them required multifactor authentication for this event.`,
            'If MFA policies exist but exclude this account, check the exclusion group membership.',
            'Deploy the baseline MFA policy below in report-only, confirm it would have caught this event, then enable.']
          : ['Deploy the baseline MFA policy below in report-only, confirm in the logs that this sign-in path shows it would have applied, then enable it.',
            `If ${sample.principal} is deliberately excluded somewhere, document why — every exclusion is a standing bypass.`],
        policyId: fixPick.policyId || undefined,
        verifyInPortal: covered ? ['Entra admin centre → Sign-in logs → this event → Conditional Access tab lists each applied policy and its grant controls.'] : undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageLegacyAuth(sample, ctx) {
    const fixPick = policyFixFor(sample, ['CA002'], false);
    return {
      rootCause: { id: 'legacy-protocol', title: `Legacy protocol in use: ${sample.clientApp || 'legacy client'}`, confidence: 'definite' },
      narrative: [
        eventIntro(sample),
        `The client connected over ${sample.clientApp || 'a legacy protocol'} — a protocol that uses basic authentication, sending the username and password on every request. These protocols predate modern authentication: there is no mechanism in them to present an MFA challenge or report device state, so for this connection the account was protected by its password alone, regardless of any MFA policy in the tenant.`,
        'This is provable from the log: the clientAppUsed field names the protocol directly.'
      ],
      fix: {
        kind: 'policy', confidence: 'definite', entity: `${sample.principal} · ${sample.clientApp || 'legacy client'}`,
        headline: `Migrate this client off ${sample.clientApp || 'legacy auth'}, then block the protocol tenant-wide`,
        steps: [
          `Identify what is behind this connection: it is ${sample.principal}${sample.device && sample.device !== 'No device recorded' ? ` on "${sample.device}"` : ''} from IP ${sample.ip || 'unknown'} — typically an old mail client, a scanner/printer, or a script with a hardcoded mailbox.`,
          'Move it to modern authentication (OAuth 2.0), or for send-only devices, a restricted dedicated mailbox or a high-volume email service.',
          'Block legacy authentication tenant-wide with the policy below (report-only first), and additionally disable the protocol at source in Exchange Online so the endpoint stops accepting basic auth at all.'
        ],
        policyId: fixPick.policyId || 'CA002'
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageWeakMfa(sample, ctx) {
    const t = sample.t;
    const weak = (t.authMethods || []).filter(m => WEAK_MFA_METHODS.some(w => m.includes(w)));
    const fixPick = policyFixFor(sample, ctx.policyIds, true);
    return {
      rootCause: { id: 'phishable-method', title: `MFA satisfied with a phishable method: ${weak.join(', ') || 'SMS/voice'}`, confidence: 'definite' },
      narrative: [
        eventIntro(sample),
        `MFA was performed — but using ${weak.join(' and ') || 'SMS or voice'}, methods delivered over the telephone network. A real-time phishing proxy (Evilginx-style) relays that code as the user types it and captures the session token; SIM-swap does the same without the user even being involved. The log shows MFA satisfied, and it was — that is exactly what makes this class of attack invisible here.`
      ],
      fix: {
        kind: 'action', confidence: 'definite', entity: sample.principal,
        headline: `Move ${sample.principal} to phishing-resistant MFA`,
        steps: [
          `Register a phishing-resistant method for ${sample.principal}: FIDO2 security key, passkey, or Windows Hello for Business. These bind the authentication to the legitimate domain cryptographically, so a proxy cannot relay them.`,
          'Enforce it with an authentication strength policy (the baseline below) rather than accepting any MFA method.',
          'Once registration is confirmed, remove SMS and voice from the tenant Authentication methods policy so nothing can fall back to them.'
        ],
        policyId: fixPick.policyId || undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageDeviceEvent(sample, ctx) {
    const t = sample.t;
    const meta = LOG_DEVICE_STATES[t.deviceState];
    const deviceLabel = t.deviceName || sample.device || 'this device';
    const dominant = ctx.dominantPrincipal && ctx.dominantPrincipal === sample.principal;
    const fixPick = policyFixFor(sample, ctx.policyIds, false);
    const perState = {
      unregistered: {
        title: 'No device identity was presented at all',
        confidence: 'definite',
        narrative: 'The sign-in carried no device object: no device id, no name, no trust type. Entra therefore reports it as not compliant by default — nothing failed a check, there was simply nothing to check. This is what a browser session on a never-joined machine, an InPrivate window, or a profile that is not passing the device certificate looks like.',
        headline: `Register or join the machine behind these sessions (${sample.principal})`,
        steps: [
          `Identify the machine ${sample.principal} is using here (IP ${sample.ip || 'unknown'}, ${t.operatingSystem || 'unknown OS'}, ${t.appId ? 'app ' + sample.app : sample.app}). If it is a corporate machine, join it to Entra; if personal, register it or route it through the app-protection path.`,
          'If the machine IS joined but sign-ins still show no device identity, the browser is the problem: the session is not passing the device identity (common with non-work browser profiles or browsers without the sign-in extension/SSO plumbing). Signing in to the browser profile with the work account usually fixes it.'
        ]
      },
      registeredNotCompliant: {
        title: 'Device is registered but not enrolled in management',
        confidence: 'definite',
        narrative: `"${deviceLabel}" has an identity in Entra (trust type: ${t.trustType || 'registered'}) but is not Intune-managed, so no compliance policy ever evaluates it — it can never become compliant from this state. Registration gives the device a name; only enrolment gives it a verified security posture.`,
        headline: `Enrol "${deviceLabel}" in Intune, or apply app protection if it stays personal`,
        steps: [
          `Enrol "${deviceLabel}" in Intune so compliance policies evaluate it (Company Portal app, or Settings → Access work or school on the device).`,
          'If it is a personal device you do not want under full management, use app protection policies instead — corporate data is contained and wipeable without managing the device.'
        ]
      },
      enrolledNotCompliant: {
        title: 'Device is managed and is failing a compliance rule',
        confidence: 'definite',
        narrative: `"${deviceLabel}" is Intune-managed and a compliance policy evaluated it — and it failed. This is the one variant where something concrete is wrong on the device rather than missing from your setup. The specific failing rule (OS version, encryption, Defender state…) is in Intune, not in this log.`,
        headline: `Fix the failing compliance rule on "${deviceLabel}"`,
        steps: [`Intune admin centre → Devices → "${deviceLabel}" → Device compliance: the failing policy and the specific setting are listed there. Remediate that setting and the device returns to compliant on next check-in.`]
      }
    }[t.deviceState];
    if (!perState) return null;
    const narrative = [eventIntro(sample), perState.narrative];
    if (dominant) narrative.push(`${sample.principal} accounts for most of this finding's volume — that pattern almost always means one unenrolled machine or one browser profile not passing device identity, not a fleet-wide problem. Fixing this one device clears most of the finding.`);
    narrative.push('Note: no policy currently requires a compliant device on this path — fixing the device creates the posture signal, and the baseline policy below is what would then enforce it.');
    return {
      rootCause: { id: `device-${t.deviceState}`, title: perState.title, confidence: perState.confidence },
      narrative,
      fix: {
        kind: 'action', confidence: perState.confidence,
        entity: t.deviceName || sample.principal,
        headline: perState.headline,
        steps: perState.steps,
        policyId: fixPick.policyId || undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageRiskySignIn(sample, ctx) {
    const t = sample.t;
    const level = ['high', 'medium'].find(l => t.riskSignIn === l || t.riskAggregated === l) || 'elevated';
    const fixPick = policyFixFor(sample, ctx.policyIds, false);
    return {
      rootCause: { id: 'risk-unenforced', title: `Identity Protection scored this sign-in ${level} risk — nothing intervened`, confidence: 'definite' },
      narrative: [
        eventIntro(sample),
        `Microsoft's Identity Protection scored this sign-in ${level} risk (anonymous IP, unfamiliar properties, leaked credentials or similar detections), and the sign-in still completed with no additional challenge. The detection fired; no policy consumed it. Risk detection without a risk policy is a report, not a control.`,
        'Treat this specific event as a potential live compromise first and a policy gap second.'
      ],
      fix: {
        kind: 'action', confidence: 'definite', entity: sample.principal,
        headline: `Investigate this session for ${sample.principal}, then enable risk-based policies`,
        steps: [
          `Entra admin centre → Protection → Identity Protection → Risky sign-ins: find this event (${sample.time}, ${sample.principal}) and read the specific detection behind the score.`,
          'If it is not explainable (VPN, travel), treat as compromise: revoke sessions, reset the credential, check for attacker persistence (new MFA methods, inbox rules, OAuth grants).',
          'Then deploy the sign-in risk policy below so the next one is challenged automatically instead of read about later.'
        ],
        policyId: fixPick.policyId || undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageGuest(sample, ctx) {
    const t = sample.t;
    const redacted = /^user [0-9a-f-]{20,}$/i.test(sample.principal);
    const noCa = !(t.appliedPolicies || []).some(p => p.result === 'success' || p.result === 'failure');
    const fixPick = policyFixFor(sample, ['CA400'], false);
    return {
      rootCause: {
        id: noCa ? 'guest-no-ca' : 'guest-single-factor',
        title: noCa ? 'Guest sign-in with no Conditional Access applied' : 'Guest sign-in completed on a single factor',
        confidence: redacted ? 'likely' : 'definite'
      },
      narrative: [
        eventIntro(sample),
        `This is an external identity arriving at your tenant — inbound B2B. It authenticates against its own home tenant, not yours, so you control neither its password policy nor its MFA registration. Your tenant's only say is what you require when the guest arrives, and here ${noCa ? 'no Conditional Access applied to the arrival at all' : 'only a single factor was required'}.`,
        redacted
          ? 'The identity is shown as a GUID because Entra redacts the UPN of cross-tenant guests. One nuance before acting: if you have Cross-Tenant Access Settings trusting MFA from this guest’s home tenant, MFA may have been satisfied there without appearing in your log — verify that before treating this as unprotected.'
          : 'MFA satisfied at the guest’s home tenant only counts in your tenant if Cross-Tenant Access Settings trust it — otherwise your policies must challenge the guest themselves.'
      ],
      fix: {
        kind: 'policy', confidence: redacted ? 'verify' : 'definite', entity: sample.principal,
        headline: 'Require MFA for guests in your own tenant',
        steps: [
          'Deploy the guest baseline below: it targets guest and external user types directly, so every arriving guest is challenged in your tenant regardless of home-tenant hygiene.',
          'Scope what guests can reach — they rarely need All cloud apps; restrict to the Teams/SharePoint surfaces they collaborate on.',
          'Review Cross-Tenant Access Settings: only trust MFA claims from partner tenants you have actually vetted.'
        ],
        policyId: fixPick.policyId || 'CA400',
        verifyInPortal: redacted ? ['Entra admin centre → External Identities → Cross-tenant access settings: check whether MFA is trusted from this partner tenant before concluding the sign-in was single-factor end-to-end.'] : undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triageOutboundB2B(sample) {
    const t = sample.t;
    const tenant = (t.resourceTenantId || '').slice(0, 8);
    return {
      rootCause: { id: 'outbound-b2b', title: `${sample.principal} is one of your members, signing in to an external tenant`, confidence: 'definite' },
      narrative: [
        eventIntro(sample),
        `Entra logged this with userType "guest", but that label is relative to the tenant that owns the resource — not to your directory. The tenant ids settle it: the home tenant on this sign-in is yours, and the resource tenant is ${tenant ? `${tenant}…` : 'another organisation'}. So this is your own business account visiting someone else, which is ordinary B2B collaboration.`,
        'Your Conditional Access policies do not apply to it. Access to that resource is decided by the other organisation\'s Conditional Access, together with your Cross-Tenant Access outbound settings.'
      ],
      fix: {
        kind: 'none', confidence: 'definite', entity: sample.principal,
        headline: `No Conditional Access gap — ${sample.principal} is a member visiting an external tenant`,
        steps: [
          `Confirm the external tenant ${tenant ? `${tenant}…` : ''} is an organisation you intend your people to work with.`,
          'If you want to constrain which external organisations, users or apps your members may reach, use Entra admin centre → External Identities → Cross-tenant access settings → Outbound access. A guest MFA policy in your tenant will not affect this sign-in.'
        ]
      }
    };
  }

  function triageOutdatedOs(sample, ctx) {
    const t = sample.t;
    const fixPick = policyFixFor(sample, ctx.policyIds, false);
    return {
      rootCause: { id: 'eol-os', title: `End-of-life operating system: ${t.osVersion || t.operatingSystem}`, confidence: 'definite' },
      narrative: [
        eventIntro(sample),
        `${sample.note || `The device reported ${t.osVersion || t.operatingSystem}, which no longer receives security updates.`} Unpatched vulnerabilities on it are permanent — malware on such a device reads session tokens and credentials from memory, which defeats MFA entirely because the attacker inherits an already-authenticated session.`
      ],
      fix: {
        kind: 'action', confidence: 'definite', entity: t.deviceName || sample.device,
        headline: `Upgrade or retire "${t.deviceName || sample.device}"`,
        steps: [
          `Upgrade this device to a supported OS version, or retire it. Confirm the true build in Intune device inventory — sign-in logs under-report Windows versions.`,
          'Then set a minimum OS version in the Intune compliance policy and gate access on compliance with the baseline below, so the next end-of-life device is blocked instead of reported.'
        ],
        policyId: fixPick.policyId || undefined
      },
      simulation: fixPick.simulation || undefined
    };
  }

  // -- entity-row handlers (evidence rows that represent an entity, not one sign-in) --

  function triageSprayIp(sample) {
    const t = sample.t;
    return {
      rootCause: { id: 'spray-source', title: `Password spray source: ${t.ip}`, confidence: 'definite' },
      narrative: [
        `The IP address ${t.ip} generated ${t.failures} invalid-password failures (Entra error 50126) spread across ${t.userCount} different accounts. One or two attempts per account, many accounts, one source — that spread is the signature of password spraying, engineered to stay under the per-account lockout threshold.`,
        'The log proves the pattern; what it cannot show is whether any attempt eventually succeeded from a different address.'
      ],
      fix: {
        kind: 'action', confidence: 'definite', entity: t.ip,
        headline: `Confirm no account fell to ${t.ip}, then make spraying worthless`,
        steps: [
          `Filter the sign-in logs for the targeted accounts and check for ANY success from ${t.ip} or its neighbouring range — a success is an incident, not a finding.`,
          'Enforce MFA everywhere and block legacy authentication (spray campaigns overwhelmingly target legacy endpoints where MFA cannot fire).',
          'Enable Entra Password Protection with a custom banned-password list; enable sign-in risk policies so anomalous sources are challenged automatically.'
        ]
      }
    };
  }

  function triageTravel(sample) {
    const t = sample.t;
    return {
      rootCause: { id: 'session-theft-or-vpn', title: `${t.user}: ${t.from} → ${t.to} in ${t.minutes} minutes`, confidence: 'verify' },
      narrative: [
        `${t.user} signed in from ${t.from} and then from ${t.to} ${t.minutes} minutes later — physically impossible travel. Two explanations fit: a VPN/proxy/corporate egress in another country (benign and common), or the credentials are in use by two different parties at once.`,
        'The log cannot distinguish them, which is why this needs a human check rather than an automatic fix.'
      ],
      fix: {
        kind: 'verify', confidence: 'verify', entity: t.user,
        headline: `Establish which of ${t.user}'s two locations is real`,
        steps: ['Do not reset anything yet — first rule out the benign twin.'],
        verifyInPortal: [
          `Ask ${t.user} (or check your VPN egress list): does one of ${t.from}/${t.to} match a VPN or corporate egress point? If yes — benign; define it as a named location so it stops alerting.`,
          'If neither location is explainable: treat as compromise — revoke sessions, reset the credential, check MFA registrations, inbox rules and OAuth grants for attacker persistence.',
          'Either way, enable sign-in risk policies: impossible travel is precisely the signal Identity Protection challenges in real time.'
        ]
      }
    };
  }

  function triageUncoveredApp(sample, ctx) {
    const resource = sample.t.resource;
    const clients = (sample.t.clients || []).map(c => `${c.name} (${c.count})`).join(', ');
    const fixPick = policyFixFor({ principal: 'any user', app: resource, location: '', clientApp: '', t: {} }, ['CA000'], false);
    return {
      rootCause: { id: 'resource-never-in-scope', title: `${resource} was reached with no Conditional Access applied`, confidence: 'likely' },
      narrative: [
        `${resource} was reached by ${sample.t.successes} successful interactive sign-ins in this export, and not one had a Conditional Access policy apply.`,
        `Conditional Access targets resources, not client applications — a policy set on Exchange applies to Outlook calling it. So the thing to scope here is the resource, ${resource}${clients ? `, which was reached by: ${clients}` : ''}.`,
        'The usual cause is policies scoped to selected resources rather than all of them: the resource was not in the list when the policies were written, so it sits outside every assignment. An attacker does not need to beat the controls on your protected resources if this one reaches the same data without any.'
      ],
      fix: {
        kind: 'policy', confidence: 'likely', entity: resource,
        headline: "Target All resources (formerly 'All cloud apps') so this class of gap cannot recur",
        steps: [
          `Switch the baseline policies from selected resources to All resources — that covers ${resource} and every future one automatically.`,
          `Confirm ${resource} is a resource your organisation intends people to reach, and that it has a named owner.`,
          'Where a resource genuinely needs different handling, exclude it explicitly and give it its own policy — explicit exclusions are visible and reviewable; implicit gaps are not.'
        ],
        policyId: fixPick.policyId || 'CA000'
      },
      simulation: fixPick.simulation || undefined
    };
  }

  function triagePossibleExclusion(sample) {
    const t = sample.t;
    return {
      rootCause: { id: 'account-possibly-excluded', title: `${t.user}: ${t.count} sign-ins, zero policies applied`, confidence: 'verify' },
      narrative: [
        `${t.user} signed in ${t.count} times with Conditional Access never applying, while most other traffic in this tenant is covered. The log shows the absence, not the cause — the classic explanation is membership of a policy exclusion group (often added "temporarily" and never removed), but the log cannot see group membership.`,
        'Exclusion groups are a standing bypass of every policy and a known attacker target: modify the group, walk past the entire design.'
      ],
      fix: {
        kind: 'verify', confidence: 'verify', entity: t.user,
        headline: `Check every policy's exclusion lists for ${t.user}`,
        steps: ['This needs the portal — exclusions are invisible in sign-in logs.'],
        verifyInPortal: [
          `Entra admin centre → Protection → Conditional Access → each policy → Users → Exclude: check whether ${t.user} (or a group containing them) is listed.`,
          'If excluded deliberately (break-glass): document it, restrict who can edit the group, and alert on any sign-in by the account.',
          'If excluded by leftover: remove the exclusion, test in report-only, and confirm this account’s next sign-ins show policies applying.'
        ]
      }
    };
  }

  function triageSpLocation(sample) {
    const t = sample.t;
    return {
      rootCause: { id: 'sp-geo-anomaly', title: `${t.name} signs in from ${t.countries.length} countries`, confidence: 'verify' },
      narrative: [
        `The service principal ${t.name} authenticated from ${t.countries.join(', ')} across ${t.count} sign-ins. A workload identity normally runs from a fixed place — one cloud region, one datacentre. A global SaaS vendor legitimately egresses from many regions; a leaked credential also works from anywhere, and geographic spread is often the only visible symptom.`
      ],
      fix: {
        kind: 'verify', confidence: 'verify', entity: t.name,
        headline: `Confirm ${t.name}'s expected egress regions with its vendor`,
        steps: [`Check ${t.name}'s vendor documentation for published egress/datacentre regions and compare with the observed list.`],
        verifyInPortal: [
          'If the spread matches the vendor’s infrastructure: expected — note it and move on.',
          'If it does not: rotate the credential immediately and review the app’s permissions; restrict by IP at the application level where supported. True location conditions on service principals need Workload Identities Premium.'
        ]
      }
    };
  }

  function triageSpCredential(sample) {
    const t = sample.t;
    const errs = t.credErrors || [];
    const hasErrors = errs.length > 0;
    const expiry = errs.filter(e => e.kind === 'expiry');
    const config = errs.filter(e => e.kind === 'config');
    const invalid = errs.filter(e => e.kind === 'invalid');
    const errorNarrative = () => {
      const bits = [`${t.name} produced authentication failures: ${errs.map(e => `${e.code} — ${e.meaning}`).join('; ')}.`];
      if (expiry.length) bits.push('The expiry codes are an availability incident in the making as well as a hygiene flag — the integration breaks when the credential lapses.');
      if (invalid.length) bits.push('An invalid-credential code usually means the wrong secret or certificate is configured on the client side, not that it has expired.');
      if (config.length) bits.push('The remaining codes are application configuration faults rather than credential expiry — the app being disabled in the tenant, or missing signing key configuration. Rotating a credential will not resolve those.');
      return bits.join(' ');
    };
    return {
      rootCause: {
        id: hasErrors ? 'credential-error' : 'secret-only',
        title: hasErrors ? `${t.name}: authentication failures (${errs.map(e => e.code).join(', ')})` : `${t.name} authenticates with a client secret`,
        confidence: 'definite'
      },
      narrative: [
        hasErrors
          ? errorNarrative()
          : `${t.name} authenticates with a client secret — a long-lived password stored in configuration. It works from anywhere, bypasses MFA by nature, and is exactly the kind of string that leaks via repositories, CI logs and config backups. Conditional Access cannot see or enforce credential type; this is app-registration governance.`
      ],
      fix: {
        kind: 'action', confidence: 'definite', entity: t.name,
        headline: hasErrors
          ? (expiry.length ? `Rotate ${t.name}'s expiring credential now` : `Investigate ${t.name}'s authentication failures`)
          : `Move ${t.name} off client secrets`,
        steps: hasErrors
          ? [
            expiry.length
              ? `Rotate the credential for ${t.name} before it fully expires and breaks the integration.`
              : `Check what ${t.name} is configured with: an invalid-credential or configuration error is not fixed by rotation.`,
            ...(config.length ? [`Confirm the application object for ${t.name} is enabled and correctly configured in Entra — these codes point at the app registration, not the secret.`] : []),
            'While in there, move to federation or a certificate rather than issuing another secret.'
          ]
          : [`If ${t.name}'s workload runs somewhere OIDC-capable (GitHub Actions, Azure, Kubernetes): switch to workload identity federation — no stored secret exists at all.`,
            'Otherwise use a certificate credential held in a key vault or hardware module.',
            'Cap secret lifetimes tenant-wide with an Entra application management policy so no future credential can be created without an expiry.']
      }
    };
  }

  const LOG_EVENT_TRIAGE = {
    'ca-not-applied': triageCaNotApplied,
    'single-factor-success': triageSingleFactor,
    'legacy-auth': triageLegacyAuth,
    'weak-mfa': triageWeakMfa,
    'noncompliant-device': triageDeviceEvent,
    'risky-signin-success': triageRiskySignIn,
    'guest-uncontrolled': triageGuest,
    'outbound-b2b': triageOutboundB2B,
    'outdated-os': triageOutdatedOs,
    'password-spray': triageSprayIp,
    'impossible-travel': triageTravel,
    'uncovered-apps': triageUncoveredApp,
    'possible-exclusions': triagePossibleExclusion,
    'sp-location-spread': triageSpLocation,
    'sp-credential-hygiene': triageSpCredential
  };

  function triageSignInEvent(sample, checkId, ctx) {
    const handler = LOG_EVENT_TRIAGE[checkId];
    if (!handler || !sample || typeof sample !== 'object' || !sample.t) return null;
    try {
      return handler(sample, ctx || {});
    } catch (_) {
      return null;
    }
  }

  // Dedupes per-event fixes into the finding's "what do I actually do" list.
  function buildActionPlan(finding) {
    const groups = new Map();
    (finding.samples || []).forEach(sample => {
      if (!sample || typeof sample !== 'object' || !sample.triage) return;
      const fix = sample.triage.fix;
      const key = `${fix.kind}|${fix.headline}`;
      const entry = groups.get(key) || {
        headline: fix.headline, kind: fix.kind, confidence: fix.confidence,
        policyId: fix.policyId || null, entity: fix.entity || '', count: 0, examples: []
      };
      entry.count += 1;
      const example = fix.entity || sample.principal || sample.label || '';
      if (example && entry.examples.length < 3 && !entry.examples.includes(example)) entry.examples.push(example);
      groups.set(key, entry);
    });
    const order = { policy: 0, action: 0, verify: 1, none: 2 };
    return [...groups.values()]
      .sort((a, b) => order[a.kind] - order[b.kind] || b.count - a.count)
      .slice(0, 10);
  }

  function makeLogFinding(agg, opts) {
    const t = agg.tallies[opts.tallyId || opts.id] || { count: 0, users: new Map(), apps: new Map(), samples: [] };
    const affected = opts.affected ?? t.count;
    if (!affected) return null;
    const declared = opts.sources || LOG_CHECK_SOURCES[opts.id] || LOG_SOURCE_ORDER;
    const sources = declared.filter(key => agg.totals[key] > 0);
    const denominator = logSourceTotal(agg, sources);
    if (!denominator) return null;
    const top = map => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, LOG_TOP_CAP).map(([name, count]) => ({ name, count }));
    const policies = policiesForControlIds(opts.controlIds || []);
    const finding = {
      id: opts.id,
      severity: opts.severity,
      title: opts.title,
      detail: opts.detail,
      metric: {
        affected,
        total: denominator,
        pct: logPct(affected, denominator),
        scope: logScopeLabel(agg, sources),
        sources
      },
      topUsers: opts.topUsers ?? top(t.users),
      topApps: opts.topApps ?? top(t.apps),
      topDevices: opts.topDevices ?? top(t.devices || new Map()),
      topLocations: opts.topLocations ?? top(t.locations || new Map()),
      platformFlow: t.platformFlow || 0,
      topUsersLabel: opts.topUsersLabel || 'Top users',
      topAppsLabel: opts.topAppsLabel || 'Top apps',
      unit: opts.unit || 'sign-ins',
      samples: opts.samples ?? t.samples,
      controlIds: opts.controlIds || [],
      policyIds: policies.map(p => p.id),
      policies,
      requirements: opts.requirements || [],
      diagnosis: opts.diagnosis || null,
      deviceSplit: opts.deviceSplit || null,
      recommendation: opts.recommendation
    };
    // Per-event triage: attach eagerly so the exported report carries it; rendering is lazy.
    const topUser = finding.topUsers[0];
    const ctxBase = {
      policyIds: finding.policyIds,
      dominantPrincipal: topUser && topUser.count > affected / 2 ? topUser.name : ''
    };
    finding.samples.forEach(sample => {
      if (!sample || typeof sample !== 'object' || !sample.t) return;
      const stats = sample.t.sourceKey ? agg.sourceStats[sample.t.sourceKey] : null;
      // caDetail is false only when this source came from a CSV export, which omits the
      // per-policy results — a JSON export with genuinely empty policy lists keeps full triage.
      const csvNoDetail = !!(stats && stats.format === 'csv' && !stats.fieldsSeen.has('appliedPolicies'));
      sample.triage = triageSignInEvent(sample, opts.id, { ...ctxBase, caDetail: !csvNoDetail });
    });
    finding.actionPlan = buildActionPlan(finding);
    return finding;
  }

  function runLogChecks(agg) {
    const findings = [];
    const push = finding => { if (finding) findings.push(finding); };
    const named = controlIds => policiesForControlIds(controlIds).map(p => p.displayName).join(', ');
    const count = id => (agg.tallies[id] ? agg.tallies[id].count : 0);

    push(makeLogFinding(agg, {
      id: 'legacy-auth', severity: 'high',
      title: 'Legacy authentication in use',
      detail: `${count('legacy-auth')} sign-ins used legacy protocols (IMAP, POP, SMTP, ActiveSync, MAPI or similar) that cannot enforce MFA.`,
      controlIds: ['legacy_auth'], requirements: ['internals'],
      recommendation: `Enable ${named(['legacy_auth'])} to block legacy authentication tenant-wide. Migrate the affected clients to modern authentication first.`
    }));
    push(makeLogFinding(agg, {
      id: 'single-factor-success', severity: 'high',
      title: 'Successful single-factor sign-ins',
      detail: `${count('single-factor-success')} successful sign-ins required only a single factor — no MFA was enforced.`,
      controlIds: ['mfa'], requirements: ['internals', 'admins'],
      recommendation: `Enforce MFA for all users with ${named(['mfa'])}.`
    }));
    const gap = agg.caGap;
    const gapParts = [];
    if (gap.notEngaged) {
      gapParts.push(`${gap.notEngaged} had no policy evaluated at all${gap.platformFlow ? ` (${gap.platformFlow} of those are Windows/token plumbing flows that Conditional Access never evaluates)` : ''}`);
    }
    if (gap.evaluated) {
      const topCond = [...gap.conditions.entries()].sort((a, b) => b[1] - a[1])[0];
      gapParts.push(`${gap.evaluated} had policies evaluated but every one was filtered out${topCond ? `, most often because ${LOG_CA_CONDITIONS[topCond[0]] || topCond[0]}` : ''}`);
    }
    // Severity keys off the ACTIONABLE remainder, not the raw count: platform/token
    // plumbing flows can never be covered by policy, so counting them would mark a
    // by-design behaviour as a high-risk gap and bury the real signal.
    const caActionable = count('ca-not-applied') - gap.platformFlow;
    const caSeverity = caActionable === 0 ? 'info' : gap.platformFlow >= caActionable * 2 ? 'medium' : 'high';
    push(makeLogFinding(agg, {
      id: 'ca-not-applied', severity: caSeverity,
      title: 'Sign-ins with no Conditional Access applied',
      detail: `${count('ca-not-applied')} successful sign-ins matched no Conditional Access policy at all (status notApplied)${caActionable === 0
        ? ' — all of them are Windows/token platform flows that Conditional Access never evaluates, so this is working as designed and nothing here needs fixing'
        : ` — but only ${caActionable} of them need attention; ${gap.platformFlow} are Windows/token platform flows that Conditional Access never evaluates, and severity is judged on the ${caActionable} actionable event(s)`}. ${gapParts.join('; ')}.`,
      controlIds: ['mfa'], requirements: caActionable ? ['internals'] : [],
      diagnosis: {
        notEngaged: gap.notEngaged,
        platformFlow: gap.platformFlow,
        evaluated: gap.evaluated,
        actionable: caActionable,
        conditions: [...gap.conditions.entries()].sort((a, b) => b[1] - a[1])
          .map(([key, n]) => ({ label: LOG_CA_CONDITIONS[key] || key, count: n })),
        policies: [...gap.policies.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
          .map(([label, n]) => ({ label, count: n }))
      },
      recommendation: `Close the coverage gap with all-user baseline policies such as ${named(['mfa'])}. Review policy scoping so every sign-in path is evaluated.`
    }));
    push(makeLogFinding(agg, {
      id: 'weak-mfa', severity: 'medium',
      title: 'Weak MFA methods (SMS / voice)',
      detail: `${count('weak-mfa')} sign-ins authenticated with SMS or voice methods that are phishable.`,
      controlIds: ['phish_mfa'], requirements: ['admins'],
      recommendation: `Move to phishing-resistant methods (FIDO2, Windows Hello, certificates) via ${named(['phish_mfa'])}, starting with privileged accounts.`
    }));
    const deviceSplit = [...agg.deviceGap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([key, n]) => ({ key, count: n, label: LOG_DEVICE_STATES[key].label, detail: LOG_DEVICE_STATES[key].detail }));
    push(makeLogFinding(agg, {
      id: 'noncompliant-device', severity: 'medium',
      title: 'Sign-ins from devices with no verified compliance',
      detail: `${count('noncompliant-device')} successful sign-ins came from devices whose security posture could not be verified. ${deviceSplit.map(s => `${s.count} ${s.label.toLowerCase()}`).join('; ')}.`,
      controlIds: ['device_compliance', 'app_protection'], requirements: ['managedDevices'],
      deviceSplit,
      recommendation: `Require device compliance or app protection with ${named(['device_compliance', 'app_protection'])}.`
    }));
    push(makeLogFinding(agg, {
      id: 'risky-signin-success', severity: 'high',
      title: 'Risky sign-ins succeeded',
      detail: `${count('risky-signin-success')} sign-ins flagged medium or high risk by Identity Protection completed successfully without being blocked.`,
      controlIds: ['sign_in_risk', 'user_risk'], requirements: ['internals'],
      recommendation: `Enable risk-based policies ${named(['sign_in_risk', 'user_risk'])} to challenge or block risky sessions automatically.`
    }));
    push(makeLogFinding(agg, {
      id: 'guest-uncontrolled', severity: 'medium',
      title: 'Inbound guest sign-ins without controls',
      detail: `${count('guest-uncontrolled')} sign-ins by external identities arriving at your tenant had no Conditional Access applied or completed with a single factor.${agg.guestDirectionUnknown ? ` ${agg.guestDirectionUnknown} of these could not be confirmed as inbound because the export carries no tenant ids — use the JSON export to be certain.` : ''}`,
      controlIds: ['guest_access'], requirements: ['guests'],
      recommendation: `Apply the guest baseline ${named(['guest_access'])} to require MFA and restrict guest access to approved apps.`
    }));
    if (agg.outboundB2B.count) {
      const tenants = [...agg.outboundB2B.tenants.entries()].sort((a, b) => b[1] - a[1]);
      push(makeLogFinding(agg, {
        id: 'outbound-b2b', severity: 'info',
        title: 'Your users signing in to other organisations (outbound B2B)',
        detail: `${agg.outboundB2B.count} sign-ins were your own members accessing ${tenants.length} external tenant(s) as guests. Entra labels these userType "guest" because the label is relative to the resource tenant — they are not guest accounts in your directory, and your Conditional Access policies do not govern them.`,
        affected: agg.outboundB2B.count,
        topUsers: [...agg.outboundB2B.users.entries()].sort((a, b) => b[1] - a[1]).slice(0, LOG_TOP_CAP).map(([name, n]) => ({ name, count: n })),
        topApps: [], topUsersLabel: 'Your users going out',
        controlIds: [], requirements: [],
        recommendation: 'Access over there is governed by the other tenant’s Conditional Access, not yours. Your lever is Cross-Tenant Access Settings → Outbound access, which controls which external tenants and applications your users may reach.'
      }));
    }

    if (agg.reportOnly.size) {
      const entries = [...agg.reportOnly.entries()].sort((a, b) => b[1].total - a[1].total);
      const baselineIds = new Set(baselinePolicies().map(p => p.id));
      const samples = entries.slice(0, LOG_SAMPLE_CAP).map(([name, e]) => {
        const idMatch = name.match(/^CA\d+/);
        const tag = idMatch && baselineIds.has(idMatch[0]) ? ' [baseline policy]' : '';
        return `${name}${tag}: evaluated ${e.total} times, would have intervened ${e.wouldBlockOrGrant} times`;
      });
      const affected = entries.reduce((sum, [, e]) => sum + e.total, 0);
      push(makeLogFinding(agg, {
        id: 'report-only', severity: 'info',
        title: 'Policies still in report-only mode',
        detail: `${entries.length} Conditional Access policies ran in report-only mode across ${affected} evaluations. The report-only policies recorded what they would do but did not themselves enforce a control; another enabled policy may still have protected the same event.`,
        affected, topUsers: [], topApps: [], samples,
        recommendation: 'Review Success, Failure, User action required and Not applied separately, confirm whether enabled policies protected the same events, then pilot and stage validated policies to On.'
      }));
    }

    const sprayEntries = [...agg.sprayIps.entries()].filter(([, e]) => e.users.size >= 5).sort((a, b) => b[1].users.size - a[1].users.size);
    if (sprayEntries.length) {
      const affected = sprayEntries.reduce((sum, [, e]) => sum + e.count, 0);
      push(makeLogFinding(agg, {
        id: 'password-spray', severity: 'high',
        title: 'Possible password spray activity',
        detail: `${sprayEntries.length} IP address(es) generated invalid-password failures (error 50126) across 5 or more distinct accounts each — a classic password spray pattern.`,
        affected, topUsers: [], topApps: [],
        samples: sprayEntries.slice(0, LOG_SAMPLE_CAP).map(([ip, e]) => ({
          kind: 'entity',
          label: `${ip}: ${e.count} failures across ${e.users.size} accounts`,
          t: { ip, failures: e.count, userCount: e.users.size }
        })),
        controlIds: ['mfa', 'legacy_auth', 'sign_in_risk'], requirements: ['internals'],
        recommendation: `Password spray only pays off where MFA is missing. Enforce ${named(['mfa'])}, block legacy auth with ${named(['legacy_auth'])}, and enable risk policies to disrupt automated attempts.`
      }));
    }

    const travelIncidents = [];
    agg.travel.forEach((timeline, user) => {
      const sorted = [...timeline].sort((a, b) => a.time - b.time);
      for (let i = 1; i < sorted.length; i += 1) {
        const prev = sorted[i - 1];
        const curr = sorted[i];
        if (prev.country !== curr.country && curr.time - prev.time <= LOG_TRAVEL_WINDOW_MS) {
          travelIncidents.push({ user, from: prev.country, to: curr.country, minutes: Math.round((curr.time - prev.time) / 60000) });
        }
      }
    });
    if (travelIncidents.length) {
      const userCounts = new Map();
      travelIncidents.forEach(inc => userCounts.set(inc.user, (userCounts.get(inc.user) || 0) + 1));
      push(makeLogFinding(agg, {
        id: 'impossible-travel', severity: 'high',
        title: 'Impossible travel between countries',
        detail: `${travelIncidents.length} sign-in pair(s) show the same account in two countries within 60 minutes.`,
        affected: travelIncidents.length,
        topUsers: [...userCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, LOG_TOP_CAP).map(([name, count]) => ({ name, count })),
        topApps: [],
        samples: travelIncidents.slice(0, LOG_SAMPLE_CAP).map(inc => ({
          kind: 'entity',
          label: `${inc.user}: ${inc.from} → ${inc.to} in ${inc.minutes} min`,
          t: { user: inc.user, from: inc.from, to: inc.to, minutes: inc.minutes }
        })),
        controlIds: ['sign_in_risk'], requirements: ['internals', 'trustedLocations'],
        recommendation: `Enable ${named(['sign_in_risk'])} so anomalous sessions are challenged, and define named locations to tighten where access is expected from.`
      }));
    }

    push(makeLogFinding(agg, {
      id: 'outdated-os', severity: 'low',
      title: 'Sign-ins from outdated operating systems',
      detail: `${count('outdated-os')} sign-ins came from end-of-life operating systems that no longer receive security updates.${agg.windowsUndetermined ? ` A further ${agg.windowsUndetermined} Windows sign-in(s) carried no build number, so their version could not be determined and they are not counted here.` : ''}`,
      controlIds: ['device_compliance', 'unknown_platforms'], requirements: ['managedDevices'],
      recommendation: `Require compliant devices with ${named(['device_compliance'])} — compliance policies can enforce minimum OS versions — and restrict unknown platforms with ${named(['unknown_platforms'])}.`
    }));

    if (agg.fieldsSeen.has('conditionalAccessStatus')) {
      const uncovered = [...agg.interactiveResources.entries()].filter(([, a]) => a.success >= 5 && a.caApplied === 0).sort((a, b) => b[1].success - a[1].success);
      if (uncovered.length) {
        const affected = uncovered.reduce((sum, [, a]) => sum + a.success, 0);
        push(makeLogFinding(agg, {
          id: 'uncovered-apps', severity: 'medium',
          title: 'Resources never covered by Conditional Access',
          detail: `${uncovered.length} resource(s) with 5+ successful interactive sign-ins never had any Conditional Access policy apply. Bootstrap flows that Conditional Access never evaluates are excluded from this count.`,
          affected, topUsers: [],
          topApps: uncovered.slice(0, LOG_TOP_CAP).map(([name, a]) => ({ name, count: a.success })),
          topAppsLabel: 'Top resources',
          samples: uncovered.slice(0, LOG_SAMPLE_CAP).map(([name, a]) => ({
            kind: 'entity',
            label: `${name}: ${a.success} successful sign-ins, no CA applied`,
            t: {
              resource: name,
              successes: a.success,
              clients: [...a.clients.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([c, n]) => ({ name: c, count: n }))
            }
          })),
          controlIds: ['mfa'], requirements: ['internals'],
          recommendation: `Target policies at All resources (formerly 'All cloud apps') rather than selected resources. The all-user baseline ${named(['mfa'])} closes per-resource gaps.`
        }));
      }
      const excluded = [...agg.interactiveUsers.entries()].filter(([, u]) => u.count >= 10 && u.caApplied === 0);
      const otherTotal = [...agg.interactiveUsers.values()].reduce((sum, u) => sum + u.count, 0) - excluded.reduce((sum, [, u]) => sum + u.count, 0);
      const otherApplied = [...agg.interactiveUsers.values()].reduce((sum, u) => sum + u.caApplied, 0);
      if (excluded.length && otherTotal > 0 && otherApplied / otherTotal > 0.5) {
        const affected = excluded.reduce((sum, [, u]) => sum + u.count, 0);
        push(makeLogFinding(agg, {
          id: 'possible-exclusions', severity: 'medium',
          title: 'Accounts possibly excluded from all policies',
          detail: `${excluded.length} account(s) with 10+ sign-ins never had Conditional Access applied, while most other traffic did — they may be blanket-excluded.`,
          affected, topApps: [],
          topUsers: excluded.sort((a, b) => b[1].count - a[1].count).slice(0, LOG_TOP_CAP).map(([name, u]) => ({ name, count: u.count })),
          samples: excluded.slice(0, LOG_SAMPLE_CAP).map(([name, u]) => ({
            kind: 'entity',
            label: `${name}: ${u.count} sign-ins, no CA applied`,
            t: { user: name, count: u.count }
          })),
          controlIds: ['mfa'], requirements: ['internals'],
          recommendation: 'Audit policy exclusion lists. Keep only documented break-glass accounts excluded, and monitor their sign-ins closely.'
        }));
      }
    }

    if (agg.countries.size >= 5) {
      const topCountries = [...agg.countries.entries()].sort((a, b) => b[1] - a[1]);
      push(makeLogFinding(agg, {
        id: 'geo-spread', severity: 'info',
        title: 'Sign-ins from many countries',
        detail: `Sign-ins originated from ${agg.countries.size} countries. If your workforce is not this distributed, consider location-based controls.`,
        affected: [...agg.countries.values()].reduce((sum, n) => sum + n, 0), topUsers: [], topApps: [],
        samples: topCountries.slice(0, LOG_SAMPLE_CAP).map(([name, n]) => `${name}: ${n} sign-ins`),
        controlIds: ['trusted_location'], requirements: ['trustedLocations'],
        recommendation: `Define named locations and consider ${named(['trusted_location'])} for high-value access paths.`
      }));
    }

    if (agg.totals.application) {
      const sps = [...agg.spPrincipals.entries()];
      const reportOnly = sps.filter(([, sp]) => sp.reportOnly > 0).sort((a, b) => b[1].reportOnly - a[1].reportOnly);
      if (reportOnly.length) {
        push(makeLogFinding(agg, {
          id: 'sp-report-only', severity: 'medium',
          title: 'Workload policies matched in report-only mode',
          detail: `${reportOnly.length} service principal(s) had matching workload Conditional Access policy evidence while access continued under report-only evaluation. This records intent, not enforcement; another enabled policy may still have acted on the same event.`,
          affected: reportOnly.reduce((sum, [, sp]) => sum + sp.reportOnly, 0),
          topUsers: reportOnly.slice(0, LOG_TOP_CAP).map(([name, sp]) => ({ name, count: sp.reportOnly })),
          topApps: [],
          topUsersLabel: 'Top service principals', topAppsLabel: 'Top resources',
          controlIds: [], requirements: [],
          recommendation: 'Review the report-only result and affected service principals, validate eligibility and ownership, then pilot and stage the workload policy. Do not describe the report-only evaluation as protection until an enabled policy is recorded acting.'
        }));
      }
      const evaluatedNoMatch = sps.filter(([, sp]) => sp.evaluatedNoMatch > 0).sort((a, b) => b[1].evaluatedNoMatch - a[1].evaluatedNoMatch);
      if (evaluatedNoMatch.length) {
        push(makeLogFinding(agg, {
          id: 'sp-ca-review', severity: 'info',
          title: 'Workload policies evaluated but did not match',
          detail: `${evaluatedNoMatch.length} service principal(s) had workload policies returned, but every recorded evaluation was filtered or not applied. This is a scope and applicability review—not proof of an unprotected eligible workload.`,
          affected: evaluatedNoMatch.reduce((sum, [, sp]) => sum + sp.evaluatedNoMatch, 0),
          topUsers: evaluatedNoMatch.slice(0, LOG_TOP_CAP).map(([name, sp]) => ({ name, count: sp.evaluatedNoMatch })),
          topApps: [], topUsersLabel: 'Service principals to review',
          controlIds: [], requirements: [],
          recommendation: 'Inspect the recorded conditions that were not satisfied, confirm the service principal is single-tenant and owned by your organisation, and only then decide whether workload Conditional Access should include it.'
        }));
      }
      const spread = sps.filter(([, sp]) => sp.countries.size >= LOG_SP_COUNTRY_THRESHOLD)
        .sort((a, b) => b[1].countries.size - a[1].countries.size);
      if (spread.length) {
        push(makeLogFinding(agg, {
          id: 'sp-location-spread', severity: 'medium',
          title: 'Service principals signing in from many locations',
          detail: `${spread.length} service principal(s) signed in from ${LOG_SP_COUNTRY_THRESHOLD} or more countries. Workload identities usually run from a predictable set of locations.`,
          affected: spread.reduce((sum, [, sp]) => sum + sp.count, 0),
          topUsers: spread.slice(0, LOG_TOP_CAP).map(([name, sp]) => ({ name, count: sp.countries.size })),
          topApps: [], topUsersLabel: 'Most widespread service principals', unit: 'countries',
          samples: spread.slice(0, LOG_SAMPLE_CAP).map(([name, sp]) => ({
            kind: 'entity',
            label: `${name}: ${sp.count} sign-ins from ${[...sp.countries.keys()].join(', ')}`,
            t: { name, count: sp.count, countries: [...sp.countries.keys()] }
          })),
          controlIds: [], requirements: [],
          recommendation: `Confirm each of these is expected to run from that many regions. For human-operated service accounts, ${named(['service_account_protection'])} blocks sign-ins outside approved named locations. For app registrations, the equivalent guardrail today is IP restriction on the application itself, since per-service-principal location conditions need Workload Identities Premium.`
        }));
      }
      const secretSps = sps.filter(([, sp]) => sp.credential.secret > 0 && !sp.credential.federated && !sp.credential.certificate);
      const errorSps = sps.filter(([, sp]) => sp.credErrors.size > 0);
      if (secretSps.length || errorSps.length) {
        const flagged = new Map([...secretSps, ...errorSps]);
        const samples = [
          ...secretSps.slice(0, LOG_TOP_CAP).map(([name, sp]) => ({
            kind: 'entity',
            label: `${name}: client secret (no certificate thumbprint, no federated credential) — ${sp.count} sign-ins`,
            t: { name, count: sp.count, credErrors: [] }
          })),
          ...errorSps.slice(0, LOG_TOP_CAP).map(([name, sp]) => ({
            kind: 'entity',
            label: `${name}: ${[...sp.credErrors.values()].reduce((a, n) => a + n, 0)} credential failure(s)`,
            t: {
              name, count: sp.count,
              credErrors: [...sp.credErrors.entries()].map(([code, n]) => ({ code, count: n, meaning: spCredentialErrorText(code), kind: spCredentialErrorKind(code) }))
            }
          }))
        ].slice(0, LOG_SAMPLE_CAP);
        push(makeLogFinding(agg, {
          id: 'sp-credential-hygiene', severity: 'medium',
          title: 'Service principals using weaker credentials',
          detail: `${secretSps.length} service principal(s) authenticated with a client secret rather than a certificate or workload identity federation${errorSps.length ? `, and ${errorSps.length} hit credential errors that usually mean an expired or invalid secret` : ''}.`,
          affected: [...flagged.values()].reduce((sum, sp) => sum + sp.count, 0),
          topUsers: [...flagged.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, LOG_TOP_CAP).map(([name, sp]) => ({ name, count: sp.count })),
          topApps: [], topUsersLabel: 'Affected service principals', samples,
          controlIds: [], requirements: [],
          recommendation: `Conditional Access cannot enforce credential type — this is app-registration governance rather than a CA control. Move these to workload identity federation where the workload runs somewhere OIDC-capable (GitHub Actions, Kubernetes, Azure), or to certificate credentials otherwise, and cap secret lifetimes with an Entra application management policy. The CA-side compensating control for human-operated service accounts is location restriction via ${named(['service_account_protection'])}. Credential errors such as 7000222 are an availability risk as well as a hygiene one.`
        }));
      }
    }

    const rank = { high: 0, medium: 1, low: 2, info: 3 };
    return findings.sort((a, b) =>
      rank[a.severity] - rank[b.severity] ||
      b.metric.pct - a.metric.pct ||
      b.metric.affected - a.metric.affected);
  }

  function degradationWarnings(agg, sources) {
    const warnings = [];
    const loaded = key => key in sources;
    const fieldSeenIn = (field, keys) => keys.some(key => agg.sourceStats[key] && agg.sourceStats[key].fieldsSeen.has(field));
    const userKeys = LOG_USER_SOURCES.filter(loaded);
    if (agg.timeParseFailures) warnings.push(`${agg.timeParseFailures} represented event(s) came from rows with unparseable timestamps and were excluded from time-based checks.`);
    if (agg.groupedRowCount) warnings.push(`${agg.groupedRowCount} imported row(s) represented grouped sign-ins. Volume calculations use the portal counts, but impossible-travel and other sequencing checks retain only one temporal observation per grouped row.`);
    LOG_SOURCE_ORDER.filter(key => !loaded(key)).forEach(key => {
      const note = {
        interactive: 'Interactive sign-in log not loaded — MFA strength, device posture and outdated OS checks were not assessed.',
        nonInteractive: 'Non-interactive sign-in log not loaded — legacy authentication is most visible there, so that evidence may be incomplete.',
        application: 'Service principal log not loaded — workload policy evaluation, credential hygiene and workload location evidence were not assessed.'
      }[key];
      if (note) warnings.push(note);
    });
    Object.keys(sources).forEach(key => {
      if (sources[key].records === 0) warnings.push(`${LOG_SOURCES[key].label}: no activity in this date range.`);
    });
    if (userKeys.length) {
      if (!fieldSeenIn('riskLevels', userKeys)) warnings.push('No risk level data found — risky sign-in checks were skipped. Risk levels require Entra ID P2 and appear in the JSON export.');
      if (!fieldSeenIn('userType', userKeys)) warnings.push('No user type data found — guest-specific checks were skipped (use the JSON export).');
      if (!fieldSeenIn('conditionalAccessStatus', userKeys)) warnings.push('No Conditional Access status data found — user coverage checks were skipped.');
    }
    if (loaded('interactive')) {
      if (!fieldSeenIn('devicePosture', ['interactive'])) warnings.push('No device compliance data in the interactive log — device posture checks were skipped.');
      if (!fieldSeenIn('authenticationRequirement', ['interactive'])) warnings.push('No authentication requirement data in the interactive log — single-factor checks were skipped.');
    }
    if (loaded('application')) {
      if (!fieldSeenIn('appliedPolicies', ['application'])) {
        warnings.push('Service-principal policy evidence is a blind spot: this export returned no per-policy evaluation detail. Absence of that detail is not proof of a Conditional Access gap; use the JSON export to assess eligible workload policies.');
      }
      if (agg.totals.application && agg.spWithCountry / agg.totals.application < 0.25) {
        warnings.push('Most service principal sign-ins had no location data — location spread analysis for workload identities is incomplete.');
      }
    }
    return warnings;
  }

  // Every tenant needs admin hardening and workforce MFA. These are not conclusions drawn
  // from the logs, so they must not depend on a finding firing.
  const LOG_STANDARD_REQUIREMENTS = ['admins', 'internals'];

  // Requirements come from three places, not one: what the logs evidenced, what is standard
  // for any tenant, and what the user declared. Findings alone meant a tenant whose guests
  // happened not to sign in during the window got no guest policies at all.
  function strategyHandOffFromFindings(findings, declarations) {
    const answers = declarations || defaultDeclarations();
    const evidenced = [...new Set(findings.flatMap(f => f.requirements))].filter(key => key in STRATEGY_REQUIREMENTS);
    const declared = [];
    const assumed = [];
    LOG_DECLARATIONS.forEach(d => {
      const answer = answers[d.key];
      if (answer === 'no') return;
      (d.requirements || []).filter(key => key in STRATEGY_REQUIREMENTS)
        .forEach(key => (answer === 'yes' ? declared : assumed).push(key));
    });
    // An explicit "no" wins even over evidence. Requiring a compliant device in a tenant with
    // no Intune locks every user out, so the safe reading of "we don't use Intune" is to drop
    // the policy — but the evidenced finding it would have answered is then unaddressed, and
    // `declinedDespiteEvidence` carries that back to the UI rather than losing it.
    const declinedRequirements = LOG_DECLARATIONS
      .filter(d => answers[d.key] === 'no')
      .flatMap(d => d.requirements || []);
    const requirementKeys = [...new Set([...evidenced, ...LOG_STANDARD_REQUIREMENTS, ...declared, ...assumed])]
      .filter(key => key in STRATEGY_REQUIREMENTS)
      .filter(key => !declinedRequirements.includes(key));
    const declinedDespiteEvidence = declinedRequirements.filter(key => evidenced.includes(key));
    const controlIds = [...new Set(findings.flatMap(f => f.controlIds))];
    const policyIds = [...new Set(findings.flatMap(f => f.policyIds))];
    const protection = findings.some(f => f.severity === 'high') ? 'maximum' : 'strong';
    // Controls the user declined outright are dropped after the plan is built, since they are
    // pulled in by protection level rather than by a requirement.
    const declinedControls = LOG_DECLARATIONS
      .filter(d => answers[d.key] === 'no')
      .flatMap(d => d.controls || []);
    return {
      protection,
      requirementKeys,
      controlIds,
      policyIds,
      declinedControls,
      declinedRequirements,
      declinedDespiteEvidence,
      // Retained so each policy can say WHY it is in the list.
      basis: { evidenced, standard: LOG_STANDARD_REQUIREMENTS, declared, assumed }
    };
  }

  // Re-simulates the recommended set against the stored aggregate. No re-ingest: the files
  // are already parsed and the coverage facts are still in memory.
  function setDeclaration(key, answer) {
    const la = state.logAnalysis;
    if (!LOG_DECLARATIONS.some(d => d.key === key) || !LOG_DECLARATION_ANSWERS.includes(answer)) return;
    if (la.declarations[key] === answer) return;
    const scrollPosition = { x: window.scrollX, y: window.scrollY };
    la.tenantAssumptionsExpanded = true;
    la.declarations = { ...la.declarations, [key]: answer };
    if (la.agg) la.recommendedPolicySet = buildRecommendedPolicySet(la.agg, la.findings, la.declarations);
    if (la.journeySelected?.type === 'recommendedPolicy') {
      const stillExists = (la.recommendedPolicySet?.policies || []).some(policy => policy.id === la.journeySelected.id);
      if (!stillExists) {
        la.journeySelected = null;
        logJourneySelectionOpener = null;
      }
    }
    renderLogAnalysis();
    window.scrollTo({ left: scrollPosition.x, top: scrollPosition.y, behavior: 'auto' });
    requestAnimationFrame(() => {
      window.scrollTo({ left: scrollPosition.x, top: scrollPosition.y, behavior: 'auto' });
      const selector = `.log-journey-declarations [data-declaration="${CSS.escape(key)}"][data-answer="${CSS.escape(answer)}"]`;
      $('logVisualContent')?.querySelector(selector)?.focus({ preventScroll: true });
    });
  }

  function buildStrategyFromFindings() {
    const findings = state.logAnalysis.findings;
    if (!findings.length) return;
    const plan = strategyHandOffFromFindings(findings, state.logAnalysis.declarations);
    if (!plan.requirementKeys.length) return;
    state.selectedIdentity = 'all_users';
    state.selectedTarget = 'all_resources';
    state.strategy = { ...STRATEGY_DEFAULTS, protection: plan.protection };
    plan.requirementKeys.forEach(key => { state.strategy[key] = true; });
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
    toast(`Strategy pre-selected from ${findings.length} log findings`);
  }

  function gapReportSeverityLabel(value) {
    return { high: 'High', medium: 'Medium', low: 'Low', info: 'Information' }[value] || value;
  }

  function gapReportList(items, fallback) {
    const values = (items || []).filter(Boolean);
    return values.length ? values.join(', ') : fallback;
  }

  function buildGapReportBlocks(la) {
    const blocks = [];
    const summary = la.summary;
    const set = la.recommendedPolicySet;
    const inventory = la.policyInventory;
    const stamp = new Date().toISOString().slice(0, 10);
    const range = summary.from && summary.to
      ? `${summary.from.slice(0, 10)} to ${summary.to.slice(0, 10)}`
      : 'Date range unavailable';
    const orderedFindings = [...la.findings].sort((a, b) => {
      const rank = { high: 0, medium: 1, low: 2, info: 3 };
      return (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4)
        || (b.metric.affected || 0) - (a.metric.affected || 0);
    });
    const overall = summary.high ? 'High' : summary.medium ? 'Medium' : summary.low ? 'Low' : 'Informational';
    const sourceNames = keys => gapReportList((keys || []).map(key => (LOG_SOURCES[key] || {}).label), 'None');
    const push = (...items) => items.forEach(item => blocks.push(item));

    push(
      docxPara('Conditional Access gap assessment', { style: 'Title' }),
      docxPara(`Generated by CA Architect V2 on ${stamp}. Evidence window: ${range}.`, { style: 'Subtitle' }),
      docxPara([
        docxRun('Assessment outcome: ', { bold: true }),
        docxRun(`${overall} priority. `),
        docxRun(`${summary.total} sign-ins were assessed and ${orderedFindings.length} configuration or coverage findings were identified. `),
        docxRun('This report turns those observations into an ordered remediation plan; it does not treat missing log sources or quiet accounts as proof that risk is absent.')
      ], { style: 'Callout' })
    );

    push(docxPara('Executive summary', { style: 'Heading2' }));
    push(docxTable([
      ['Measure', 'Assessment result'],
      ['Sign-ins analysed', `${summary.total} total; ${summary.success} successful; ${summary.failure} failed`],
      ['Identity and resource reach', `${summary.users} distinct users; ${summary.apps} applications; ${summary.workloads} workload identities; ${summary.guests} guest sign-ins`],
      ['Findings', `${summary.high} high; ${summary.medium} medium; ${summary.low} low; ${summary.info} informational`],
      ['Conditional Access evidence', inventory ? `${inventory.summary.total} policies observed; ${inventory.summary.enforcing} enforcing; ${inventory.summary.reportOnly} report-only; ${inventory.summary.neverMatched} never matched` : 'No authoritative policy inventory was available in the loaded log data'],
      ['Recommended replacement set', set ? `${set.policies.length} consolidated policies representing ${set.replaces.length} baseline policies` : 'No policy set was generated from the available evidence']
    ], { header: true, widths: [34, 66] }));

    push(...buildCaCoverageDocxBlocks(buildCaCoverageReport(la), 'Heading2'));
    push(...buildMfaExclusionDocxBlocks(policyOfficeMfaExclusions(inventory?.policies || []), 'Heading2'));

    push(docxPara('Finding priorities', { style: 'Heading2' }));
    push(docxTable([
      ['Priority', 'Count', 'How to use this report'],
      ['High', String(summary.high), 'Investigate immediately; validate possible active compromise before changing policy.'],
      ['Medium', String(summary.medium), 'Plan remediation and pilot the relevant controls in report-only.'],
      ['Low', String(summary.low), 'Address during policy refinement and normal hardening work.'],
      ['Information', String(summary.info), 'Validate context; some observations may be expected platform behaviour.']
    ], { header: true, widths: [22, 12, 66] }));

    push(docxPara('Evidence coverage and confidence', { style: 'Heading2' }));
    push(docxPara(`Loaded sources: ${sourceNames(summary.sourcesLoaded)}.`));
    push(docxPara(`Missing sources: ${sourceNames(summary.sourcesMissing)}.`));
    if (la.files.length) push(docxPara(`Files analysed: ${la.files.map(file => `${file.name} (${file.representedEvents} represented sign-ins from ${file.importedRowCount} imported rows)`).join('; ')}.`));
    if (la.failures.length) push(docxPara(`Files that could not be analysed: ${la.failures.map(file => file.name || file).join(', ')}.`, { style: 'Callout' }));
    (la.parseWarnings || []).forEach(note => push(docxPara(note, { bullet: true, style: 'ListParagraph' })));
    push(docxPara('Important limitation: a sign-in export records what happened during its date range. It cannot prove that an unused account, application, guest route, agent identity, location, or emergency-access path is safe. Validate the recommendations against your tenant inventory before deployment.', { italic: true }));

    push(docxPara('Detailed findings and remediation', { style: 'Heading2' }));
    if (!orderedFindings.length) {
      push(docxPara('No findings were produced from the loaded evidence. Confirm that all relevant sign-in sources and a representative date range were included.'));
    }
    orderedFindings.forEach((finding, index) => {
      const guide = LOG_REMEDIATION[finding.id] || {};
      const metric = finding.metric || {};
      const concentration = [
        (finding.topUsers || []).length ? `Users: ${finding.topUsers.map(item => `${item.name} (${item.count})`).join(', ')}` : '',
        (finding.topApps || []).length ? `Apps: ${finding.topApps.map(item => `${item.name} (${item.count})`).join(', ')}` : '',
        (finding.topLocations || []).length ? `Locations: ${finding.topLocations.map(item => `${item.name} (${item.count})`).join(', ')}` : ''
      ].filter(Boolean);
      const policyNames = (finding.policies || []).map(policy => `${policy.id}: ${tenantPolicyName(policy.displayName)}`);
      push(
        docxPara(`${index + 1}. ${gapReportSeverityLabel(finding.severity)} - ${finding.title}`, { style: 'Heading3' }),
        docxTable([
          ['Evidence', 'Result'],
          ['Affected activity', `${metric.affected} of ${metric.total} ${metric.scope || 'sign-ins'} (${metric.pct}%)`],
          ['Evidence source', sourceNames(metric.sources)],
          ['Observation', finding.detail]
        ], { header: true, widths: [28, 72] })
      );
      if (concentration.length) push(docxPara(`Where it concentrates: ${concentration.join(' | ')}`));
      if (guide.attack) push(docxPara([docxRun('Security impact. ', { bold: true }), docxRun(guide.attack)]));
      else if (guide.cause) push(docxPara([docxRun('Why it matters. ', { bold: true }), docxRun(guide.cause)]));
      push(docxPara('Recommended actions', { style: 'Heading3' }));
      const actions = (guide.fix || []).length ? guide.fix : [finding.recommendation].filter(Boolean);
      actions.forEach(action => push(docxPara(action, { bullet: true, style: 'ListParagraph' })));
      if (policyNames.length) push(docxPara([docxRun('Relevant policy controls: ', { bold: true }), docxRun(policyNames.join('; '))]));
      if (guide.verify) push(docxPara([docxRun('Validation: ', { bold: true }), docxRun(guide.verify)], { style: 'Callout' }));
    });

    push(docxPara('Recommended policy strategy', { style: 'Heading2' }));
    if (set && set.policies.length) {
      const basisCounts = set.policies.reduce((counts, item) => {
        counts[item.basis.kind] = (counts[item.basis.kind] || 0) + 1;
        return counts;
      }, {});
      push(docxPara(`${set.policies.length} consolidated policies are recommended: ${basisCounts.evidenced || 0} evidenced, ${basisCounts.standard || 0} standard, ${basisCounts.declared || 0} declared and ${basisCounts.unconfirmed || 0} unconfirmed. These policies are a replacement architecture for the ${set.replaces.length} baseline policies they represent, not an additional permanent layer.`));
      push(docxTable([['Policy to build', 'Basis', 'Purpose']].concat(set.policies.map(item => [
        tenantPolicyName(item.displayName),
        item.basis.label,
        item.summary || item.basis.detail
      ])), { header: true, widths: [42, 16, 42] }));
      if ((set.uncovered || []).length) {
        push(docxPara('Controls not included in the recommended set', { style: 'Heading3' }));
        set.uncovered.forEach(item => push(docxPara(`${item.id}: ${tenantPolicyName(item.displayName)} - ${gapReportList(item.controls.map(id => (CONTROLS[id] || {}).label), 'baseline control')}`, { bullet: true, style: 'ListParagraph' })));
      }
      if ((set.declined || []).length) {
        push(docxPara('Policy families excluded by assessment answers', { style: 'Heading3' }));
        set.declined.forEach(item => push(docxPara(`${item.question.replace(/\?$/, '')}: excluded${item.contradictsEvidence ? ' even though the loaded logs contain related evidence; review this decision before deployment' : ''}.`, { bullet: true, style: 'ListParagraph' })));
      }
      push(docxPara('Use the separate Conditional Access build guide for the exact Entra portal settings, prerequisites, and build order for every recommended policy.', { italic: true }));
    } else {
      push(docxPara('The loaded evidence did not produce a replacement policy set. Review the source coverage and assessment answers before concluding that no changes are needed.'));
    }

    push(docxPara('Recommended next steps', { style: 'Heading2' }));
    [
      'Investigate high-priority findings and possible active compromise before making broad policy changes.',
      'Confirm at least two cloud-only emergency-access accounts and exclude their dedicated group from every applicable policy.',
      'Create the recommended policies in report-only mode first and test with a non-administrator pilot identity.',
      'Use the Conditional Access What If tool to test expected and exception paths before enforcement.',
      'Review sign-in logs and Conditional Access Insights for at least one representative working cycle.',
      'Enable one policy at a time, monitor impact, and only then retire the baseline or tenant policies it replaces.',
      'Repeat this assessment after rollout to confirm that the measured gaps have reduced without creating new exclusions.'
    ].forEach(action => push(docxPara(action, { bullet: true, style: 'ListParagraph' })));

    return blocks;
  }

  function gapAssessmentSummarySheet(la, coverage) {
    const summary = la.summary;
    const range = policyOfficeEvidenceRange(summary);
    const mfaExclusions = policyOfficeMfaExclusions(la.policyInventory?.policies || []);
    const mfaIdentities = new Set(mfaExclusions.flatMap(policy => policy.identities.map(identity => identity.objectId || `${identity.identityType}:${identity.name}`)));
    const rows = [
      [xlsxCell('Conditional Access gap assessment', 'text', XLSX_STYLES.title), ''],
      [xlsxCell(`Generated locally by CA Architect V2 on ${new Date().toISOString().slice(0, 10)}. Evidence window: ${range}. Successful access without enforcing CA is separated into confirmed gaps, report-only exposure and evidence unknown; expected outside-CA activity is context only.`, 'text', XLSX_STYLES.subtitle), ''],
      ['', ''],
      ['Measure', 'Result'],
      [xlsxCell('Sign-ins analysed', 'text', XLSX_STYLES.label), xlsxCell(summary.total, 'integer')],
      [xlsxCell('Successful events', 'text', XLSX_STYLES.label), xlsxCell(summary.success, 'integer')],
      [xlsxCell('Failed events', 'text', XLSX_STYLES.label), xlsxCell(summary.failure, 'integer')],
      [xlsxCell('Protected successful access', 'text', XLSX_STYLES.label), xlsxCell(coverage.protectedSuccess, 'integer')],
      [xlsxCell('Successful access without enforcing CA', 'text', XLSX_STYLES.label), xlsxCell(coverage.reviewTotal, 'integer')],
      [xlsxCell('Confirmed scoping gap', 'text', XLSX_STYLES.label), xlsxCell(coverage.confirmedGap, 'integer')],
      [xlsxCell('Report-only exposure', 'text', XLSX_STYLES.label), xlsxCell(coverage.reportOnlyExposure, 'integer')],
      [xlsxCell('Evidence unknown', 'text', XLSX_STYLES.label), xlsxCell(coverage.evidenceUnknown, 'integer')],
      [xlsxCell('Expected outside CA', 'text', XLSX_STYLES.label), xlsxCell(coverage.expectedOutsideCa, 'integer')],
      [xlsxCell('MFA policies with observed identity exclusions', 'text', XLSX_STYLES.label), xlsxCell(mfaExclusions.length, 'integer')],
      [xlsxCell('Observed identities on MFA exclusion paths', 'text', XLSX_STYLES.label), xlsxCell(mfaIdentities.size, 'integer')],
      [xlsxCell('Successful-event reconciliation difference', 'text', XLSX_STYLES.label), xlsxCell(coverage.reconciliationDifference, 'integer')],
      [xlsxCell('Findings', 'text', XLSX_STYLES.label), xlsxCell(la.findings.length, 'integer')],
      [xlsxCell('Evidence window', 'text', XLSX_STYLES.label), xlsxCell(range, 'text', XLSX_STYLES.value)],
      [xlsxCell('Loaded sources', 'text', XLSX_STYLES.label), xlsxCell(policyOfficeList(summary.sourcesLoaded, key => LOG_SOURCES[key]?.label || key) || 'None recorded', 'text', XLSX_STYLES.value)],
      [xlsxCell('Files analysed', 'text', XLSX_STYLES.label), xlsxCell(policyOfficeList(la.files, file => `${file.name} (${file.representedEvents || 0} represented sign-ins)`) || 'Not recorded', 'text', XLSX_STYLES.value)]
    ];
    return { name: 'Summary', rows, widths: [42, 96], headerRow: 4, freezeRows: 4, merges: ['A1:B1', 'A2:B2'] };
  }

  function gapAssessmentFindingsSheet(la) {
    const headers = ['Severity', 'Finding', 'Affected', 'Total', 'Percentage', 'Scope', 'Sources', 'Observation', 'Recommendation', 'Top identities', 'Top apps / resources', 'Top devices', 'Top locations'];
    const rank = { high: 0, medium: 1, low: 2, info: 3 };
    const rows = [...la.findings]
      .sort((a, b) => (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4) || (b.metric?.affected || 0) - (a.metric?.affected || 0))
      .map(finding => [
        gapReportSeverityLabel(finding.severity),
        finding.title,
        xlsxCell(Number(finding.metric?.affected) || 0, 'integer'),
        xlsxCell(Number(finding.metric?.total) || 0, 'integer'),
        xlsxCell((Number(finding.metric?.pct) || 0) / 100, 'percentage'),
        finding.metric?.scope || 'sign-ins',
        policyOfficeList(finding.metric?.sources, key => LOG_SOURCES[key]?.label || key),
        finding.detail || '',
        finding.recommendation || '',
        policyOfficeList(finding.topUsers, item => `${item.name} (${item.count})`),
        policyOfficeList(finding.topApps, item => `${item.name} (${item.count})`),
        policyOfficeList(finding.topDevices, item => `${item.name} (${item.count})`),
        policyOfficeList(finding.topLocations, item => `${item.name} (${item.count})`)
      ]);
    return {
      name: 'Findings',
      rows: [
        [xlsxCell('Assessment findings', 'text', XLSX_STYLES.title), ...headers.slice(1).map(() => '')],
        [xlsxCell('Affected-event totals can overlap across findings and must not be added together.', 'text', XLSX_STYLES.subtitle), ...headers.slice(1).map(() => '')],
        headers,
        ...rows
      ],
      widths: [14, 42, 13, 13, 14, 20, 30, 62, 62, 40, 40, 36, 36],
      headerRow: 3,
      freezeRows: 3,
      merges: ['A1:M1', 'A2:M2']
    };
  }

  function buildGapAssessmentXlsx(la) {
    const coverage = buildCaCoverageReport(la);
    return buildXlsx([
      gapAssessmentSummarySheet(la, coverage),
      caCoverageSheet(coverage),
      caCoverageEventsSheet(coverage),
      mfaExclusionSheet(policyOfficeMfaExclusions(la.policyInventory?.policies || [])),
      gapAssessmentFindingsSheet(la)
    ]);
  }

  function exportLogReport(format = 'docx') {
    const la = state.logAnalysis;
    if (!la.summary) return;
    try {
      const blob = format === 'xlsx' ? buildGapAssessmentXlsx(la) : buildDocx(buildGapReportBlocks(la));
      const extension = format === 'xlsx' ? 'xlsx' : 'docx';
      downloadBlob(blob, `ca-architect-gap-assessment-${new Date().toISOString().slice(0, 10)}.${extension}`);
      toast(`Gap assessment exported to ${format === 'xlsx' ? 'Excel' : 'Word'}`);
    } catch (err) {
      toast(`Could not build the gap assessment: ${err.message}`);
    }
  }

  function clearLogAnalysis() {
    state.logAnalysis = emptyLogAnalysis();
    state.activeTab = 'log-analysis';
    $('logFileInput').value = '';
    renderAll();
    toast('Log analysis cleared');
  }

  function renderLogAnalysis() {
    const la = state.logAnalysis;
    const hasResults = Boolean(la.summary);
    const resultsWorkspace = $('logResultsWorkspace');
    const visualWorkspace = $('logVisualWorkspace');
    const viewControl = $('logViewControl');
    const logStatus = $('logStatus');
    const logPanel = $('logAnalysisPanel')?.querySelector('.log-panel');
    const importedRows = (la.files || []).reduce((sum, file) => sum + (Number(file.importedRowCount) || 0), 0);
    logPanel?.classList.toggle('is-large-analysis', importedRows >= LOG_LARGE_ANALYSIS_THRESHOLD);
    ['logExportDocxBtn', 'logExportXlsxBtn'].forEach(id => {
      const button = $(id);
      const format = id.includes('Xlsx') ? 'Excel workbook' : 'Word document';
      button.disabled = !la.summary;
      button.setAttribute('aria-disabled', String(!la.summary));
      button.setAttribute('aria-label', hasResults
        ? `Download the Conditional Access assessment as a ${format}`
        : `Assessment ${format} download unavailable until sign-in logs are analysed`);
      button.title = hasResults ? '' : 'Load sign-in logs to enable this assessment download';
    });
    $('logClearBtn').hidden = !hasResults && !la.failures.length;
    viewControl.hidden = !hasResults || la.view !== 'list';
    resultsWorkspace.hidden = !hasResults || la.view === 'visual';
    visualWorkspace.hidden = !hasResults || la.view !== 'visual';
    $('logUploadStage').classList.toggle('has-results', hasResults);
    $('logFilterControl').querySelectorAll('button[data-log-filter]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.logFilter === la.filter);
    });
    const sourceControl = $('logSourceFilterControl');
    if (sourceControl) {
      const available = new Set(la.findings.flatMap(f => f.metric.sources || []));
      sourceControl.hidden = !la.summary;
      sourceControl.querySelectorAll('button[data-log-source-filter]').forEach(btn => {
        const key = btn.dataset.logSourceFilter;
        btn.classList.toggle('active', key === la.sourceFilter);
        btn.disabled = key !== 'all' && !available.has(key);
      });
    }
    if (!la.summary) {
      logStatus.hidden = !la.failures.length;
      if (la.failures.length) logStatus.textContent = la.failures[0].message;
      $('logDropzone').classList.remove('compact');
      $('logDashboard').innerHTML = '';
      $('logSourceGrid').innerHTML = '';
      $('logFindings').innerHTML = '';
      $('logStrategyCta').innerHTML = '';
      $('logPolicyInventory').innerHTML = '';
      $('logVisualContent').innerHTML = '';
      if (logJourneyResizeObserver) logJourneyResizeObserver.disconnect();
      logJourneySelectionOpener = null;
      return;
    }
    const s = la.summary;
    const range = s.from && s.to ? ` spanning ${s.from.slice(0, 10)} to ${s.to.slice(0, 10)}` : '';
    // The file list and parse warnings repeat what the source tiles and the confidence panel
    // already say, so they collapse rather than pushing the findings below the fold.
    const detailCount = la.files.length + la.parseWarnings.length;
    const details = detailCount
      ? `<details class="log-status-detail">
          <summary>${esc(la.files.length)} file(s) loaded${la.parseWarnings.length ? ` · ${esc(la.parseWarnings.length)} note(s)` : ''}</summary>
          ${la.files.length ? `<ul class="log-file-list">${la.files.map(f => `<li>${esc(f.name)} — ${esc(LOG_SOURCES[f.source].label)}, ${esc(f.representedEvents)} represented sign-in(s) from ${esc(f.importedRowCount)} imported row(s)${f.empty ? ' (none in range)' : ''}</li>`).join('')}</ul>` : ''}
          ${la.parseWarnings.length ? `<ul class="log-warnings">${la.parseWarnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
        </details>`
      : '';
    // Once results are on screen the dropzone is no longer the point of the page.
    $('logDropzone').classList.add('compact');
    logStatus.hidden = false;
    logStatus.innerHTML = `Analysed <strong>${esc(s.total)}</strong> sign-ins${esc(range)} — ${esc(la.findings.length)} findings (${esc(s.high)} high).${details}`;
    const visible = la.findings.filter(f =>
      (la.filter === 'all' || f.severity === la.filter) &&
      (la.sourceFilter === 'all' || (f.metric.sources || []).includes(la.sourceFilter)));
    if (la.view === 'visual') {
      // Do not keep a second, fully populated detailed workspace behind the visual view.
      // Large imports otherwise duplicate hundreds of policy/evidence nodes during draw.
      $('logDashboard').innerHTML = '';
      $('logSourceGrid').innerHTML = '';
      $('logFindings').innerHTML = '';
      $('logStrategyCta').innerHTML = '';
      $('logPolicyInventory').innerHTML = '';
      $('logVisualContent').innerHTML = renderLogVisualWorkspace();
      applyLogJourneyTabs();
      applyLogJourneySelection();
      queueLogJourneyDraw();
    }
    else {
      $('logDashboard').innerHTML = renderLogDashboard(s);
      $('logSourceGrid').innerHTML = renderLogSourceGrid();
      $('logFindings').innerHTML = renderLogConfidence() + (visible.length
        ? visible.map(renderLogFindingCard).join('')
        : '<div class="empty-state">No findings match this filter.</div>');
      $('logStrategyCta').innerHTML = renderLogStrategyCta();
      $('logPolicyInventory').innerHTML = renderLogPolicyInventory();
      $('logVisualContent').innerHTML = '';
      if (logJourneyResizeObserver) logJourneyResizeObserver.disconnect();
    }
    scheduleScrollableRegionEnhancement();
  }

  function showLogStatus(message) {
    const status = $('logStatus');
    status.hidden = false;
    status.textContent = message;
  }

  // What this analysis can and cannot see. Placed above the findings because it governs how
  // much weight they carry: silence in an unexported log is not evidence of safety.
  function renderLogConfidence() {
    const la = state.logAnalysis;
    const agg = la.agg;
    if (!la.summary) return '';
    const missing = LOG_SOURCE_ORDER.filter(key => !(key in la.sources));
    const empty = Object.keys(la.sources).filter(key => la.sources[key].records === 0);
    const inbound = agg ? (agg.tallies['guest-uncontrolled'] || {}).count || 0 : null;
    const principals = agg ? agg.users.size : null;
    const days = la.summary.from && la.summary.to
      ? Math.max(1, Math.round((new Date(la.summary.to) - new Date(la.summary.from)) / 86400000))
      : null;

    // The source tiles above already show which exports loaded, so this states only what the
    // tiles cannot: what the missing data means for the findings.
    const facts = [];
    if (days) facts.push(`<li>Window of <strong>${esc(days)} day${days === 1 ? '' : 's'}</strong>. Anything that happens less often than this cannot appear.</li>`);
    if (principals !== null) facts.push(`<li><strong>${esc(principals)}</strong> distinct principal${principals === 1 ? '' : 's'} signed in. Accounts that stayed quiet are absent, not absent-of-risk.</li>`);
    if (inbound !== null) {
      facts.push(inbound
        ? `<li><strong>${esc(inbound)}</strong> inbound guest sign-in${inbound === 1 ? '' : 's'} observed.</li>`
        : '<li><strong>No inbound guest sign-ins</strong> in this window. If you have guest accounts, their activity is not represented here — guest access to SharePoint and Teams is frequently non-interactive.</li>');
    }

    const consequence = missing.length || empty.length
      ? `Because ${esc([...missing, ...empty].map(k => LOG_SOURCES[k].label).join(' and '))} ${missing.length + empty.length === 1 ? 'is' : 'are'} not represented, findings below are <strong>unproven rather than disproven</strong> for the traffic those logs carry. Non-interactive sign-ins in particular hold token refresh, guest resource access and much legacy authentication.`
      : 'All three supported exports contain data, so the findings below cover interactive, non-interactive and service-principal activity in this window.';

    return `<div class="status-box log-confidence">
      <strong>What this analysis could see</strong>
      <ul>${facts.join('')}</ul>
      <p>${consequence}</p>
    </div>`;
  }

  function renderLogDashboard(summary) {
    const tiles = [
      ['Sign-ins', summary.total],
      ['Users', summary.users],
      ['Apps / resources', summary.apps + summary.workloads],
      ['Guests', summary.guests],
      ['Findings', state.logAnalysis.findings.length],
      ['High severity', summary.high]
    ].map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join('');
    return tiles;
  }

  function renderLogSourceGrid() {
    const sources = state.logAnalysis.sources;
    return LOG_SOURCE_ORDER.map(key => {
      const entry = sources[key];
      const chip = !entry
        ? '<em class="status-chip import-different">not loaded</em>'
        : entry.records === 0
          ? '<em class="status-chip import-extra">no activity in range</em>'
          : '<em class="status-chip import-exact">loaded</em>';
      return `<article class="log-source-tile${entry ? '' : ' missing'}">
        <span>${esc(LOG_SOURCES[key].short)}</span>
        <strong>${esc(entry ? entry.representedEvents : 0)}</strong>
        ${entry && entry.importedRowCount !== entry.representedEvents ? `<small>${esc(entry.importedRowCount)} grouped row(s)</small>` : ''}
        ${chip}
      </article>`;
    }).join('');
  }

  function logJourneyIcon(name, className) {
    const paths = {
      users: '<path d="M8.5 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7-1a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM3 19c0-3 2.2-5 5.5-5s5.5 2 5.5 5M14 14.5c.5-.2 1-.3 1.5-.3 3 0 5 1.8 5 4.8"/>',
      clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
      applications: '<rect x="4" y="4" width="7" height="7" rx="1"/><rect x="13" y="4" width="7" height="7" rx="1"/><rect x="4" y="13" width="7" height="7" rx="1"/><rect x="13" y="13" width="7" height="7" rx="1"/>',
      workload: '<path d="M7 7.5h10M7 12h10M7 16.5h6"/><rect x="3.5" y="4" width="17" height="16" rx="2"/>',
      'shield-check': '<path d="M12 3.5 19 6v5.2c0 4.5-2.7 7.6-7 9.3-4.3-1.7-7-4.8-7-9.3V6l7-2.5Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/>',
      'document-search': '<path d="M7 3.5h7l4 4V14M14 3.5v4h4M9 9h4M9 12h3"/><path d="m16.5 18.5 3 3"/><circle cx="13.5" cy="15.5" r="3.5"/>',
      branch: '<path d="M7 4v12a4 4 0 0 0 4 4h6M7 9h6a4 4 0 0 0 4-4V4"/><circle cx="7" cy="4" r="1.5"/><circle cx="17" cy="4" r="1.5"/><circle cx="17" cy="20" r="1.5"/>',
      filter: '<path d="M4 5h16l-6.2 7v5.5l-3.6 1.8V12L4 5Z"/>',
      'shield-off': '<path d="M5 5.8 12 3.5 19 6v5.2c0 2-.5 3.7-1.5 5.1M15 19c-.9.6-1.9 1.1-3 1.5-4.3-1.7-7-4.8-7-9.3V8.5M3.5 3.5l17 17"/>',
      blocked: '<circle cx="12" cy="12" r="8.5"/><path d="m6 18 12-12"/>',
      unlock: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7.5a4 4 0 0 1 7.5-2"/>',
      warning: '<path d="m12 3 9 17H3L12 3Z"/><path d="M12 9v5M12 17.5h.01"/>',
      target: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="M12 3.5V7M20.5 12H17M12 20.5V17M3.5 12H7"/>',
      key: '<circle cx="8.5" cy="14.5" r="4.5"/><path d="m12 11 7-7M16 7l2 2M14 9l2 2"/>',
      device: '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
      session: '<rect x="4" y="5" width="16" height="14" rx="2"/><path d="M4 9h16M8 5v4M16 5v4"/>',
      risk: '<path d="M12 3.5 19 6v5.2c0 4.5-2.7 7.6-7 9.3-4.3-1.7-7-4.8-7-9.3V6l7-2.5Z"/><path d="M12 8v5M12 16.5h.01"/>',
      location: '<path d="M19 10c0 5-7 10.5-7 10.5S5 15 5 10a7 7 0 1 1 14 0Z"/><circle cx="12" cy="10" r="2.5"/>',
      pulse: '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
      external: '<path d="M10 5H5v14h14v-5M13 4h7v7M20 4l-9 9"/>',
      certificate: '<rect x="4" y="3.5" width="16" height="13" rx="2"/><path d="M8 8h8M8 11h5M10 16.5v4l2-1.2 2 1.2v-4"/>',
      check: '<path d="m5 12.5 4 4L19 6.5"/>',
      eyeOff: '<path d="M4 4l16 16M9.5 6.5A9.8 9.8 0 0 1 12 6c5.5 0 9 6 9 6a16 16 0 0 1-2.1 2.8M6.1 8.2A16 16 0 0 0 3 12s3.5 6 9 6c1 0 2-.2 2.8-.5M10 10a3 3 0 0 0 4 4"/>'
    };
    return `<svg class="log-journey-icon${className ? ` ${esc(className)}` : ''}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${paths[name] || paths.pulse}</svg>`;
  }

  const LOG_JOURNEY_STATUS_META = {
    protected: { label: 'Protected', icon: 'shield-check' },
    gap: { label: 'Gap', icon: 'warning' },
    partial: { label: 'Partial', icon: 'pulse' },
    review: { label: 'Review', icon: 'document-search' },
    blind: { label: 'Blind spot', icon: 'eyeOff' },
    noIssue: { label: 'No issue observed', icon: 'check' }
  };

  function logJourneyTopEntries(map, cap) {
    return [...(map || new Map()).entries()].sort((a, b) => b[1] - a[1]).slice(0, cap || 8)
      .map(([name, count]) => ({ name, count }));
  }

  function logJourneyDomId(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  }

  function logJourneyPositiveCount(element) {
    const la = state.logAnalysis;
    const policies = la.policyInventory?.policies || [];
    if (element.positive === 'enforcing') return la.agg?.journey.decisions.get('enforcing') || 0;
    if (element.positive === 'session') {
      return policies.filter(policy => policy.state === 'enforcing' && policy.sessions.length)
        .reduce((sum, policy) => sum + policy.applied, 0);
    }
    if (element.positive === 'mfa') {
      return policies.filter(policy => policy.state === 'enforcing' && (
        policy.authStrength.length || policy.grants.some(grant => /mfa|authenticationstrength/i.test(`${grant.name} ${grant.label}`))
      )).reduce((sum, policy) => sum + policy.applied, 0);
    }
    if (element.positive === 'authStrength') {
      return policies.filter(policy => policy.state === 'enforcing' && policy.authStrength.length)
        .reduce((sum, policy) => sum + policy.applied, 0);
    }
    if (element.positive === 'deviceCompliance') {
      return policies.filter(policy => policy.state === 'enforcing' && policy.grants.some(grant => (
        /compliantdevice|domainjoineddevice|hybridjoined/i.test(`${grant.name} ${grant.label}`)
      ))).reduce((sum, policy) => sum + policy.applied, 0);
    }
    if (element.positive === 'byod') {
      return policies.filter(policy => policy.state === 'enforcing' && (
        policy.grants.some(grant => /approvedapplication|compliantapplication|appprotection/i.test(`${grant.name} ${grant.label}`))
        || policy.sessions.some(session => /applicationenforcedrestrictions|cloudappsecurity/i.test(`${session.name} ${session.label}`))
      )).reduce((sum, policy) => sum + policy.applied, 0);
    }
    return 0;
  }

  function logJourneyEvidenceAvailable(element) {
    const la = state.logAnalysis;
    const sources = element.sources || [];
    if (sources.some(key => !(key in la.sources))) return false;
    if (!element.field) return true;
    return sources.every(key => {
      const loaded = la.sources[key];
      if (!loaded || loaded.records === 0) return true;
      return Boolean(la.agg?.sourceStats[key]?.fieldsSeen?.has(element.field));
    });
  }

  function logJourneyElementStatus(element, findings) {
    const available = logJourneyEvidenceAvailable(element);
    const positive = logJourneyPositiveCount(element);
    if (findings.length) {
      if (positive > 0 || !available) return 'partial';
      if (element.findingStatus) return element.findingStatus;
      return findings.some(finding => finding.severity === 'high' || finding.severity === 'medium') ? 'gap' : 'review';
    }
    if (!available) return 'blind';
    if (positive > 0) return 'protected';
    if (element.defaultStatus) return element.defaultStatus;
    return 'noIssue';
  }

  function logJourneyStatusReason(status, findingCount, positive) {
    if (status === 'protected') return `${positive} observed policy application${positive === 1 ? '' : 's'} show an applicable control acting.`;
    if (status === 'gap') return `${findingCount} observed finding${findingCount === 1 ? ' needs' : 's need'} attention.`;
    if (status === 'partial') return 'Both useful evidence and a gap or blind spot are present.';
    if (status === 'review') return 'The evidence is contextual, sampled or outside direct CA enforcement.';
    if (status === 'blind') return 'A required source or policy field was not loaded.';
    return 'Activity was assessed, with no issue or enforced control demonstrated here.';
  }

  function buildLogJourneyElement(element, parent) {
    const findings = (state.logAnalysis.findings || []).filter(finding => element.findingIds.includes(finding.id));
    const positive = logJourneyPositiveCount(element);
    const status = logJourneyElementStatus(element, findings);
    const severity = ['high', 'medium', 'low', 'info'].reduce((counts, level) => {
      counts[level] = findings.filter(finding => finding.severity === level).length;
      return counts;
    }, {});
    const observedPolicies = logJourneyPolicyEvidence(element);
    const recommendedPolicies = logJourneyRecommendedPolicyEvidence(element);
    return {
      ...element,
      parentId: parent.id,
      parentLabel: parent.label,
      findings,
      severity,
      observedPolicies,
      recommendedPolicies,
      guidance: LOG_JOURNEY_GUIDANCE[element.id] || null,
      positive,
      status,
      statusReason: logJourneyStatusReason(status, findings.length, positive)
    };
  }

  function buildLogJourneyModel() {
    const la = state.logAnalysis;
    const journey = la.agg?.journey || createSignInAgg().journey;
    const sourceIcons = { interactive: 'users', nonInteractive: 'clock', application: 'applications' };
    const sources = LOG_SOURCE_ORDER.map(id => {
      const loaded = la.sources[id];
      return {
        id,
        label: LOG_SOURCES[id].short,
        description: LOG_SOURCES[id].label,
        icon: sourceIcons[id],
        count: journey.sources.get(id) || 0,
        loaded: Boolean(loaded),
        empty: Boolean(loaded && loaded.records === 0),
        tone: loaded ? 'measured' : 'blind'
      };
    });
    const decisions = LOG_JOURNEY_DECISIONS.map(item => ({ ...item, count: journey.decisions.get(item.id) || 0 }));
    const outcomes = LOG_JOURNEY_OUTCOMES.map(item => ({ ...item, count: journey.outcomes.get(item.id) || 0 }));
    const links = [];
    journey.sourceDecision.forEach((value, key) => {
      if (!value) return;
      const [source, decision] = key.split('|');
      const meta = LOG_JOURNEY_DECISIONS.find(item => item.id === decision);
      links.push({ fromType: 'source', fromId: source, toType: 'decision', toId: decision, value, tone: meta?.tone || 'neutral' });
    });
    journey.decisionOutcome.forEach((value, key) => {
      if (!value) return;
      const [decision, outcome] = key.split('|');
      const meta = LOG_JOURNEY_OUTCOMES.find(item => item.id === outcome);
      links.push({ fromType: 'decision', fromId: decision, toType: 'outcome', toId: outcome, value, tone: meta?.tone || 'neutral' });
    });
    const stages = LOG_JOURNEY_STAGES.map(stage => ({
      ...stage,
      elements: stage.elements.map(element => buildLogJourneyElement(element, stage))
    }));
    const adjacent = LOG_JOURNEY_ADJACENT.map(item => buildLogJourneyElement(item, { id: 'adjacent', label: 'Adjacent controls' }));
    const severity = ['high', 'medium', 'low', 'info'].reduce((counts, level) => {
      counts[level] = la.findings.filter(finding => finding.severity === level).length;
      return counts;
    }, {});
    const observedPolicies = la.policyInventory?.policies || [];
    const recommendedPolicies = la.recommendedPolicySet?.policies || [];
    return {
      journey,
      deviceContext: la.agg?.deviceContext || createSignInAgg().deviceContext,
      sources,
      decisions,
      outcomes,
      links,
      stages,
      adjacent,
      severity,
      observedPolicies,
      recommendedPolicies,
      summary: {
        signIns: la.summary?.total || 0,
        users: la.summary?.users || 0,
        apps: (la.summary?.apps || 0) + (la.summary?.workloads || 0),
        guests: la.summary?.guests || 0,
        findings: la.findings.length
      }
    };
  }

  function logJourneyNodeValue(node, type) {
    if (type === 'source' && !node.loaded) return 'Not loaded';
    if (type === 'source' && node.empty) return 'No activity';
    return `${node.count.toLocaleString()} event${node.count === 1 ? '' : 's'}`;
  }

  function renderLogJourneyNode(node, type) {
    const quiet = !node.count || (type === 'source' && !node.loaded);
    return `<button type="button" class="log-journey-node log-journey-tone-${esc(node.tone || 'neutral')}${quiet ? ' is-quiet' : ''}" data-journey-node="${esc(`${type}:${node.id}`)}" data-journey-type="${esc(type)}" data-journey-id="${esc(node.id)}" aria-label="${esc(`${node.label}, ${logJourneyNodeValue(node, type)}`)}">
      <span class="log-journey-node-icon">${logJourneyIcon(node.icon)}</span>
      <span class="log-journey-node-copy"><strong>${esc(node.label)}</strong><small>${esc(logJourneyNodeValue(node, type))}</small></span>
    </button>`;
  }

  function renderLogJourneyStatus(status, compact) {
    const meta = LOG_JOURNEY_STATUS_META[status] || LOG_JOURNEY_STATUS_META.review;
    return `<span class="log-journey-status log-journey-status-${esc(status)}${compact ? ' is-compact' : ''}">${logJourneyIcon(meta.icon)}<span>${esc(meta.label)}</span></span>`;
  }

  function renderLogJourneySeverityCounts(counts, options) {
    const settings = options || {};
    const levels = ['high', 'medium', 'low', 'info'];
    return `<div class="log-journey-severity-counts${settings.compact ? ' is-compact' : ''}" aria-label="Finding severity counts">${levels.map(level => {
      const value = counts[level] || 0;
      if (settings.interactive) {
        return `<button type="button" class="log-journey-severity log-journey-severity-${level}" data-journey-type="severity" data-journey-id="${level}" aria-pressed="false"><strong>${esc(value)}</strong><span>${esc(level)}</span></button>`;
      }
      return value ? `<span class="log-journey-severity log-journey-severity-${level}"><strong>${esc(value)}</strong><span>${esc(level)}</span></span>` : '';
    }).join('')}</div>`;
  }

  function renderLogJourneyElement(element) {
    const actionCounts = element.recommendedPolicies.reduce((counts, policy) => {
      counts[policy.actionTier] = (counts[policy.actionTier] || 0) + 1;
      return counts;
    }, {});
    const recommendationSummary = element.recommendedPolicies.length
      ? `${actionCounts.actNow || 0} act now · ${actionCounts.validateFirst || 0} validate · ${actionCounts.optionalAdvanced || 0} optional`
      : '0 proposed';
    return `<article class="log-journey-element log-journey-element-status-${esc(element.status)}" data-journey-element="${esc(element.id)}">
      <button type="button" class="log-journey-element-head" data-journey-type="element" data-journey-id="${esc(element.id)}">
        <span class="log-journey-element-icon">${logJourneyIcon(element.icon)}</span>
        <span><strong>${esc(element.label)}</strong><small>${esc(element.statusReason)}</small></span>
        ${renderLogJourneyStatus(element.status, true)}
        ${renderLogJourneySeverityCounts(element.severity, { compact: true })}
        <span class="log-journey-policy-counts">${esc(element.observedPolicies.length)} observed · ${esc(recommendationSummary)}</span>
      </button>
      ${element.findings.length ? `<div class="log-journey-findings">${element.findings.map(finding => `<button type="button" class="log-journey-finding" data-journey-type="finding" data-journey-id="${esc(finding.id)}">
        <span class="log-journey-finding-mark is-${esc(finding.severity)}" aria-hidden="true"></span>
        <span class="log-journey-finding-title">${esc(finding.title)}</span>
        <span class="log-journey-finding-meta">${esc(finding.metric.affected)} affected · ${esc(finding.severity)}</span>
      </button>`).join('')}</div>` : ''}
    </article>`;
  }

  function renderLogJourneyStage(stage, index) {
    const findingCount = stage.elements.reduce((sum, element) => sum + element.findings.length, 0);
    const severity = ['high', 'medium', 'low', 'info'].reduce((counts, level) => {
      counts[level] = stage.elements.reduce((sum, element) => sum + (element.severity[level] || 0), 0);
      return counts;
    }, {});
    return `<section class="log-journey-stage" data-journey-stage="${esc(stage.id)}">
      <div class="log-journey-stage-head">
        <span class="log-journey-stage-number">${esc(String(index + 1).padStart(2, '0'))}</span>
        <span class="log-journey-stage-icon">${logJourneyIcon(stage.icon)}</span>
        <span><strong>${esc(stage.label)}</strong><small>${esc(stage.summary)}</small></span>
        <span class="log-journey-stage-summary"><em>${esc(findingCount)} finding${findingCount === 1 ? '' : 's'}</em>${renderLogJourneySeverityCounts(severity, { compact: true })}</span>
      </div>
      <div class="log-journey-stage-elements">${stage.elements.map(renderLogJourneyElement).join('')}</div>
    </section>`;
  }

  function renderLogJourneySummary(model) {
    const metrics = [
      ['Sign-ins', model.summary.signIns],
      ['Users', model.summary.users],
      ['Apps / resources', model.summary.apps],
      ['Guests', model.summary.guests],
      ['Findings', model.summary.findings]
    ];
    return `<section class="log-journey-summary" aria-labelledby="logJourneySummaryTitle">
      <div class="log-journey-summary-head"><div><span class="eyebrow">Assessment at a glance</span><h3 id="logJourneySummaryTitle">Measured scope and priority</h3></div><p>Counts match the detailed assessment. Severity highlights evidence without hiding the rest of the map.</p></div>
      <div class="log-journey-summary-grid">
        <div class="log-journey-metrics">${metrics.map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value.toLocaleString())}</strong></article>`).join('')}</div>
        <article class="log-journey-severity-card"><span>Severity</span>${renderLogJourneySeverityCounts(model.severity, { interactive: true })}</article>
      </div>
      <div class="log-journey-source-summary" aria-label="Sign-in source coverage">${model.sources.map(source => `<button type="button" class="log-journey-source-card${source.loaded ? '' : ' is-blind'}" data-journey-type="source" data-journey-id="${esc(source.id)}" aria-pressed="false">
        <span class="log-journey-source-icon">${logJourneyIcon(source.icon)}</span><span><strong>${esc(source.label)}</strong><small>${esc(logJourneyNodeValue(source, 'source'))}</small></span><em>${source.loaded ? (source.empty ? 'No activity' : 'Loaded') : 'Blind spot'}</em>
      </button>`).join('')}</div>
    </section>`;
  }

  function logJourneyPriorityData(model) {
    const priorityLevel = ['high', 'medium', 'low', 'info'].find(level => model.severity[level]) || 'info';
    const priorityFindings = state.logAnalysis.findings
      .filter(finding => finding.severity === priorityLevel)
      .sort((a, b) => (b.metric.affected || 0) - (a.metric.affected || 0) || a.title.localeCompare(b.title));
    const blockedCount = model.journey.outcomes.get('blocked') || 0;
    const protectedSuccessCount = model.journey.outcomes.get('protectedSuccess') || 0;
    const protectedCount = blockedCount + protectedSuccessCount;
    const protectionPct = model.journey.total ? Math.round(protectedCount / model.journey.total * 1000) / 10 : 0;
    const protectedSources = new Map();
    [...model.journey.routes.values()].forEach(route => {
      if (!['blocked', 'protectedSuccess'].includes(route.outcome)) return;
      incrementJourneyMap(protectedSources, route.source, route.count);
    });
    const enforcingPolicies = model.observedPolicies
      .filter(policy => policy.state === 'enforcing' && policy.applied > 0)
      .sort((a, b) => b.applied - a.applied || b.evaluations - a.evaluations || a.name.localeCompare(b.name));
    const sortPolicies = policies => [...policies]
      .sort((a, b) => logRecommendationPriority(b) - logRecommendationPriority(a) || a.displayName.localeCompare(b.displayName));
    const actNowPolicies = sortPolicies(model.recommendedPolicies.filter(policy => policy.actionTier === 'actNow'));
    const validateFirstPolicies = sortPolicies(model.recommendedPolicies.filter(policy => policy.actionTier === 'validateFirst'));
    const optionalPolicies = sortPolicies(model.recommendedPolicies.filter(policy => policy.actionTier === 'optionalAdvanced'));
    const elements = [...model.stages.flatMap(stage => stage.elements), ...model.adjacent];
    return {
      priorityLevel,
      priorityCount: priorityFindings.length,
      priorityFindings,
      blockedCount,
      protectedSuccessCount,
      protectedCount,
      protectionPct,
      protectedSources,
      enforcingPolicies,
      actNowPolicies,
      validateFirstPolicies,
      optionalPolicies,
      elements,
      evidenceLimits: elements.filter(element => ['blind', 'review'].includes(element.status))
    };
  }

  function logJourneyPriorityDetail(id, model) {
    const priority = logJourneyPriorityData(model);
    const findingIds = new Set(priority.priorityFindings.map(finding => finding.id));
    const connectedGapElements = priority.elements.filter(element => element.findings.some(finding => findingIds.has(finding.id)));
    const protectedNames = new Set(priority.enforcingPolicies.map(policy => policy.name));
    const protectedElements = priority.elements.filter(element => element.observedPolicies.some(policy => protectedNames.has(policy.name)));
    const elementLink = element => `<button type="button" class="log-journey-inline-link" data-journey-type="element" data-journey-id="${esc(element.id)}">${esc(element.label)}</button>`;
    const findingLink = finding => `<button type="button" class="log-journey-inline-link" data-journey-type="finding" data-journey-id="${esc(finding.id)}">${esc(finding.title)}</button>`;
    const policyLink = policy => `<button type="button" class="log-journey-inline-link" data-journey-type="${policy.actionTier ? 'recommendedPolicy' : 'observedPolicy'}" data-journey-id="${esc(policy.actionTier ? policy.id : policy.name)}">${esc(policy.actionTier ? tenantPolicyName(policy.displayName) : policy.name)}</button>`;
    if (id === 'gaps') {
      const firstFinding = priority.priorityFindings[0];
      const firstGuide = firstFinding ? LOG_REMEDIATION[firstFinding.id] || {} : {};
      const firstAction = firstFinding ? (firstGuide.fix?.[0] || firstFinding.recommendation) : '';
      const limitList = priority.evidenceLimits.slice(0, 6);
      return {
        title: priority.priorityCount ? `${priority.priorityLevel.charAt(0).toUpperCase()}${priority.priorityLevel.slice(1)} findings to investigate first` : 'No priority gap was observed',
        kicker: `${priority.priorityCount} highest-priority finding${priority.priorityCount === 1 ? '' : 's'}`,
        status: priority.priorityCount && ['high', 'medium'].includes(priority.priorityLevel) ? 'gap' : 'review',
        body: [
          renderLogJourneyEvidenceSection('Why this is first', `<p>${priority.priorityCount ? `These are the highest-severity findings produced from the loaded evidence. Affected counts are shown per finding and are deliberately not added together because the same sign-in can drive more than one finding.` : 'No gap finding was produced. That does not prove universal protection; the controls below still show where evidence was missing or intent needs review.'}</p>`),
          renderLogJourneyEvidenceSection('Highest-priority evidence', priority.priorityCount ? `<ul>${priority.priorityFindings.map(finding => `<li>${findingLink(finding)} — ${esc(finding.metric.affected)} affected · ${esc((finding.metric.sources || []).map(source => LOG_SOURCES[source]?.short || source).join(', ') || 'loaded evidence')}</li>`).join('')}</ul>` : limitList.length ? `<ul>${limitList.map(element => `<li>${elementLink(element)} — ${esc(LOG_JOURNEY_STATUS_META[element.status].label)}</li>`).join('')}</ul>` : '<p>No blind-spot or review control was identified in the loaded activity.</p>'),
          renderLogJourneyEvidenceSection('Connected controls', connectedGapElements.length ? `<p>${connectedGapElements.map(elementLink).join(' · ')}</p>` : '<p>No control relationship was inferred beyond the evidence limits shown above.</p>'),
          renderLogJourneyEvidenceSection('Most useful next step', firstAction ? `<p>${esc(firstAction)}</p><p>${findingLink(firstFinding)} opens the evidence, remediation and validation path.</p>` : '<p>Review blind spots and load a representative JSON sign-in export before treating this as a clean result.</p>')
        ].join('')
      };
    }
    if (id === 'protection') {
      const sourceLabels = Object.fromEntries(LOG_SOURCE_ORDER.map(key => [key, LOG_SOURCES[key].short]));
      const policyEvidence = priority.enforcingPolicies.length
        ? `<ul>${priority.enforcingPolicies.slice(0, 8).map(policy => `<li>${policyLink(policy)} — ${esc(policy.applied.toLocaleString())} recorded policy application${policy.applied === 1 ? '' : 's'}</li>`).join('')}</ul><p class="log-journey-evidence-muted">Policy application totals are not unique event counts because more than one policy can act on the same sign-in.</p>`
        : '<p>No enforcing policy application was recorded in the available per-policy evidence.</p>';
      return {
        title: 'Protection demonstrated in this evidence window',
        kicker: `${priority.protectedCount.toLocaleString()} unique events · ${priority.protectionPct}%`,
        status: priority.protectedCount ? 'protected' : 'review',
        body: [
          renderLogJourneyEvidenceSection('Measured protection', `<dl class="log-journey-evidence-facts"><div><dt>Unique protected events</dt><dd>${esc(priority.protectedCount.toLocaleString())}</dd></div><div><dt>Share of all events</dt><dd>${esc(priority.protectionPct)}%</dd></div><div><dt>Blocked by CA</dt><dd>${esc(priority.blockedCount.toLocaleString())}</dd></div><div><dt>Protected access succeeded</dt><dd>${esc(priority.protectedSuccessCount.toLocaleString())}</dd></div></dl><p>${priority.protectedCount ? 'These outcomes are mutually exclusive classifications from the measured journey.' : 'Zero classified protected events means protection was not demonstrated in this evidence window; it does not prove that the tenant has no protective configuration.'}</p>`),
          renderLogJourneyEvidenceSection('Where it was seen', `<h5>By sign-in source</h5>${renderLogJourneyFactList(logJourneyTopEntries(priority.protectedSources, 8), sourceLabels)}`),
          renderLogJourneyEvidenceSection('Policies observed acting', policyEvidence),
          renderLogJourneyEvidenceSection('Controls demonstrated', protectedElements.length ? `<p>${protectedElements.map(elementLink).join(' · ')}</p><p>Open a control to see the recorded policy evidence and any gaps on the same path.</p>` : '<p>No primary control relationship could be established from the per-policy fields returned.</p>')
        ].join('')
      };
    }
    if (id === 'actions') {
      const reasonCounts = new Map();
      priority.optionalPolicies.forEach(policy => (policy.reasonLabels || []).forEach(reason => incrementJourneyMap(reasonCounts, reason, 1)));
      const policyList = policies => policies.length
        ? `<ol>${policies.map(policy => `<li>${policyLink(policy)} — ${esc(policy.basis.label)} · ${esc(policy.drivers.length)} finding driver${policy.drivers.length === 1 ? '' : 's'} · ${esc(coverageHeadline(policy.coverage))}${policy.reasonLabels?.length ? `<span class="log-journey-reason-labels">${policy.reasonLabels.map(label => `<em>${esc(label)}</em>`).join('')}</span>` : ''}${policy.unresolvedPrerequisites?.length ? `<small>${esc(policy.unresolvedPrerequisites.length)} unresolved prerequisite${policy.unresolvedPrerequisites.length === 1 ? '' : 's'}</small>` : ''}</li>`).join('')}</ol>`
        : '<p>No policy currently sits in this action tier.</p>';
      const first = priority.actNowPolicies[0] || priority.validateFirstPolicies[0];
      return {
        title: 'Recommended policy actions in priority order',
        kicker: `${priority.actNowPolicies.length} act now · ${priority.validateFirstPolicies.length} validate first · ${priority.optionalPolicies.length} optional`,
        status: 'review',
        body: [
          renderLogJourneyEvidenceSection('Act now', `${policyList(priority.actNowPolicies)}<p class="log-journey-evidence-muted">Act now means begin investigation, design and a staged rollout. It never means enable a policy immediately.</p>`),
          renderLogJourneyEvidenceSection('Validate first', policyList(priority.validateFirstPolicies)),
          renderLogJourneyEvidenceSection('Optional / advanced', priority.optionalPolicies.length ? `<p>${esc(priority.optionalPolicies.length)} proposal${priority.optionalPolicies.length === 1 ? '' : 's'} depend only on unanswered assumptions, preview features, adjacent controls or unobserved specialist scenarios.</p>${reasonCounts.size ? renderLogJourneyFactList(logJourneyTopEntries(reasonCounts, 8)) : ''}` : '<p>No optional proposal is waiting behind unanswered assumptions.</p>'),
          renderLogJourneyEvidenceSection('Start here', first ? `<p>${first.actionTier === 'actNow' ? 'The first Act now policy has the strongest direct evidence and affected-event basis.' : 'No Act now policy is available, so begin by resolving the prerequisites on the highest-ranked Validate first policy.'}</p>${first.unresolvedPrerequisites?.length ? `<p><strong>Resolve:</strong> ${esc(first.unresolvedPrerequisites.map(item => item.label).join(' · '))}</p>` : '<p>Use emergency-access exclusions, a pilot group and report-only impact review before staged enablement.</p>'}` : '<p>Resolve the evidence limits and tenant assumptions before building a policy set.</p>'),
          renderLogJourneyEvidenceSection('Continue in the workbench', '<p>The policy action board keeps observed runtime evidence separate from proposed controls.</p><button type="button" class="btn secondary" data-log-scroll-policy-board>Open policy action board</button>')
        ].join('')
      };
    }
    return null;
  }

  function renderLogJourneyPriorityOverview(model) {
    const priority = logJourneyPriorityData(model);
    const selected = state.logAnalysis.journeySelected?.type === 'priority' ? state.logAnalysis.journeySelected.id : '';
    const card = (id, icon, tone, label, headline, description) => `<button type="button" class="log-journey-overview-card is-${esc(tone)}" data-journey-type="priority" data-journey-id="${esc(id)}" aria-expanded="${selected === id}" aria-controls="logJourneyPriorityTray" aria-pressed="${selected === id}">
      <span class="log-journey-overview-icon is-${esc(tone)}">${logJourneyIcon(icon)}</span>
      <span class="log-journey-overview-copy"><span>${esc(label)}</span><strong>${esc(headline)}</strong><p>${esc(description)}</p></span>
      <span class="log-journey-overview-cue" aria-hidden="true">${selected === id ? 'Close guidance' : 'View guidance'}</span>
    </button>`;
    const trayDetail = selected ? logJourneyPriorityDetail(selected, model) : null;
    return `<div class="log-journey-overview">
      ${card('gaps', 'warning', 'gap', 'Priority gaps', priority.priorityCount ? `${priority.priorityCount} ${priority.priorityLevel} finding${priority.priorityCount === 1 ? '' : 's'}` : 'No gaps observed', priority.priorityCount ? 'Start with the highest-severity evidence in the control rail below.' : 'Missing sources and quiet activity still remain evidence limits.')}
      ${card('protection', 'shield-check', 'protected', 'Demonstrated protection', `${priority.protectedCount.toLocaleString()} events · ${priority.protectionPct}%`, `${priority.enforcingPolicies.length} enforcing ${priority.enforcingPolicies.length === 1 ? 'policy was' : 'policies were'} observed acting in this window.`)}
      ${card('actions', 'target', 'next', 'Next policy actions', `${priority.actNowPolicies.length} act now · ${priority.validateFirstPolicies.length} validate first`, `${priority.optionalPolicies.length} optional or advanced proposal${priority.optionalPolicies.length === 1 ? '' : 's'} remain available below.`)}
    </div>${trayDetail ? `<section class="log-journey-priority-tray" id="logJourneyPriorityTray" role="region" aria-labelledby="logJourneyPriorityTrayTitle">
      <header><div><span class="eyebrow">${esc(trayDetail.kicker)}</span><h4 id="logJourneyPriorityTrayTitle">${esc(trayDetail.title)}</h4></div><div>${renderLogJourneyStatus(trayDetail.status, false)}<button type="button" class="btn secondary" data-log-journey-clear>Close details</button></div></header>
      <div class="log-journey-priority-tray-reveal"><div class="log-journey-priority-tray-body">${trayDetail.body}</div></div>
    </section>` : ''}`;
  }

  function renderLogJourneyEvidence(model) {
    const selection = state.logAnalysis.journeySelected;
    const prioritySelection = selection?.type === 'priority';
    const detail = selection && !prioritySelection ? logJourneyEntityDetail(selection.type, selection.id) : null;
    return `<section class="log-journey-evidence" id="logJourneyEvidence" aria-live="polite" aria-labelledby="logJourneyEvidenceTitle">
      <header class="log-journey-evidence-head">
        <div><span class="eyebrow">${detail ? esc(detail.kicker) : 'Priority overview'}</span><h3 id="logJourneyEvidenceTitle" tabindex="-1">${detail ? esc(detail.title) : 'What needs attention first'}</h3></div>
        <div class="log-journey-evidence-actions">${detail ? `${renderLogJourneyStatus(detail.status, false)}<button type="button" class="btn secondary" data-log-journey-clear>Back to overview</button>` : '<span>Select any item for measured evidence and next steps.</span>'}</div>
      </header>
      <div class="log-journey-evidence-body">${detail ? detail.body : renderLogJourneyPriorityOverview(model)}</div>
    </section>`;
  }

  function renderLogJourneyDeclarationDisclosure(model) {
    const answers = state.logAnalysis.declarations || defaultDeclarations();
    const unanswered = LOG_DECLARATIONS.filter(item => answers[item.key] === 'unknown').length;
    const rows = LOG_DECLARATIONS.map(item => {
      const current = answers[item.key] || 'unknown';
      const affected = model.recommendedPolicies.filter(policy => (policy.declarationKeys || []).includes(item.key));
      const impact = current === 'unknown'
        ? `${affected.length} proposed ${affected.length === 1 ? 'policy' : 'policies'} affected · Yes can promote or retain · No can remove incompatible proposals`
        : current === 'yes'
          ? `${affected.length} proposed ${affected.length === 1 ? 'policy' : 'policies'} currently confirmed or retained`
          : 'Incompatible proposals removed; any contradictory measured finding remains visible as a warning';
      const buttons = LOG_DECLARATION_ANSWERS.map(value => `<button type="button" class="log-declaration-btn${current === value ? ' active' : ''}" data-declaration="${esc(item.key)}" data-answer="${esc(value)}" aria-pressed="${current === value}">${esc({ yes: 'Yes', unknown: 'Not sure', no: 'No' }[value])}</button>`).join('');
      return `<div class="log-declaration"><div><strong>${esc(item.question)}</strong><p>${esc(item.why)}</p><small class="log-declaration-impact">${esc(impact)}</small></div><div class="log-declaration-answers" role="group" aria-label="${esc(item.question)}">${buttons}</div></div>`;
    }).join('');
    return `<details class="log-journey-declarations"${state.logAnalysis.tenantAssumptionsExpanded ? ' open' : ''}><summary><span>${logJourneyIcon('document-search')}</span><span><strong>Tenant assumptions</strong><small>${unanswered ? `${unanswered} unanswered — proposed policies include caveats` : 'All questions answered'}</small></span></summary><div><p>These answers change recommendations only. They do not change measured sign-in evidence.</p><div class="log-declaration-list">${rows}</div></div></details>`;
  }

  function renderLogJourneyDeclinedWarnings() {
    const declined = state.logAnalysis.recommendedPolicySet?.declined || [];
    const contradicted = declined.filter(item => item.contradictsEvidence);
    if (!declined.length) return '';
    return `<div class="log-journey-declined-warning"><strong>${esc(declined.length)} policy ${declined.length === 1 ? 'family is' : 'families are'} excluded by tenant answers</strong><p>${contradicted.length ? `${contradicted.length} ${contradicted.length === 1 ? 'answer conflicts' : 'answers conflict'} with measured finding evidence. The finding remains visible, but incompatible proposals have been removed.` : 'The excluded families remain recorded here so absence is not mistaken for a clean assessment.'}</p></div>`;
  }

  function renderLogJourneyObservedPolicy(policy) {
    const controls = [...policy.grants.map(item => item.label), ...policy.sessions.map(item => item.label), ...policy.authStrength.map(item => `Strength: ${item.name}`)];
    return `<button type="button" class="log-journey-policy" data-journey-type="observedPolicy" data-journey-id="${esc(policy.name)}" aria-pressed="false">
      <span class="status-chip ${policy.state === 'enforcing' ? 'import-exact' : policy.state === 'reportOnly' ? 'import-different' : 'import-extra'}">${esc(policy.state === 'enforcing' ? 'Enforcing' : policy.state === 'reportOnly' ? 'Report-only' : 'Never matched')}</span>
      <span><strong>${esc(policy.name)}</strong><small>${esc(policy.applied)} applied · ${esc(policy.evaluations)} evaluated${controls.length ? ` · ${esc([...new Set(controls)].slice(0, 2).join(', '))}` : ''}</small></span>
      <em>${esc(policy.hitRate || 0)}% hit rate</em>
    </button>`;
  }

  function renderLogJourneyRecommendedPolicy(policy) {
    const element = [...LOG_JOURNEY_STAGES.flatMap(stage => stage.elements), ...LOG_JOURNEY_ADJACENT].find(item => item.id === policy.primaryElementId);
    const affected = policy.drivers.reduce((maximum, driver) => Math.max(maximum, Number(driver.affected) || 0), 0);
    const unresolved = policy.unresolvedPrerequisites?.length || 0;
    return `<button type="button" class="log-journey-policy is-proposed is-${esc(policy.actionTier)}" data-journey-type="recommendedPolicy" data-journey-id="${esc(policy.id)}" aria-pressed="false">
      <span class="status-chip log-action-tier is-${esc(policy.actionTier)}">${esc(policy.actionTierLabel)}</span>
      <span><strong>${esc(tenantPolicyName(policy.displayName))}</strong><small>${esc(policy.basis.label)} · ${esc(policy.drivers.length)} finding driver${policy.drivers.length === 1 ? '' : 's'}${affected ? ` · up to ${esc(affected.toLocaleString())} affected` : ''} · ${esc(element?.label || policy.primaryElementId)}${unresolved ? ` · ${esc(unresolved)} unresolved prerequisite${unresolved === 1 ? '' : 's'}` : ''}<span class="log-journey-reason-labels">${(policy.reasonLabels || []).map(label => `<em>${esc(label)}</em>`).join('')}</span></small></span>
      <em>${esc(coverageHeadline(policy.coverage))}</em>
    </button>`;
  }

  function renderLogJourneyTab(config) {
    const active = Boolean(config.active);
    return `<button type="button" class="log-journey-tab${active ? ' is-active' : ''}" id="${esc(config.id)}" role="tab" aria-selected="${active}" aria-controls="${esc(config.panelId)}" tabindex="${active ? '0' : '-1'}" ${config.dataAttribute}="${esc(config.value)}">
      <span>${esc(config.label)}</span><small>${esc(config.badge)}</small>
    </button>`;
  }

  function renderLogPolicyDownloadActions(kind, count) {
    const label = kind === 'recommended' ? 'recommended' : 'observed';
    const disabled = count ? '' : ' disabled';
    const title = count ? '' : ` title="No ${label} policies are available to download"`;
    return `<div class="log-journey-download-actions" aria-label="Download ${label} policy reports">
      <button type="button" class="btn primary" data-log-policy-download data-policy-kind="${label}" data-policy-format="docx" aria-label="Download ${label} policies as a Word document"${disabled}${title}>Download DOCX</button>
      <button type="button" class="btn primary" data-log-policy-download data-policy-kind="${label}" data-policy-format="xlsx" aria-label="Download ${label} policies as an Excel workbook"${disabled}${title}>Download XLSX</button>
    </div>`;
  }

  function renderLogJourneyCoverageSummary(coverage) {
    const metric = (label, count, tone) => `<article class="is-${esc(tone)}"><span>${esc(label)}</span><strong>${esc(count.toLocaleString())}</strong><small>${esc(caCoveragePercentLabel(count, coverage.successful))} of successful events</small></article>`;
    const retention = coverage.retention;
    return `<section class="log-journey-coverage-summary" aria-labelledby="logJourneyCoverageSummaryTitle">
      <header><div><span class="eyebrow">CA coverage evidence</span><h5 id="logJourneyCoverageSummaryTitle">${esc(coverage.reviewTotal.toLocaleString())} successful access events without enforcing CA require review</h5></div><p>These same mutually exclusive counts appear in both Observed Policy downloads.</p></header>
      <div>${metric('Confirmed scoping gap', coverage.confirmedGap, 'gap')}${metric('Report-only exposure', coverage.reportOnlyExposure, 'review')}${metric('Evidence unknown', coverage.evidenceUnknown, 'blind')}</div>
      <footer><span>${esc(coverage.protectedSuccess.toLocaleString())} protected successful events</span><span>${esc(coverage.expectedOutsideCa.toLocaleString())} expected outside CA - not counted as bypasses</span><span>${esc(retention.retainedRows.toLocaleString())} of ${esc(retention.eligibleRows.toLocaleString())} evidence rows retained${retention.truncated ? ' - ledger truncated, totals complete' : ' - ledger complete'}</span></footer>
    </section>`;
  }

  function renderLogJourneyPolicyBoard(model) {
    const observed = [...model.observedPolicies].sort((a, b) => {
      const rank = policy => policy.state === 'enforcing' ? 0 : policy.state === 'reportOnly' ? 1 : 2;
      return rank(a) - rank(b) || b.applied - a.applied || b.evaluations - a.evaluations;
    });
    const relevant = observed.filter(policy => policy.state !== 'neverMatched');
    const remainder = observed.filter(policy => policy.state === 'neverMatched');
    const visible = state.logAnalysis.observedPoliciesExpanded ? observed : relevant;
    const observedContent = visible.length
      ? visible.map(renderLogJourneyObservedPolicy).join('')
      : '<div class="log-journey-policy-blind"><strong>Policy-evidence blind spot</strong><p>No per-policy evaluation data was recorded. CSV exports do not include this detail; use a JSON sign-in export to see observed policy names and controls.</p></div>';
    const actNowRecommendations = model.recommendedPolicies.filter(policy => policy.actionTier === 'actNow');
    const validateRecommendations = model.recommendedPolicies.filter(policy => policy.actionTier === 'validateFirst');
    const optionalRecommendations = model.recommendedPolicies.filter(policy => policy.actionTier === 'optionalAdvanced');
    const reasonCounts = new Map();
    optionalRecommendations.forEach(policy => (policy.reasonLabels || []).forEach(reason => incrementJourneyMap(reasonCounts, reason, 1)));
    const optionalReasons = logJourneyTopEntries(reasonCounts, 4).map(item => `${item.name} ${item.count}`).join(' · ');
    const coverage = buildCaCoverageReport(state.logAnalysis, { includeEvents: false });
    const actionLane = (className, title, description, policies) => `<section class="log-journey-action-lane ${esc(className)}"><header><div><span>${esc(title)}</span><small>${esc(description)}</small></div><strong>${esc(policies.length)}</strong></header><div>${policies.length ? policies.map(renderLogJourneyRecommendedPolicy).join('') : '<div class="log-journey-policy-blind"><strong>No policy in this tier</strong><p>The current evidence and assumption answers did not place a proposal here.</p></div>'}</div></section>`;
    const recommendations = model.recommendedPolicies.length
      ? `${actionLane('is-act-now', 'Act now', 'Begin investigation, design and staged rollout.', actNowRecommendations)}${actionLane('is-validate-first', 'Validate first', 'Resolve prerequisites before pilot deployment.', validateRecommendations)}${optionalRecommendations.length ? `<details class="log-journey-contextual"><summary><span>Optional / advanced (${optionalRecommendations.length})</span><small>${esc(optionalReasons || 'Unanswered assumptions and specialist scenarios')}</small></summary><div>${optionalRecommendations.map(renderLogJourneyRecommendedPolicy).join('')}</div></details>` : ''}`
      : '<div class="log-journey-policy-blind"><strong>No proposed set was generated</strong><p>The loaded evidence did not produce a recommendation set. Review blind spots and tenant assumptions before treating this as a clean result.</p></div>';
    const activePolicyTab = state.logAnalysis.journeyPolicyTab === 'observed' ? 'observed' : 'recommended';
    return `<section class="log-journey-policy-board" id="logJourneyPolicyBoard" tabindex="-1" aria-labelledby="logJourneyPolicyBoardTitle">
      <div class="log-journey-section-head"><div><span class="eyebrow">Policy action board</span><h3 id="logJourneyPolicyBoardTitle">What acted—and what to change next</h3><p>Observed policy results are runtime evidence. Proposed controls are guidance and never alter the measured ribbons above.</p></div><div class="log-journey-board-actions"><button type="button" class="btn secondary" data-log-build-guide>Download build guide</button><button type="button" class="btn primary" data-log-build-strategy>Build this strategy</button></div></div>
      ${renderLogJourneyDeclarationDisclosure(model)}
      ${renderLogJourneyDeclinedWarnings()}
      <nav class="log-journey-tabs log-journey-policy-tabs" role="tablist" aria-label="Policy action views" data-log-journey-tablist="policy">
        ${renderLogJourneyTab({ id: 'logJourneyPolicyTabRecommended', panelId: 'logJourneyPolicyPanelRecommended', value: 'recommended', label: 'Recommended policies', badge: `${model.recommendedPolicies.length} proposed`, active: activePolicyTab === 'recommended', dataAttribute: 'data-log-policy-tab' })}
        ${renderLogJourneyTab({ id: 'logJourneyPolicyTabObserved', panelId: 'logJourneyPolicyPanelObserved', value: 'observed', label: 'Observed policies', badge: `${observed.length} recorded`, active: activePolicyTab === 'observed', dataAttribute: 'data-log-policy-tab' })}
      </nav>
      <div class="log-journey-policy-panels">
        <section class="log-journey-policy-panel" id="logJourneyPolicyPanelRecommended" role="tabpanel" aria-labelledby="logJourneyPolicyTabRecommended" data-log-policy-panel="recommended"${activePolicyTab === 'recommended' ? '' : ' hidden'}>
          <header><div><span class="eyebrow">Recommended next controls</span><h4>${esc(model.recommendedPolicies.length)} proposed · ${esc(actNowRecommendations.length)} act now · ${esc(validateRecommendations.length)} validate first · ${esc(optionalRecommendations.length)} optional</h4></div><div class="log-journey-panel-actions">${renderLogPolicyDownloadActions('recommended', model.recommendedPolicies.length)}</div></header>
          <div class="log-journey-policy-list">${recommendations}</div>
        </section>
        <section class="log-journey-policy-panel" id="logJourneyPolicyPanelObserved" role="tabpanel" aria-labelledby="logJourneyPolicyTabObserved" data-log-policy-panel="observed"${activePolicyTab === 'observed' ? '' : ' hidden'}>
          <header><div><span class="eyebrow">Observed in this window</span><h4>${esc(relevant.length)} active or report-only ${relevant.length === 1 ? 'policy' : 'policies'}</h4></div><div class="log-journey-panel-actions">${renderLogPolicyDownloadActions('observed', observed.length)}${remainder.length ? `<button type="button" class="btn secondary" data-log-toggle-observed>${state.logAnalysis.observedPoliciesExpanded ? 'Show relevant only' : `View all observed policies (${observed.length})`}</button>` : ''}</div></header>
          ${renderLogJourneyCoverageSummary(coverage)}
          <div class="log-journey-policy-list">${observedContent}</div>
        </section>
      </div>
    </section>`;
  }

  function renderLogVisualWorkspace() {
    const model = buildLogJourneyModel();
    const findingCount = state.logAnalysis.findings.length;
    const allSources = model.sources.every(source => source.loaded);
    const selected = state.logAnalysis.journeySelected;
    const activeWorkspaceTab = ['controls', 'policies', 'adjacent'].includes(state.logAnalysis.journeyWorkspaceTab) ? state.logAnalysis.journeyWorkspaceTab : 'controls';
    const controlFindingIds = new Set(model.stages.flatMap(stage => stage.elements.flatMap(element => element.findings.map(finding => finding.id))));
    const adjacentFindingIds = new Set(model.adjacent.flatMap(element => element.findings.map(finding => finding.id)));
    return `<div class="log-journey${selected ? ' has-selection' : ''}">
      <header class="log-journey-head">
        <div><span class="eyebrow">Conditional Access visual assessment</span><h2 id="logVisualTitle">See where access is protected—and where it slips through</h2><p>${esc(model.journey.total.toLocaleString())} sign-in events classified once from identity source to CA decision and outcome. ${allSources ? 'All three supported log sources are represented.' : 'Missing supported sources remain visible as blind spots.'}</p></div>
        <button type="button" class="btn primary log-journey-details" data-log-show-details>Detailed findings (${esc(findingCount)})</button>
      </header>
      ${renderLogJourneySummary(model)}
      <section class="log-journey-flow" aria-labelledby="logJourneyFlowTitle">
        <div class="log-journey-section-head"><div><span class="eyebrow">Measured authentication flow</span><h3 id="logJourneyFlowTitle">How sign-ins moved through Conditional Access</h3><p>Ribbon width represents mutually exclusive events, never policy-evaluation totals.</p></div><div class="log-journey-flow-key"><span><i class="is-protected"></i>Protected</span><span><i class="is-review"></i>Review</span><span><i class="is-gap"></i>Gap</span></div></div>
        <div class="log-journey-flow-shell" id="logJourneyFlowShell" data-journey-clear-space>
          <svg class="log-journey-ribbons" id="logJourneyRibbons" aria-hidden="true"></svg>
          <div class="log-journey-flow-columns">
            <section class="log-journey-column"><header><span>01</span><strong>Identity / log type</strong></header><div>${model.sources.map(node => renderLogJourneyNode(node, 'source')).join('')}</div></section>
            <section class="log-journey-column"><header><span>02</span><strong>CA decision</strong></header><div>${model.decisions.map(node => renderLogJourneyNode(node, 'decision')).join('')}</div></section>
            <section class="log-journey-column"><header><span>03</span><strong>Sign-in outcome</strong></header><div>${model.outcomes.map(node => renderLogJourneyNode(node, 'outcome')).join('')}</div></section>
          </div>
        </div>
      </section>
      ${renderLogJourneyEvidence(model)}
      <section class="log-journey-workbench" aria-label="Assessment detail workspace">
        <div class="log-journey-control-bridge"><span>${logJourneyIcon('branch')}</span><p><strong>Explore the evidence behind the flow</strong>The measured journey remains visible above while the tabs organise its supporting controls and policy evidence.</p></div>
        <nav class="log-journey-tabs log-journey-workspace-tabs" role="tablist" aria-label="Visual assessment detail" data-log-journey-tablist="workspace">
          ${renderLogJourneyTab({ id: 'logJourneyWorkspaceTabControls', panelId: 'logJourneyWorkspacePanelControls', value: 'controls', label: 'Control map', badge: `${controlFindingIds.size} finding${controlFindingIds.size === 1 ? '' : 's'}`, active: activeWorkspaceTab === 'controls', dataAttribute: 'data-log-workspace-tab' })}
          ${renderLogJourneyTab({ id: 'logJourneyWorkspaceTabPolicies', panelId: 'logJourneyWorkspacePanelPolicies', value: 'policies', label: 'Policy actions', badge: `${model.recommendedPolicies.length} proposed`, active: activeWorkspaceTab === 'policies', dataAttribute: 'data-log-workspace-tab' })}
          ${renderLogJourneyTab({ id: 'logJourneyWorkspaceTabAdjacent', panelId: 'logJourneyWorkspacePanelAdjacent', value: 'adjacent', label: 'Adjacent controls', badge: `${model.adjacent.length} controls · ${adjacentFindingIds.size} finding${adjacentFindingIds.size === 1 ? '' : 's'}`, active: activeWorkspaceTab === 'adjacent', dataAttribute: 'data-log-workspace-tab' })}
        </nav>
        <div class="log-journey-workspace-panels">
          <div id="logJourneyWorkspacePanelControls" role="tabpanel" aria-labelledby="logJourneyWorkspaceTabControls" data-log-workspace-panel="controls"${activeWorkspaceTab === 'controls' ? '' : ' hidden'}>
            <section class="log-journey-assessment" aria-labelledby="logJourneyAssessmentTitle">
              <div class="log-journey-section-head"><div><span class="eyebrow">Connected control assessment</span><h3 id="logJourneyAssessmentTitle">Why the flow looks this way</h3><p>Each finding appears once beneath the control that best explains it. Policy counts show where observed and proposed controls connect.</p></div><div class="log-journey-status-key">${Object.keys(LOG_JOURNEY_STATUS_META).map(status => renderLogJourneyStatus(status, true)).join('')}</div></div>
              ${findingCount ? '' : '<p class="log-journey-no-findings"><strong>No gaps were identified in the loaded evidence.</strong> That does not prove universal protection; quiet activity and missing sources remain visible below.</p>'}
              <div class="log-journey-stage-grid">${model.stages.map(renderLogJourneyStage).join('')}</div>
            </section>
          </div>
          <div id="logJourneyWorkspacePanelPolicies" role="tabpanel" aria-labelledby="logJourneyWorkspaceTabPolicies" data-log-workspace-panel="policies"${activeWorkspaceTab === 'policies' ? '' : ' hidden'}>
            ${renderLogJourneyPolicyBoard(model)}
          </div>
          <div id="logJourneyWorkspacePanelAdjacent" role="tabpanel" aria-labelledby="logJourneyWorkspaceTabAdjacent" data-log-workspace-panel="adjacent"${activeWorkspaceTab === 'adjacent' ? '' : ' hidden'}>
            <section class="log-journey-adjacent" aria-labelledby="logJourneyAdjacentTitle">
              <div class="log-journey-section-head"><div><span class="eyebrow">Outside the tenant CA boundary</span><h3 id="logJourneyAdjacentTitle">Adjacent identity controls</h3><p>These remain part of the assessment, while clearly separated from controls Conditional Access can enforce.</p></div></div>
              <div class="log-journey-adjacent-grid">${model.adjacent.map(renderLogJourneyElement).join('')}</div>
            </section>
          </div>
        </div>
      </section>
    </div>`;
  }

  function queueLogJourneyDraw() {
    cancelAnimationFrame(logJourneyDrawFrame);
    logJourneyDrawFrame = requestAnimationFrame(() => {
      logJourneyDrawFrame = requestAnimationFrame(() => {
        drawLogJourneyRibbons();
        const shell = $('logJourneyFlowShell');
        if (!shell || typeof ResizeObserver === 'undefined') return;
        if (logJourneyResizeObserver) logJourneyResizeObserver.disconnect();
        logJourneyResizeObserver = new ResizeObserver(() => drawLogJourneyRibbons());
        logJourneyResizeObserver.observe(shell);
      });
    });
  }

  function drawLogJourneyRibbons() {
    const shell = $('logJourneyFlowShell');
    const svg = $('logJourneyRibbons');
    if (!shell || !svg || shell.offsetWidth < 560) {
      if (svg) svg.innerHTML = '';
      return;
    }
    const model = buildLogJourneyModel();
    const bounds = shell.getBoundingClientRect();
    const width = Math.max(1, bounds.width);
    const height = Math.max(1, bounds.height);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const total = Math.max(1, model.journey.total);
    svg.innerHTML = model.links.map((link, index) => {
      const from = shell.querySelector(`[data-journey-node="${link.fromType}:${link.fromId}"]`);
      const to = shell.querySelector(`[data-journey-node="${link.toType}:${link.toId}"]`);
      if (!from || !to) return '';
      const a = from.getBoundingClientRect();
      const b = to.getBoundingClientRect();
      const sx = a.right - bounds.left;
      const tx = b.left - bounds.left;
      const sy = a.top - bounds.top + a.height / 2;
      const ty = b.top - bounds.top + b.height / 2;
      const band = Math.max(2.5, Math.min(34, (link.value / total) * 92));
      const bend = Math.max(34, (tx - sx) * .46);
      const top = `M ${sx} ${sy - band / 2} C ${sx + bend} ${sy - band / 2}, ${tx - bend} ${ty - band / 2}, ${tx} ${ty - band / 2}`;
      const bottom = `L ${tx} ${ty + band / 2} C ${tx - bend} ${ty + band / 2}, ${sx + bend} ${sy + band / 2}, ${sx} ${sy + band / 2} Z`;
      const center = `M ${sx} ${sy} C ${sx + bend} ${sy}, ${tx - bend} ${ty}, ${tx} ${ty}`;
      const attrs = `data-from="${link.fromType}:${link.fromId}" data-to="${link.toType}:${link.toId}" data-link-value="${link.value}"`;
      return `<path class="log-journey-ribbon log-journey-tone-${esc(link.tone)}" d="${top} ${bottom}" ${attrs}/><path class="log-journey-pulse log-journey-tone-${esc(link.tone)}" d="${center}" ${attrs} style="--journey-delay:-${(index % 7) * .55}s"/>`;
    }).join('');
    applyLogJourneySelection();
  }

  function logJourneySelectionEntities(selection) {
    const model = buildLogJourneyModel();
    const entities = new Set();
    if (!selection) return entities;
    entities.add(`${selection.type}:${selection.id}`);
    const addRoute = route => {
      entities.add(`source:${route.source}`);
      entities.add(`decision:${route.decision}`);
      entities.add(`outcome:${route.outcome}`);
    };
    if (['source', 'decision', 'outcome'].includes(selection.type)) {
      model.journey.routes.forEach(route => {
        if (route[selection.type] === selection.id) addRoute(route);
      });
    } else {
      const elements = [...model.stages.flatMap(stage => stage.elements), ...model.adjacent];
      let findings = selection.type === 'finding'
        ? state.logAnalysis.findings.filter(item => item.id === selection.id)
        : selection.type === 'severity'
          ? state.logAnalysis.findings.filter(item => item.severity === selection.id)
          : [];
      let connectedElements = selection.type === 'element'
        ? elements.filter(item => item.id === selection.id)
        : elements.filter(item => item.findings.some(finding => findings.some(selectedFinding => selectedFinding.id === finding.id)));
      if (selection.type === 'priority') {
        const priority = logJourneyPriorityData(model);
        if (selection.id === 'gaps') {
          findings = priority.priorityFindings;
          connectedElements = elements.filter(element => element.findings.some(finding => findings.some(item => item.id === finding.id)));
        }
        if (selection.id === 'protection') {
          const enforcingPolicyNames = new Set(priority.enforcingPolicies.map(policy => policy.name));
          connectedElements = elements.filter(element => element.observedPolicies.some(policy => enforcingPolicyNames.has(policy.name)));
          priority.enforcingPolicies.forEach(policy => entities.add(`observedPolicy:${policy.name}`));
          model.journey.routes.forEach(route => {
            if (route.outcome === 'blocked' || route.outcome === 'protectedSuccess') addRoute(route);
          });
        }
        if (selection.id === 'actions') {
          const priorityPolicies = [...priority.actNowPolicies, ...priority.validateFirstPolicies];
          const priorityPolicyIds = new Set(priorityPolicies.map(policy => policy.id));
          connectedElements = elements.filter(element => element.recommendedPolicies.some(policy => priorityPolicyIds.has(policy.id)));
          priorityPolicies.forEach(policy => entities.add(`recommendedPolicy:${policy.id}`));
          const driverTitles = new Set(priorityPolicies.flatMap(policy => policy.drivers.map(driver => driver.title)));
          findings = state.logAnalysis.findings.filter(finding => driverTitles.has(finding.title));
        }
      }
      if (selection.type === 'observedPolicy') {
        connectedElements = elements.filter(element => element.observedPolicies.some(policy => policy.name === selection.id));
        model.journey.routes.forEach(route => {
          if (route.evaluatedPolicies?.has(selection.id) || route.policies?.has(selection.id)) addRoute(route);
        });
      }
      if (selection.type === 'recommendedPolicy') {
        const policy = model.recommendedPolicies.find(item => item.id === selection.id);
        connectedElements = elements.filter(element => element.recommendedPolicies.some(item => item.id === selection.id));
        findings = state.logAnalysis.findings.filter(finding => policy?.drivers.some(driver => driver.title === finding.title));
      }
      if (selection.type === 'element') findings = connectedElements.flatMap(element => element.findings);
      if (selection.type !== 'priority' || selection.id === 'gaps') {
        const sourceIds = new Set([...findings.flatMap(finding => finding.metric.sources || []), ...connectedElements.flatMap(element => element.findings.flatMap(finding => finding.metric.sources || []))]);
        sourceIds.forEach(sourceId => model.journey.routes.forEach(route => { if (route.source === sourceId) addRoute(route); }));
      }
      connectedElements.forEach(element => entities.add(`element:${element.id}`));
      findings.forEach(finding => entities.add(`finding:${finding.id}`));
    }
    return entities;
  }

  function applyLogJourneySelection() {
    const root = $('logVisualContent');
    if (!root) return;
    const selection = state.logAnalysis.journeySelected;
    const entities = logJourneySelectionEntities(selection);
    root.querySelector('.log-journey')?.classList.toggle('has-selection', Boolean(selection));
    root.querySelectorAll('[data-journey-type][data-journey-id]').forEach(item => {
      const selected = Boolean(selection && item.dataset.journeyType === selection.type && item.dataset.journeyId === selection.id);
      item.classList.toggle('is-selected', selected || entities.has(`${item.dataset.journeyType}:${item.dataset.journeyId}`));
      if (item.hasAttribute('aria-pressed')) item.setAttribute('aria-pressed', String(selected));
    });
    root.querySelectorAll('[data-journey-node]').forEach(node => {
      const connected = entities.has(node.dataset.journeyNode);
      node.classList.toggle('is-connected', Boolean(selection && connected));
      node.classList.toggle('is-dimmed', Boolean(selection && !connected));
      node.classList.toggle('is-selected', Boolean(selection && node.dataset.journeyNode === `${selection.type}:${selection.id}`));
    });
    root.querySelectorAll('[data-journey-element], .log-journey-finding').forEach(node => {
      const id = node.dataset.journeyElement ? `element:${node.dataset.journeyElement}` : `finding:${node.dataset.journeyId}`;
      node.classList.toggle('is-selected', Boolean(selection && entities.has(id)));
    });
    root.querySelectorAll('.log-journey-policy').forEach(policy => {
      const key = `${policy.dataset.journeyType}:${policy.dataset.journeyId}`;
      policy.classList.toggle('is-connected', Boolean(selection && (entities.has(key) || policy.classList.contains('is-selected'))));
    });
    root.querySelectorAll('.log-journey-ribbon, .log-journey-pulse').forEach(path => {
      const connected = entities.has(path.dataset.from) && entities.has(path.dataset.to);
      path.classList.toggle('is-connected', Boolean(selection && connected));
      path.classList.toggle('is-dimmed', Boolean(selection && !connected));
      path.classList.remove('is-replaying');
      if (selection && connected && path.classList.contains('log-journey-pulse')) {
        void path.getBoundingClientRect();
        path.classList.add('is-replaying');
      }
    });
  }

  function logJourneyMatchingRoutes(type, id) {
    const routes = [...(state.logAnalysis.agg?.journey.routes.values() || [])];
    return routes.filter(route => route[type] === id).sort((a, b) => b.count - a.count);
  }

  function logObservedPolicyRelationships(policy) {
    const candidates = [];
    const grantText = policy.grants.map(grant => `${grant.name} ${grant.label}`).join(' ');
    const sessionText = policy.sessions.map(session => `${session.name} ${session.label}`).join(' ');
    const configText = policy.observedConfig.map(row => `${row.label} ${row.value}`).join(' ');
    const conditionText = policy.notSatisfied.map(item => `${item.name} ${item.label}`).join(' ');
    if (policy.authStrength.length) candidates.push('auth-strength');
    if (/compliantdevice|domainjoineddevice|hybridjoined/i.test(grantText)) candidates.push('device-compliance');
    if (/approvedapplication|compliantapplication|appprotection/i.test(grantText)
      || /applicationenforcedrestrictions|cloudappsecurity/i.test(sessionText)) candidates.push('byod-protection');
    if (/risk/i.test(conditionText)) candidates.push('risk-protection');
    if (/location|ip address/i.test(`${conditionText} ${configText}`)) candidates.push('location-context');
    if (/block/i.test(grantText) && /client apps/i.test(configText)) candidates.push('legacy-controls');
    if (/authentication flow|device code|transfer/i.test(`${conditionText} ${configText}`)) candidates.push('authentication-flows');
    if (policy.sessions.length) candidates.push('session-protection');
    if (/mfa|multifactor|authenticationstrength/i.test(grantText)) candidates.push('mfa-coverage');
    if (/^Excludes/im.test(configText)) candidates.push('exclusions-filters');
    if (/guest|external/i.test(configText)) candidates.push('guest-scope');
    if (/application|target resources/i.test(configText)) candidates.push('application-scope');
    if (/assigned to|users|roles/i.test(configText)) candidates.push('identity-scope');
    if (policy.state === 'reportOnly') candidates.push('report-only-state');
    if (policy.state === 'enforcing' && policy.applied) candidates.push('applied-path');
    const unique = [...new Set(candidates)];
    return { primary: unique[0] || null, secondary: unique.slice(1) };
  }

  function logJourneyPolicyEvidence(element) {
    const policies = state.logAnalysis.policyInventory?.policies || [];
    if (element.id === 'runtime-coverage') return [];
    return policies.filter(policy => logObservedPolicyRelationships(policy).primary === element.id);
  }

  function logJourneyRecommendedPolicyEvidence(element) {
    const policies = state.logAnalysis.recommendedPolicySet?.policies || [];
    if (element.id === 'applied-path' || element.id === 'runtime-coverage' || element.id === 'report-only-state') return [];
    return policies.filter(policy => policy.primaryElementId === element.id);
  }

  function renderLogJourneySamples(samples) {
    const rows = (samples || []).filter(sample => sample && typeof sample === 'object' && !sample.kind).slice(0, 6);
    if (!rows.length) return '<p class="log-journey-evidence-muted">No event-level sample was retained for this observation.</p>';
    return `<div class="log-journey-samples">${rows.map(sample => `<article><span>${esc(sample.time || 'unknown')}${sample.representedEvents > 1 ? ` · represents ${esc(sample.representedEvents)} events` : ''}</span><strong>${esc(sample.principal || 'unknown')}</strong><p>${esc(sample.app || 'unknown')} · ${esc(sample.location || 'unknown')}</p></article>`).join('')}</div>`;
  }

  function renderLogJourneyPolicies(policies) {
    if (!policies.length) return '';
    return `<div class="log-journey-evidence-policies"><strong>Policies and conditions observed</strong>${policies.map(policy => {
      const controls = [...policy.grants.map(item => item.label), ...policy.sessions.map(item => item.label), ...policy.authStrength.map(item => `Authentication strength: ${item.name}`)];
      const conditions = [...policy.observedConfig.map(item => `${item.label}: ${item.value}`), ...policy.notSatisfied.map(item => `${item.label} (${item.count})`)];
      return `<article><h5>${esc(policy.name)}</h5><p>${esc(policy.applied)} applied · ${esc(policy.reportOnly)} report-only · ${esc(policy.notApplied)} did not match</p>${controls.length ? `<p><strong>Controls:</strong> ${esc([...new Set(controls)].join(' · '))}</p>` : ''}${conditions.length ? `<p><strong>Observed scope / filters:</strong> ${esc(conditions.slice(0, 6).join(' · '))}</p>` : ''}</article>`;
    }).join('')}</div>`;
  }

  function renderLogJourneyMfaExclusions(policies) {
    const summary = mfaExclusionSummary(policies);
    if (!summary.policyCount) {
      return `<section class="log-mfa-exclusions log-mfa-exclusions-empty">
        <div><p class="eyebrow">MFA exclusion review</p><h5>No exercised identity-assignment exclusion was returned</h5></div>
        <p>The loaded sign-in evidence did not show an MFA policy excluding a user through a directory role, group, named-user or external-user assignment. This is not proof that the stored tenant policies contain no exclusions; inspect the authoritative Conditional Access policy configuration as well.</p>
      </section>`;
    }
    const policiesHtml = summary.policies.map(policy => {
      const rules = policy.exclusionRules.filter(rule => rule.identityAssignment);
      const identities = policy.exclusionIdentities || [];
      const visible = identities.slice(0, LOG_EXCLUSION_DISPLAY_CAP);
      const roleOrGroupUnknown = rules.some(rule => ['roleid', 'groupid'].includes(normToken(rule.rule)));
      return `<article class="log-mfa-exclusion-policy">
        <header><div><span>High review priority</span><h6>${esc(policy.name)}</h6></div><strong>${esc((policy.excludedEventCount || 0).toLocaleString())} observed exclusion event${policy.excludedEventCount === 1 ? '' : 's'}</strong></header>
        <div class="log-mfa-exclusion-rules">${rules.map(rule => `<div><strong>${esc(rule.ruleLabel)}</strong><span>${esc(rule.count.toLocaleString())} observed event${rule.count === 1 ? '' : 's'}</span><p>${esc(rule.detail)}</p></div>`).join('')}</div>
        ${roleOrGroupUnknown ? '<p class="log-mfa-exclusion-warning"><strong>Configuration detail required:</strong> the sign-in export does not identify the configured role or group object. Open this policy in Microsoft Entra or compare an authorised policy configuration export before accepting the exclusion.</p>' : ''}
        ${visible.length ? `<div class="log-evidence-scroll"><table class="log-mfa-exclusion-table">
          <thead><tr><th>Observed identity</th><th>Object ID</th><th>Type</th><th>Events</th><th>Exclusion rule</th><th>Apps / resources</th><th>Locations</th><th>Observed UTC</th></tr></thead>
          <tbody>${visible.map(identity => `<tr>
            <td><strong>${esc(identity.name)}</strong></td>
            <td><code>${esc(identity.objectId || 'Not returned')}</code></td>
            <td>${esc([identity.identityType, identity.userType].filter(Boolean).join(' / ') || 'user')}</td>
            <td>${esc(identity.count.toLocaleString())}</td>
            <td>${esc(identity.rules.map(rule => `${rule.label} (${rule.count})`).join(' · '))}</td>
            <td>${esc(identity.apps.slice(0, 5).map(item => `${item.name} (${item.count})`).join(' · '))}</td>
            <td>${esc(identity.locations.slice(0, 5).map(item => `${item.name} (${item.count})`).join(' · '))}</td>
            <td>${esc(identity.from ? identity.from.replace('T', ' ').slice(0, 16) : 'Unknown')}<br><span>to ${esc(identity.to ? identity.to.replace('T', ' ').slice(0, 16) : 'Unknown')}</span></td>
          </tr>`).join('')}</tbody>
        </table></div>` : '<p>No event-level identity was retained for this exercised exclusion.</p>'}
        ${identities.length > visible.length ? `<p class="log-journey-evidence-muted">Showing ${esc(visible.length.toLocaleString())} of ${esc(identities.length.toLocaleString())} observed identities here. The XLSX export includes the complete observed identity list.</p>` : ''}
      </article>`;
    }).join('');
    return `<section class="log-mfa-exclusions">
      <header>
        <div><p class="eyebrow">High review priority</p><h5>Observed MFA exclusion paths</h5><p>These identities were observed taking an identity-assignment exclusion path in an MFA-related policy. That can create material business risk, but the evidence alone does not prove an emergency or intentional exclusion is wrong.</p></div>
        <dl><div><dt>MFA policies</dt><dd>${esc(summary.policyCount.toLocaleString())}</dd></div><div><dt>Distinct identities</dt><dd>${esc(summary.identityCount.toLocaleString())}</dd></div><div><dt>Policy-event observations</dt><dd>${esc(summary.policyEventObservations.toLocaleString())}</dd></div></dl>
      </header>
      <p class="log-mfa-exclusion-method">Counts are policy-event observations and can overlap when one sign-in exercises exclusions in more than one MFA policy. They show what happened in the imported window, not every object configured in the tenant.</p>
      ${policiesHtml}
    </section>`;
  }

  function renderLogJourneyEvidenceSection(title, content) {
    return `<section class="log-journey-evidence-section"><h4>${esc(title)}</h4>${content}</section>`;
  }

  function logJourneyAggregateRoutes(routes, field) {
    const result = new Map();
    routes.forEach(route => {
      if (route[field] instanceof Map) route[field].forEach((count, name) => incrementJourneyMap(result, name, count));
      else if (route[field]) incrementJourneyMap(result, route[field], route.count);
    });
    return result;
  }

  function renderLogJourneyFactList(items, labels) {
    if (!items.length) return '<p class="log-journey-evidence-muted">No measured values were available.</p>';
    return `<ul class="log-journey-fact-list">${items.map(item => `<li><span>${esc(labels?.[item.name] || item.name)}</span><strong>${esc(item.count.toLocaleString())}</strong></li>`).join('')}</ul>`;
  }

  function renderLogJourneyGuidance(guidance) {
    if (!guidance) return '';
    const links = (guidance.links || []).map(key => LOG_LEARN_GUIDANCE[key]).filter(Boolean);
    return `<div class="log-journey-guidance"><ul>${(guidance.notes || []).map(note => `<li>${esc(note)}</li>`).join('')}</ul>${links.length ? `<div class="log-journey-guidance-links">${links.map(link => `<a href="${esc(link.url)}" target="_blank" rel="noopener noreferrer">${logJourneyIcon('external')}${esc(link.label)}</a>`).join('')}</div>` : ''}</div>`;
  }

  function logJourneyDeviceFilterExamples(context) {
    const examples = [];
    const topValue = name => logJourneyTopEntries(context.attributeValues.get(name), 1)[0]?.name;
    if (context.attributes.has('isCompliant')) examples.push({ label: 'Compliant device', expression: 'device.isCompliant -eq true' });
    const trustType = topValue('trustType');
    if (trustType) examples.push({ label: 'Returned join type', expression: `device.trustType -eq "${trustType}"` });
    if (trustType && (context.byState.get('unregistered') || 0)) examples.push({ label: 'Include null/unregistered when deliberately excluding a join type', expression: `device.trustType -ne "${trustType}"` });
    const ownership = topValue('deviceOwnership');
    if (ownership) examples.push({ label: 'Returned ownership', expression: `device.deviceOwnership -eq "${ownership}"` });
    const operatingSystemVersion = topValue('operatingSystemVersion');
    if (operatingSystemVersion) examples.push({ label: 'Returned OS version', expression: `device.operatingSystemVersion -eq "${operatingSystemVersion}"` });
    const mdmAppId = topValue('mdmAppId');
    if (mdmAppId) examples.push({ label: 'Returned management authority', expression: `device.mdmAppId -eq "${mdmAppId}"` });
    const profile = topValue('enrollmentProfileName');
    if (profile) examples.push({ label: 'Returned enrolment profile', expression: `device.enrollmentProfileName -eq "${profile}"` });
    if (!examples.length) return '<p class="log-journey-evidence-muted">No supported device-filter attribute was returned, so no filter example is shown.</p>';
    return `<div class="log-journey-filter-examples"><p><strong>Guidance to validate — not generated runtime proof</strong></p>${examples.map(example => `<div><span>${esc(example.label)}</span><code>${esc(example.expression)}</code></div>`).join('')}</div>`;
  }

  function renderLogJourneyDeviceContext(elementId, context) {
    const stateLabels = Object.fromEntries(LOG_DEVICE_CONTEXT_STATES.map(item => [item.id, item.label]));
    const rootCauses = LOG_DEVICE_CONTEXT_STATES.slice(0, 3).map(item => ({ name: item.id, count: context.findingStates.get(item.id) || 0 }));
    if (elementId === 'device-identity') {
      return `<div class="log-journey-device-context"><div class="log-journey-breakdowns"><div><h5>Identity and join state</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.joinStates, 8))}</div><div><h5>Platforms</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.platforms, 8))}</div><div><h5>Special context</h5><ul class="log-journey-fact-list"><li><span>Device-code flows</span><strong>${esc(context.deviceCodeFlows.toLocaleString())}</strong></li><li><span>Inbound guests</span><strong>${esc(context.inboundGuests.toLocaleString())}</strong></li></ul></div></div>${logJourneyDeviceFilterExamples(context)}</div>`;
    }
    if (elementId === 'device-compliance') {
      return `<div class="log-journey-device-context"><p><strong>Root-cause slices for the device finding</strong></p><div class="log-journey-breakdowns"><div><h5>Needs action</h5>${renderLogJourneyFactList(rootCauses, stateLabels)}</div><div><h5>Positive and unknown context</h5>${renderLogJourneyFactList(['compliant', 'unknown'].map(name => ({ name, count: context.byState.get(name) || 0 })), stateLabels)}</div><div><h5>Ownership</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.ownership, 8))}</div></div><p class="log-journey-evidence-muted">Compliant and joined traffic is useful positive context. Join state alone is not treated as proof of compliance.</p>${logJourneyDeviceFilterExamples(context)}</div>`;
    }
    if (elementId === 'byod-protection') {
      return `<div class="log-journey-device-context"><div class="log-journey-breakdowns"><div><h5>Ownership</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.ownership, 8))}</div><div><h5>Browser</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.browsers, 8))}</div><div><h5>Client application</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.clientApps, 8))}</div></div><p>${esc(context.inboundGuests.toLocaleString())} inbound guest event${context.inboundGuests === 1 ? '' : 's'} were present. Their external device claims are useful only when inbound cross-tenant trust is configured.</p></div>`;
    }
    if (elementId === 'session-protection') {
      return `<div class="log-journey-device-context"><div class="log-journey-breakdowns"><div><h5>Client application</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.clientApps, 8))}</div><div><h5>Browser</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.browsers, 8))}</div><div><h5>Platforms</h5>${renderLogJourneyFactList(logJourneyTopEntries(context.platforms, 8))}</div></div></div>`;
    }
    return '';
  }

  function logJourneyElementActions(element) {
    const actions = {
      'device-identity': [
        'Separate no-device-identity events from registered devices before changing policy. Investigate device-code flows with an authentication control rather than a device grant.',
        'Use device-filter examples only after confirming the attribute is returned on the intended platform. Use a negative operator when unregistered devices must be included deliberately.',
        'For inbound guests, confirm cross-tenant device-claim trust before relying on their home-tenant compliance or hybrid-join claim.'
      ],
      'device-compliance': [
        'Remediate managed but noncompliant devices in the management service; enrol registered but unmanaged corporate devices; define a separate supported path for personal devices.',
        'Prefer Require device to be marked as compliant for a cloud-native estate. Use the hybrid-join grant only for the intended Windows domain-joined population.',
        'Pilot with emergency-access exclusions and review report-only results before staged enablement; account for possible device-certificate prompts on supported mobile and macOS clients.'
      ],
      'byod-protection': [
        'Choose an explicit BYOD model per application: supported app protection, restricted browser access, or blocked access. Validate platform and application support before proposing it.',
        'Do not treat platform conditions as device posture. Pair user-agent platform signals with compliance or app protection where supported.'
      ],
      'session-protection': [
        'Choose the session capability for a specific risk and supported application. Sign-in frequency, browser persistence, app restrictions, Defender for Cloud Apps and token protection are not interchangeable defaults.',
        'Validate client, application, licensing and capability status before adding a session control, then test it in report-only or a pilot group where supported.'
      ],
      'mfa-coverage': [
        'Close measured single-factor paths with an applicable MFA grant, keeping emergency-access accounts excluded and monitored.',
        'Pilot broad workforce coverage against All resources, then review application-specific exceptions rather than creating a separate MFA policy for every app.'
      ],
      'auth-strength': [
        'Use authentication strength only where the required method assurance is clear. Treat phishing-resistant strength as a deliberate higher-assurance control, not a synonym for any MFA.'
      ],
      'legacy-controls': [
        'Use a dedicated legacy-authentication block only when legacy client evidence or migration intent supports it. Unknown device platforms are not legacy-client evidence.'
      ],
      'authentication-flows': [
        'Review device code and authentication transfer separately. Apply a supported authentication-flow condition or authentication control only when that flow is present and intended.'
      ],
      'risk-protection': [
        'Keep workforce user and sign-in risk controls conditional on Microsoft Entra ID P2 licensing and observed risk evidence or an explicit tenant choice.',
        'Assess workload-identity risk separately; it is not evidence for a workforce risk policy.'
      ],
      'location-context': [
        'Treat geographic spread as a review signal until expected countries, travel and named-location intent are declared. Do not convert spread alone into a deterministic block.',
        'Keep workload-identity location controls separate from workforce named-location recommendations.'
      ],
      'applied-path': [
        'Investigate only policies recorded on the affected runtime routes. A policy seen elsewhere in the export is not evidence that it protected this path.'
      ],
      'report-only-state': [
        'Review Success, Failure, User action required and Not applied separately. Confirm whether another enabled policy protected the same sign-in before changing state.'
      ],
      'runtime-coverage': [
        'Load the missing sign-in source or richer JSON fields before making a policy claim. Runtime coverage is an evidence task and does not generate a proposed-policy total.'
      ]
    };
    return actions[element.id] || [];
  }

  function renderLogJourneyReportOnlyResults(policies) {
    const labels = {
      reportonlysuccess: 'Success — conditions and configured controls were satisfied',
      reportonlyfailure: 'Failure — the policy would have blocked access',
      reportonlyinterrupted: 'User action required — the user would need to satisfy a control',
      reportonlynotapplied: 'Not applied — assignments or conditions did not match'
    };
    const results = new Map();
    (policies || []).forEach(policy => (policy.reportOnlyResults || []).forEach(item => incrementJourneyMap(results, item.name, item.count)));
    if (!results.size) return '';
    return `<div class="log-journey-report-results"><p><strong>Report-only result meanings</strong></p>${renderLogJourneyFactList(logJourneyTopEntries(results, 8), labels)}<p class="log-journey-evidence-muted">These results describe the report-only policy. Another enabled policy may still have protected the same sign-in.</p></div>`;
  }

  function logJourneyRelatedFindings(type, id, routes) {
    const explicit = {
      'decision:reportOnly': ['report-only'],
      'decision:filtered': ['ca-not-applied', 'possible-exclusions', 'uncovered-apps'],
      'decision:noEvaluation': ['ca-not-applied'],
      'decision:workloadReportOnly': ['sp-report-only'],
      'decision:workloadBlindspot': [],
      'decision:outsideCa': [],
      'decision:workloadReview': ['sp-ca-review'],
      'outcome:allowedReportOnly': ['report-only'],
      'outcome:workloadReportOnlyFlow': ['sp-report-only'],
      'outcome:allowedWithoutCa': ['ca-not-applied', 'single-factor-success'],
      'outcome:workloadUnknownFlow': [],
      'outcome:workloadReviewFlow': ['sp-ca-review'],
      'outcome:otherFailure': ['password-spray']
    }[`${type}:${id}`] || [];
    const sources = new Set(routes.map(route => route.source));
    return state.logAnalysis.findings.filter(finding => explicit.includes(finding.id)
      || (type === 'source' && (finding.metric.sources || []).includes(id))
      || (explicit.length && (finding.metric.sources || []).some(source => sources.has(source)) && explicit.includes(finding.id)));
  }

  function logJourneyEntityDetail(type, id) {
    const model = buildLogJourneyModel();
    if (type === 'priority') return logJourneyPriorityDetail(id, model);
    if (type === 'severity') {
      const findings = state.logAnalysis.findings.filter(finding => finding.severity === id);
      return {
        title: `${id.charAt(0).toUpperCase()}${id.slice(1)} severity evidence`,
        kicker: `${findings.length} finding${findings.length === 1 ? '' : 's'} · highlight only`,
        status: id === 'high' || id === 'medium' ? 'gap' : 'review',
        body: [
          renderLogJourneyEvidenceSection('What happened', `<p>${findings.length ? `The assessment produced ${findings.length} ${esc(id)}-severity finding${findings.length === 1 ? '' : 's'}. The rest of the control map remains visible so priority does not erase context.` : `No ${esc(id)}-severity findings were produced from the loaded evidence.`}</p>`),
          renderLogJourneyEvidenceSection('Evidence', findings.length ? `<ul>${findings.map(finding => `<li><button type="button" class="log-journey-inline-link" data-journey-type="finding" data-journey-id="${esc(finding.id)}">${esc(finding.title)}</button> — ${esc(finding.metric.affected)} affected</li>`).join('')}</ul>` : '<p>There is nothing at this severity to investigate.</p>'),
          renderLogJourneyEvidenceSection('Recommended action', '<p>Use severity to order the work, then open the related control or finding for the evidence, remediation and validation path.</p>')
        ].join('')
      };
    }
    if (type === 'observedPolicy') {
      const policy = model.observedPolicies.find(item => item.name === id);
      if (!policy) return null;
      const controls = [...policy.grants.map(item => item.label), ...policy.sessions.map(item => item.label), ...policy.authStrength.map(item => `Authentication strength: ${item.name}`)];
      const relationships = logObservedPolicyRelationships(policy);
      const elementLabels = new Map([...LOG_JOURNEY_STAGES.flatMap(stage => stage.elements), ...LOG_JOURNEY_ADJACENT].map(item => [item.id, item.label]));
      const top = [
        ...policy.topUsers.map(item => `Identity: ${item.name} (${item.count})`),
        ...policy.topApps.map(item => `App: ${item.name} (${item.count})`),
        ...policy.topLocations.map(item => `Location: ${item.name} (${item.count})`)
      ].slice(0, 9);
      return {
        title: policy.name,
        kicker: `Observed policy · ${policy.state === 'reportOnly' ? 'report-only' : policy.state === 'enforcing' ? 'enforcing' : 'never matched'}`,
        status: policy.state === 'enforcing' && policy.applied ? 'protected' : policy.state === 'reportOnly' ? 'review' : 'noIssue',
        body: [
          renderLogJourneyEvidenceSection('What happened', `<dl class="log-journey-evidence-facts"><div><dt>Applied</dt><dd>${esc(policy.applied.toLocaleString())}</dd></div><div><dt>Evaluated</dt><dd>${esc(policy.evaluations.toLocaleString())}</dd></div><div><dt>Report-only</dt><dd>${esc(policy.reportOnly.toLocaleString())}</dd></div><div><dt>Did not match</dt><dd>${esc(policy.notApplied.toLocaleString())}</dd></div></dl>`),
          renderLogJourneyEvidenceSection('Evidence', `${relationships.primary ? `<p><strong>Primary control relationship:</strong> ${esc(elementLabels.get(relationships.primary) || relationships.primary)}</p>` : ''}${relationships.secondary.length ? `<p><strong>Secondary relationships:</strong> ${esc(relationships.secondary.map(item => elementLabels.get(item) || item).join(' · '))}</p>` : ''}${controls.length ? `<p><strong>Controls recorded:</strong> ${esc([...new Set(controls)].join(' · '))}</p>` : '<p>No enforced grant or session control was recorded.</p>'}${mfaExclusionPolicies([policy]).length ? renderLogJourneyMfaExclusions([policy]) : ''}${renderLogJourneyReportOnlyResults([policy])}${top.length ? `<ul>${top.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}${renderLogJourneySamples(policy.samples)}`),
          renderLogJourneyEvidenceSection('Recommended action', `<p>${policy.state === 'reportOnly' ? 'Review impact, exclusions and failures before moving this policy to On.' : policy.state === 'neverMatched' ? 'Confirm the policy is still required and that its assignments and conditions can match intended traffic.' : 'Keep the policy mapped to its control objective and investigate any gap findings on the same path.'}</p>`),
          renderLogJourneyEvidenceSection('How to validate', '<p>Inspect the policy in Entra and compare its stored configuration with the exercised scope shown here. Re-export the same sign-in types after any change.</p>')
        ].join('')
      };
    }
    if (type === 'recommendedPolicy') {
      const policy = model.recommendedPolicies.find(item => item.id === id);
      if (!policy) return null;
      const controls = (policy.controls || []).map(control => (CONTROLS[control] || {}).label).filter(Boolean);
      const settings = [...(policy.tailoring || []).map(item => `${item.label}: ${item.value}`), ...(policy.settings || []).map(item => `${item.label}: ${item.value}`)].slice(0, 10);
      const elementLabels = new Map([...LOG_JOURNEY_STAGES.flatMap(stage => stage.elements), ...LOG_JOURNEY_ADJACENT].map(item => [item.id, item.label]));
      return {
        title: tenantPolicyName(policy.displayName),
        kicker: `${policy.actionTierLabel} proposed policy · ${policy.basis.label}`,
        status: 'review',
        body: [
          renderLogJourneyEvidenceSection('Why it is proposed', `<p>${esc(policy.basis.detail)}</p>${policy.drivers.length ? `<ul>${policy.drivers.map(driver => `<li><strong>${esc(driver.severity)}</strong> — ${esc(driver.title)}: ${esc(driver.affected)} of ${esc(driver.scope)}</li>`).join('')}</ul>` : '<p>This is a standard, declared or assumption-led proposal rather than a measured gap response.</p>'}<p class="log-journey-evidence-muted">${policy.actionTier === 'actNow' ? 'Act now means begin investigation, design and staged rollout. It does not mean enable immediately.' : policy.actionTier === 'validateFirst' ? 'Resolve the prerequisites below before building a pilot.' : 'Keep this available for later validation; it is not presented as immediate work.'}</p>`),
          renderLogJourneyEvidenceSection('Control and coverage', `<dl class="log-journey-evidence-facts"><div><dt>Action tier</dt><dd>${esc(policy.actionTierLabel)}</dd></div><div><dt>Evidence basis</dt><dd>${esc(policy.basis.label)}</dd></div><div><dt>Capability</dt><dd>${esc(policy.capabilityStatus)}</dd></div><div><dt>Coverage headline</dt><dd>${esc(coverageHeadline(policy.coverage))}</dd></div></dl><p class="log-journey-reason-labels">${(policy.reasonLabels || []).map(label => `<em>${esc(label)}</em>`).join('')}</p><p><strong>Applicability:</strong> ${esc(policy.applicability)}</p><p><strong>Primary relationship:</strong> ${esc(elementLabels.get(policy.primaryElementId) || policy.primaryElementId)}</p>${policy.secondaryElementIds.length ? `<p><strong>Secondary relationships:</strong> ${esc(policy.secondaryElementIds.map(item => elementLabels.get(item) || item).join(' · '))}</p>` : ''}${controls.length ? `<p><strong>Controls:</strong> ${esc(controls.join(' · '))}</p>` : ''}`),
          renderLogJourneyEvidenceSection('Recommended configuration', `${policy.prerequisites.length ? `<p><strong>Prerequisites</strong></p><ul>${policy.prerequisites.map(item => `<li><strong>${esc(item.status)}</strong> — ${esc(item.label)}${item.detail ? `<br><span>${esc(item.detail)}</span>` : ''}</li>`).join('')}</ul>` : '<p>No tenant-specific capability prerequisite is currently unresolved.</p>'}${settings.length ? `<ul>${settings.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p>Open the build guide for the full Entra configuration steps.</p>'}`),
          renderLogJourneyEvidenceSection('How to validate', `<p>Create the policy with emergency-access exclusions, pilot it in report-only, review impact and sampled sign-ins, then enable it in stages.</p><div class="log-journey-guidance-links">${(policy.guidanceUrls || []).map(link => `<a href="${esc(link.url)}" target="_blank" rel="noopener noreferrer">${logJourneyIcon('external')}${esc(link.label)}</a>`).join('')}</div>`)
        ].join('')
      };
    }
    if (type === 'finding') {
      const finding = state.logAnalysis.findings.find(item => item.id === id);
      if (!finding) return null;
      const guide = LOG_REMEDIATION[finding.id] || {};
      const top = [
        ...finding.topUsers.map(item => `Identity: ${item.name} (${item.count})`),
        ...finding.topApps.map(item => `App: ${item.name} (${item.count})`),
        ...finding.topLocations.map(item => `Location: ${item.name} (${item.count})`)
      ].slice(0, 10);
      const policyEvidence = (state.logAnalysis.policyInventory?.policies || []).filter(policy => finding.policyIds.includes(policy.baselineId)).slice(0, 6);
      const deviceEvidence = finding.id === 'noncompliant-device' ? renderLogJourneyDeviceContext('device-compliance', model.deviceContext) : '';
      const findingGuidance = finding.id === 'noncompliant-device' ? LOG_JOURNEY_GUIDANCE['device-compliance'] : null;
      return {
        title: finding.title,
        kicker: `${finding.severity} finding · ${finding.metric.affected} affected`,
        status: finding.severity === 'high' || finding.severity === 'medium' ? 'gap' : 'review',
        body: [
          renderLogJourneyEvidenceSection('What happened', `<p>${esc(finding.detail)}</p>`),
          renderLogJourneyEvidenceSection('Why it matters', `<p>${esc(guide.attack || guide.cause || finding.recommendation)}</p>`),
          renderLogJourneyEvidenceSection('Evidence', `<dl class="log-journey-evidence-facts"><div><dt>Affected</dt><dd>${esc(finding.metric.affected)} of ${esc(finding.metric.total)} ${esc(finding.metric.scope || 'sign-ins')} (${esc(finding.metric.pct)}%)</dd></div><div><dt>Sources</dt><dd>${esc((finding.metric.sources || []).map(key => LOG_SOURCES[key].label).join(', ') || 'Loaded sign-in logs')}</dd></div></dl>${deviceEvidence}${top.length ? `<ul>${top.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}${finding.diagnosis?.conditions?.length ? `<p><strong>Conditions that filtered policies:</strong> ${esc(finding.diagnosis.conditions.map(item => `${item.label} (${item.count})`).join(' · '))}</p>` : ''}${renderLogJourneyPolicies(policyEvidence)}${renderLogJourneySamples(finding.samples)}`),
          findingGuidance ? renderLogJourneyEvidenceSection('Microsoft guidance', renderLogJourneyGuidance(findingGuidance)) : '',
          renderLogJourneyEvidenceSection('Recommended action', `<ol>${(guide.fix?.length ? guide.fix : [finding.recommendation]).filter(Boolean).map(item => `<li>${esc(item)}</li>`).join('')}</ol>${finding.policies.length ? `<p><strong>Relevant baseline controls:</strong> ${esc(finding.policies.map(policy => `${policy.id} ${tenantPolicyName(policy.displayName)}`).join(' · '))}</p>` : ''}`),
          renderLogJourneyEvidenceSection('How to validate', `<p>${esc(guide.verify || 'Re-export a representative sign-in window and confirm the Conditional Access result and enforced controls changed as expected.')}</p><button type="button" class="btn secondary" data-log-open-finding="${esc(finding.id)}">Open full finding evidence</button>`)
        ].join('')
      };
    }
    if (type === 'element') {
      const element = [...model.stages.flatMap(stage => stage.elements), ...model.adjacent].find(item => item.id === id);
      if (!element) return null;
      const guides = element.findings.map(finding => LOG_REMEDIATION[finding.id] || {});
      const contextualActions = logJourneyElementActions(element);
      const actions = contextualActions.length ? contextualActions : [...new Set(element.findings.flatMap((finding, index) => guides[index].fix?.length ? guides[index].fix : [finding.recommendation]).filter(Boolean))].slice(0, 6);
      const verifies = [...new Set(guides.map(guide => guide.verify).filter(Boolean))].slice(0, 4);
      const policies = element.observedPolicies;
      const proposed = element.recommendedPolicies;
      const deviceEvidence = renderLogJourneyDeviceContext(element.id, model.deviceContext);
      const reportOnlyEvidence = element.id === 'report-only-state' ? renderLogJourneyReportOnlyResults(model.observedPolicies) : '';
      const mfaExclusionEvidence = element.id === 'mfa-coverage' ? renderLogJourneyMfaExclusions(policies) : '';
      return {
        title: element.label,
        kicker: `${element.parentLabel} · ${LOG_JOURNEY_STATUS_META[element.status].label}`,
        status: element.status,
        body: [
          renderLogJourneyEvidenceSection('What happened', `<p>${esc(element.statusReason)}</p>${element.findings.length ? `<ul>${element.findings.map(finding => `<li><strong>${esc(finding.title)}</strong> — ${esc(finding.metric.affected)} affected</li>`).join('')}</ul>` : '<p>No related gap finding was produced from the loaded activity.</p>'}`),
          renderLogJourneyEvidenceSection('Why it matters', `<p>${esc(element.why)}</p>`),
          renderLogJourneyEvidenceSection('Evidence', `${deviceEvidence}${mfaExclusionEvidence}${renderLogJourneyPolicies(policies)}${reportOnlyEvidence}${!policies.length ? (reportOnlyEvidence ? '<p class="log-journey-evidence-muted">Report-only state is shown as secondary evidence here; each policy card remains owned by its primary control relationship.</p>' : '<p class="log-journey-evidence-muted">No policy configuration is inferred here unless the sign-in export recorded it acting or being evaluated.</p>') : ''}${proposed.length ? `<p><strong>Primary proposed controls connected here:</strong> ${esc(proposed.map(policy => tenantPolicyName(policy.displayName)).join(' · '))}</p>` : ''}`),
          element.guidance ? renderLogJourneyEvidenceSection('Microsoft guidance', renderLogJourneyGuidance(element.guidance)) : '',
          renderLogJourneyEvidenceSection('Recommended action', actions.length ? `<ol>${actions.map(item => `<li>${esc(item)}</li>`).join('')}</ol>` : '<p>Keep this element in the review cycle and validate intent against the tenant policy configuration.</p>'),
          renderLogJourneyEvidenceSection('How to validate', verifies.length ? `<ul>${verifies.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p>Re-run the assessment with a representative JSON sign-in export and confirm the relevant policy result and control fields are present.</p>')
        ].join('')
      };
    }
    const collection = type === 'source' ? model.sources : type === 'decision' ? model.decisions : type === 'outcome' ? model.outcomes : [];
    const entity = collection.find(item => item.id === id);
    if (!entity) return null;
    const routes = logJourneyMatchingRoutes(type, id);
    const samples = [];
    routes.forEach(route => samples.push(...route.samples));
    const evaluatedPolicies = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'evaluatedPolicies'), 8);
    const matchedPolicies = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'policies'), 8);
    const identities = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'identities'), 5);
    const apps = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'apps'), 5);
    const locations = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'locations'), 5);
    const sources = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'source'), 5);
    const decisions = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'decision'), 6);
    const outcomes = logJourneyTopEntries(logJourneyAggregateRoutes(routes, 'outcome'), 7);
    const success = routes.reduce((sum, route) => sum + (route.success || 0), 0);
    const failure = routes.reduce((sum, route) => sum + (route.failure || 0), 0);
    const relatedFindings = logJourneyRelatedFindings(type, id, routes);
    const recommended = (state.logAnalysis.recommendedPolicySet?.policies || []).filter(policy => policy.drivers.some(driver => relatedFindings.some(finding => finding.title === driver.title)));
    const percentage = model.journey.total ? Math.round(entity.count / model.journey.total * 1000) / 10 : 0;
    const sourceContext = type === 'source' && !entity.loaded
      ? 'This export was not loaded, so the assessment cannot make claims about the activity it carries.'
      : entity.description;
    return {
      title: entity.label,
      kicker: type === 'source' && !entity.loaded ? 'Blind spot · not loaded' : `${entity.count.toLocaleString()} measured event${entity.count === 1 ? '' : 's'}`,
      status: type === 'source' && !entity.loaded ? 'blind' : entity.tone === 'gap' ? 'gap' : entity.tone === 'review' ? 'review' : entity.tone === 'protected' ? 'protected' : 'noIssue',
      body: [
        renderLogJourneyEvidenceSection('What happened', `<p>${esc(sourceContext)}</p><dl class="log-journey-evidence-facts"><div><dt>Measured events</dt><dd>${esc(entity.count.toLocaleString())}</dd></div><div><dt>Share of all events</dt><dd>${esc(percentage)}%</dd></div><div><dt>Successful</dt><dd>${esc(success.toLocaleString())}</dd></div><div><dt>Failed</dt><dd>${esc(failure.toLocaleString())}</dd></div></dl>`),
        renderLogJourneyEvidenceSection('Path breakdown', `<div class="log-journey-breakdowns"><div><h5>By source</h5>${renderLogJourneyFactList(sources, Object.fromEntries(LOG_SOURCE_ORDER.map(key => [key, LOG_SOURCES[key].short])))}</div><div><h5>By CA decision</h5>${renderLogJourneyFactList(decisions, Object.fromEntries(LOG_JOURNEY_DECISIONS.map(item => [item.id, item.label])))}</div><div><h5>By outcome</h5>${renderLogJourneyFactList(outcomes, Object.fromEntries(LOG_JOURNEY_OUTCOMES.map(item => [item.id, item.label])))}</div></div>`),
        renderLogJourneyEvidenceSection('Entities and evidence', `<div class="log-journey-breakdowns"><div><h5>Top identities</h5>${renderLogJourneyFactList(identities)}</div><div><h5>Top apps</h5>${renderLogJourneyFactList(apps)}</div><div><h5>Top locations</h5>${renderLogJourneyFactList(locations)}</div></div>${relatedFindings.length ? `<p><strong>Related findings:</strong> ${relatedFindings.map(finding => `<button type="button" class="log-journey-inline-link" data-journey-type="finding" data-journey-id="${esc(finding.id)}">${esc(finding.title)} (${esc(finding.severity)})</button>`).join(' · ')}</p>` : '<p>No related gap finding was produced for this path.</p>'}`),
        renderLogJourneyEvidenceSection('Policies evaluated', evaluatedPolicies.length ? `<p>${esc(evaluatedPolicies.map(item => `${item.name} (${item.count})`).join(' · '))}</p>${matchedPolicies.length ? `<p><strong>Matched or acted:</strong> ${esc(matchedPolicies.map(item => `${item.name} (${item.count})`).join(' · '))}</p>` : ''}` : '<p><strong>No policy evaluation was returned for these events.</strong> This can mean Conditional Access was not engaged, the flow was outside its boundary, or the export format omitted per-policy detail. The map does not invent a policy explanation.</p>'),
        renderLogJourneyEvidenceSection('Recommended action', `<p>${esc(type === 'source' && !entity.loaded ? `Export ${LOG_SOURCES[id].label} for the same date range and add it to this assessment.` : relatedFindings.length ? 'Work through the related findings and connected control elements, then test the proposed controls in report-only.' : 'Confirm this path matches tenant intent and keep it in the validation cycle.')}</p>${recommended.length ? `<p><strong>${esc(recommended.length)} proposed ${recommended.length === 1 ? 'policy is' : 'policies are'} connected to these findings.</strong></p>` : ''}`),
        renderLogJourneyEvidenceSection('Representative events', `${renderLogJourneySamples(samples)}<p>Validate with a fresh JSON sign-in export and inspect the Conditional Access tab for the sampled events.</p>`)
      ].join('')
    };
  }

  function updateLogJourneyEvidence() {
    const panel = $('logJourneyEvidence');
    if (!panel) return;
    panel.outerHTML = renderLogJourneyEvidence(buildLogJourneyModel());
    applyLogJourneySelection();
  }

  function cancelLogJourneyEvidenceReveal() {
    if (!logJourneyRevealFrame) return;
    cancelAnimationFrame(logJourneyRevealFrame);
    logJourneyRevealFrame = 0;
  }

  function revealLogJourneyEvidence() {
    cancelLogJourneyEvidenceReveal();
    logJourneyRevealFrame = requestAnimationFrame(() => {
      logJourneyRevealFrame = requestAnimationFrame(() => {
        logJourneyRevealFrame = 0;
        const panel = $('logJourneyEvidence');
        const heading = $('logJourneyEvidenceTitle');
        if (!panel || !heading) return;
        const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        heading.focus({ preventScroll: true });
        panel.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
      });
    });
  }

  function applyLogJourneyTabs() {
    const root = $('logVisualContent');
    if (!root) return;
    const workspaceTab = ['controls', 'policies', 'adjacent'].includes(state.logAnalysis.journeyWorkspaceTab)
      ? state.logAnalysis.journeyWorkspaceTab
      : 'controls';
    const policyTab = state.logAnalysis.journeyPolicyTab === 'observed' ? 'observed' : 'recommended';
    root.querySelectorAll('[data-log-workspace-tab]').forEach(tab => {
      const active = tab.dataset.logWorkspaceTab === workspaceTab;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', String(active));
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });
    root.querySelectorAll('[data-log-workspace-panel]').forEach(panel => {
      panel.hidden = panel.dataset.logWorkspacePanel !== workspaceTab;
    });
    root.querySelectorAll('[data-log-policy-tab]').forEach(tab => {
      const active = tab.dataset.logPolicyTab === policyTab;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', String(active));
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });
    root.querySelectorAll('[data-log-policy-panel]').forEach(panel => {
      panel.hidden = panel.dataset.logPolicyPanel !== policyTab;
    });
  }

  function activateLogJourneyTab(group, value, options) {
    const settings = options || {};
    const valid = group === 'workspace'
      ? ['controls', 'policies', 'adjacent'].includes(value)
      : group === 'policy' && ['recommended', 'observed'].includes(value);
    if (!valid) return false;
    const key = group === 'workspace' ? 'journeyWorkspaceTab' : 'journeyPolicyTab';
    const changed = state.logAnalysis[key] !== value;
    state.logAnalysis[key] = value;
    if (changed && settings.clearSelection !== false) clearLogJourneySelection(false);
    applyLogJourneyTabs();
    if (settings.focus) {
      const selector = group === 'workspace' ? `[data-log-workspace-tab="${CSS.escape(value)}"]` : `[data-log-policy-tab="${CSS.escape(value)}"]`;
      $('logVisualContent')?.querySelector(selector)?.focus({ preventScroll: true });
    }
    return true;
  }

  function routeLogJourneyEntity(type, id) {
    if (type === 'observedPolicy') {
      activateLogJourneyTab('workspace', 'policies', { clearSelection: false });
      activateLogJourneyTab('policy', 'observed', { clearSelection: false });
      return;
    }
    if (type === 'recommendedPolicy') {
      activateLogJourneyTab('workspace', 'policies', { clearSelection: false });
      activateLogJourneyTab('policy', 'recommended', { clearSelection: false });
      return;
    }
    if (type !== 'element' && type !== 'finding') return;
    const adjacent = type === 'element'
      ? LOG_JOURNEY_ADJACENT.some(element => element.id === id)
      : LOG_JOURNEY_ADJACENT.some(element => element.findingIds.includes(id));
    activateLogJourneyTab('workspace', adjacent ? 'adjacent' : 'controls', { clearSelection: false });
  }

  function selectLogJourneyEntity(type, id, opener) {
    const current = state.logAnalysis.journeySelected;
    if (!logJourneyEntityDetail(type, id)) return;
    routeLogJourneyEntity(type, id);
    if (current?.type === type && current.id === id) {
      updateLogJourneyEvidence();
      revealLogJourneyEvidence();
      return;
    }
    state.logAnalysis.journeySelected = { type, id };
    logJourneySelectionOpener = { element: opener || document.activeElement, type, id };
    updateLogJourneyEvidence();
    applyLogJourneySelection();
    revealLogJourneyEvidence();
  }

  function clearLogJourneySelection(restoreFocus) {
    cancelLogJourneyEvidenceReveal();
    if (!state.logAnalysis.journeySelected) return;
    const opener = logJourneySelectionOpener;
    state.logAnalysis.journeySelected = null;
    updateLogJourneyEvidence();
    applyLogJourneySelection();
    if (restoreFocus !== false && opener) {
      const candidates = [...($('logVisualContent')?.querySelectorAll('[data-journey-type][data-journey-id]') || [])];
      const target = opener.element?.isConnected
        ? opener.element
        : candidates.find(item => item.dataset.journeyType === opener.type && item.dataset.journeyId === opener.id);
      requestAnimationFrame(() => target?.focus());
    }
    logJourneySelectionOpener = null;
  }

  function onLogJourneyKeydown(event) {
    if (state.logAnalysis.view !== 'visual') return;
    const tab = event.target.closest?.('[role="tab"][data-log-workspace-tab], [role="tab"][data-log-policy-tab]');
    if (tab && (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar')) {
      event.preventDefault();
      const group = tab.hasAttribute('data-log-workspace-tab') ? 'workspace' : 'policy';
      const value = group === 'workspace' ? tab.dataset.logWorkspaceTab : tab.dataset.logPolicyTab;
      activateLogJourneyTab(group, value, { clearSelection: true, focus: true });
      return;
    }
    if (tab && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) {
      const tablist = tab.closest('[role="tablist"]');
      const tabs = [...(tablist?.querySelectorAll(':scope > [role="tab"]') || [])];
      const currentIndex = tabs.indexOf(tab);
      if (currentIndex < 0 || !tabs.length) return;
      event.preventDefault();
      const backwards = event.key === 'ArrowLeft' || event.key === 'ArrowUp';
      const nextIndex = event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? tabs.length - 1
          : (currentIndex + (backwards ? -1 : 1) + tabs.length) % tabs.length;
      const next = tabs[nextIndex];
      const group = next.hasAttribute('data-log-workspace-tab') ? 'workspace' : 'policy';
      const value = group === 'workspace' ? next.dataset.logWorkspaceTab : next.dataset.logPolicyTab;
      activateLogJourneyTab(group, value, { clearSelection: true, focus: true });
      return;
    }
    if (event.key !== 'Escape' || !state.logAnalysis.journeySelected) return;
    event.preventDefault();
    clearLogJourneySelection();
  }

  function openLogFindingInList(findingId) {
    state.logAnalysis.view = 'list';
    state.logAnalysis.filter = 'all';
    state.logAnalysis.sourceFilter = 'all';
    renderLogAnalysis();
    const detail = document.getElementById(`log-finding-${logJourneyDomId(findingId)}`) || document.getElementById(`log-finding-${findingId}`);
    if (detail) {
      detail.open = true;
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
      detail.querySelector('summary')?.focus({ preventScroll: true });
    }
  }

  function onLogVisualInteraction(event) {
    const workspaceTab = event.target.closest('[data-log-workspace-tab]');
    if (workspaceTab) {
      activateLogJourneyTab('workspace', workspaceTab.dataset.logWorkspaceTab, { clearSelection: true });
      return;
    }
    const policyTab = event.target.closest('[data-log-policy-tab]');
    if (policyTab) {
      activateLogJourneyTab('policy', policyTab.dataset.logPolicyTab, { clearSelection: true });
      return;
    }
    const openFinding = event.target.closest('[data-log-open-finding]');
    if (openFinding) {
      openLogFindingInList(openFinding.dataset.logOpenFinding);
      return;
    }
    const details = event.target.closest('[data-log-show-details]');
    if (details) {
      state.logAnalysis.view = 'list';
      state.logAnalysis.journeySelected = null;
      renderLogAnalysis();
      $('logViewControl')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (event.target.closest('[data-log-journey-clear]')) {
      clearLogJourneySelection();
      return;
    }
    if (event.target.closest('[data-log-scroll-policy-board]')) {
      activateLogJourneyTab('workspace', 'policies', { clearSelection: false });
      activateLogJourneyTab('policy', 'recommended', { clearSelection: false });
      const board = $('logJourneyPolicyBoard');
      board?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      requestAnimationFrame(() => board?.focus({ preventScroll: true }));
      return;
    }
    const declaration = event.target.closest('[data-declaration][data-answer]');
    if (declaration) {
      setDeclaration(declaration.dataset.declaration, declaration.dataset.answer);
      return;
    }
    if (event.target.closest('[data-log-build-strategy]')) {
      buildStrategyFromFindings();
      return;
    }
    if (event.target.closest('[data-log-build-guide]')) {
      exportBuildGuideDocx();
      return;
    }
    const policyDownload = event.target.closest('[data-log-policy-download]');
    if (policyDownload && !policyDownload.disabled) {
      downloadPolicyOfficeReport(policyDownload.dataset.policyKind, policyDownload.dataset.policyFormat);
      return;
    }
    if (event.target.closest('[data-log-toggle-observed]')) {
      const selected = state.logAnalysis.journeySelected;
      if (state.logAnalysis.observedPoliciesExpanded && selected?.type === 'observedPolicy') {
        const policy = state.logAnalysis.policyInventory?.policies.find(item => item.name === selected.id);
        if (policy?.state === 'neverMatched') state.logAnalysis.journeySelected = null;
      }
      state.logAnalysis.observedPoliciesExpanded = !state.logAnalysis.observedPoliciesExpanded;
      $('logVisualContent').innerHTML = renderLogVisualWorkspace();
      applyLogJourneyTabs();
      applyLogJourneySelection();
      queueLogJourneyDraw();
      return;
    }
    const entity = event.target.closest('[data-journey-type][data-journey-id]');
    if (entity) {
      selectLogJourneyEntity(entity.dataset.journeyType, entity.dataset.journeyId, entity);
      return;
    }
    if (event.target.closest('[data-journey-clear-space]')) clearLogJourneySelection();
  }

  function renderLogFindingCard(finding) {
    const cardClass = { high: 'status-risk', medium: 'status-different', low: 'status-extra', info: 'status-exact' }[finding.severity] || 'status-risk';
    const chipClass = logSeverityChip(finding.severity);
    const scope = finding.metric.scope || 'sign-ins';
    const sourceKeys = finding.metric.sources || [];
    const sourceNames = sourceKeys.length ? sourceKeys.map(key => LOG_SOURCES[key].label).join(', ') : 'all loaded logs';
    const topList = (label, items, unit) => items.length
      ? `<div><strong>${esc(label)}</strong><ul>${items.map(item => `<li>${esc(item.name)} (${esc(item.count)} ${esc(unit)})</li>`).join('')}</ul></div>`
      : '';
    const tops = topList(finding.topUsersLabel || 'Top users', finding.topUsers, finding.unit || 'sign-ins')
      + topList(finding.topAppsLabel || 'Top apps', finding.topApps, finding.unit || 'sign-ins')
      + topList('Top devices', finding.topDevices || [], finding.unit || 'sign-ins')
      + topList('Top locations', finding.topLocations || [], finding.unit || 'sign-ins');
    const indexed = finding.samples.map((s, idx) => ({ s, idx }));
    const structured = indexed.filter(({ s }) => s && typeof s === 'object' && !s.kind);
    const entities = indexed.filter(({ s }) => s && typeof s === 'object' && s.kind === 'entity');
    const plain = indexed.filter(({ s }) => typeof s === 'string').map(({ s }) => s);
    const expanded = state.logAnalysis.expanded || new Set();
    const rowAttrs = (s, idx) => {
      if (!s.triage) return '';
      const open = expanded.has(`${finding.id}:${idx}`);
      return ` class="log-evidence-row" data-fid="${esc(finding.id)}" data-idx="${idx}" tabindex="0" role="button" aria-expanded="${open}"`;
    };
    const detailRow = (s, idx, colspan) => (s.triage && expanded.has(`${finding.id}:${idx}`)
      ? `<tr class="log-event-detail"><td colspan="${colspan}">${renderEventTriage(s, s.triage)}</td></tr>`
      : '');
    const explainCell = s => `<td class="log-explain-cell">${s.triage ? '<span class="log-chevron" aria-hidden="true">▾</span> Explain' : ''}</td>`;
    const samples = structured.length
      ? `<div class="log-samples">
          <strong>Evidence — what signed in, from where</strong>
          <em class="log-evidence-hint">Click any row for the full expert triage of that specific sign-in: what happened, the root cause, and the exact fix.</em>
          <div class="log-evidence-scroll"><table class="log-evidence">
            <thead><tr><th>When (UTC)</th><th>Identity</th><th>App</th><th>Device</th><th>Location</th><th></th></tr></thead>
            <tbody>${structured.map(({ s, idx }) => `<tr${rowAttrs(s, idx)}>
              <td>${esc(s.time)}<em>${esc(s.source)}${s.representedEvents > 1 ? ` · represents ${esc(s.representedEvents)} events` : ''}</em></td>
              <td>${esc(s.principal)}</td>
              <td>${esc(s.app)}${s.clientApp ? `<em>${esc(s.clientApp)}</em>` : ''}${s.note ? `<em>${esc(s.note)}</em>` : ''}</td>
              <td>${esc(s.device)}${s.deviceDetail ? `<em>${esc(s.deviceDetail)}</em>` : ''}${s.posture ? `<em>${esc(s.posture)}</em>` : ''}</td>
              <td>${esc(s.location)}${s.ip ? `<em>${esc(s.ip)}</em>` : ''}</td>
              ${explainCell(s)}
            </tr>${detailRow(s, idx, 6)}`).join('')}</tbody>
          </table></div>
          ${finding.metric.affected > structured.length ? `<em class="log-evidence-note">Showing the first ${esc(structured.length)} of ${esc(finding.metric.affected)}. For the complete set, filter the Entra sign-in logs on these users and apps, or use the top device and location breakdowns above.</em>` : ''}
        </div>`
      : entities.length
        ? `<div class="log-samples">
            <strong>Evidence</strong>
            <em class="log-evidence-hint">Click any row for the full expert triage: what it means, the root cause, and the exact fix.</em>
            <div class="log-evidence-scroll"><table class="log-evidence">
              <thead><tr><th>Observation</th><th></th></tr></thead>
              <tbody>${entities.map(({ s, idx }) => `<tr${rowAttrs(s, idx)}>
                <td>${esc(s.label)}</td>
                ${explainCell(s)}
              </tr>${detailRow(s, idx, 2)}`).join('')}</tbody>
            </table></div>
          </div>`
        : plain.length
          ? `<div class="log-samples"><strong>Evidence</strong><ul>${plain.map(s => `<li>${esc(s)}</li>`).join('')}</ul></div>`
          : '';
    const actionPlan = (finding.actionPlan || []).length
      ? `<section class="log-block log-action-plan"><h5>What to actually do — per-event action plan</h5>
          <ol>${finding.actionPlan.map(a => `<li>
            <span class="count-pill">${esc(a.count)}</span>
            <span class="status-chip ${esc({ definite: 'import-exact', likely: 'import-extra', verify: 'import-different' }[a.confidence] || 'import-extra')} log-triage-chip">${esc((LOG_TRIAGE_CONFIDENCE[a.confidence] || {}).label || a.confidence)}</span>
            <strong>${esc(a.headline)}</strong>
            ${a.examples.length ? `<em>${esc(a.examples.join(', '))}</em>` : ''}
          </li>`).join('')}</ol>
          <p class="log-evidence-note">Built from the ${esc(finding.samples.length)} sampled events above — expand any evidence row for the full reasoning behind each item.</p>
        </section>`
      : '';
    const d = finding.diagnosis;
    const platformNote = d
      ? `<section class="log-block log-diagnosis"><h5>Why these specific sign-ins were not covered</h5>
          ${d.actionable !== undefined ? `<p class="log-callout log-callout-info"><strong>Severity is judged on the ${esc(d.actionable)} actionable event(s), not the headline count.</strong> ${esc(d.platformFlow)} of these sign-ins are platform flows that Conditional Access never evaluates — by design, permanently, and harmlessly. ${d.actionable === 0 ? 'Nothing in this finding needs fixing.' : 'They are listed for completeness; the events that matter are the remainder.'}</p>` : ''}
          <p>Two different things produce a notApplied status, and they need different responses. This is the split for your data:</p>
          <ul class="log-diagnosis-split">
            ${d.notEngaged ? `<li><strong>${esc(d.notEngaged)} — Conditional Access was never engaged.</strong> No policy was even evaluated for these sign-ins; Entra returned an empty policy list.${d.platformFlow ? ` <em>${esc(d.platformFlow)} of them are Windows and device-plumbing flows</em> — primary refresh token issuance, device registration and the authentication broker. Conditional Access does not evaluate those by design, so they will always read notApplied and no policy can change it. They are safe to discount.` : ''}</li>` : ''}
            ${d.evaluated ? `<li><strong>${esc(d.evaluated)} — policies ran, but every one was filtered out.</strong> These are the real scoping gaps: a policy existed and could have applied, but a condition excluded this sign-in.</li>` : ''}
          </ul>
          ${d.conditions.length ? `<p class="log-diagnosis-lead">Which condition excluded them:</p>
            <ul class="log-diagnosis-list">${d.conditions.map(c => `<li><span class="count-pill">${esc(c.count)}</span> ${esc(c.label)}</li>`).join('')}</ul>` : ''}
          ${d.policies.length ? `<p class="log-diagnosis-lead">The policies that came closest to applying — these are the ones to re-scope:</p>
            <ul class="log-diagnosis-list">${d.policies.map(p => `<li><span class="count-pill">${esc(p.count)}</span> ${esc(p.label)}</li>`).join('')}</ul>` : ''}
          ${!d.evaluated ? '<p class="log-diagnosis-lead">None of these had a policy evaluated, so there is no policy to re-scope — the fix is to create coverage where none exists, or accept the platform flows above as out of scope.</p>' : ''}
        </section>`
      : finding.deviceSplit && finding.deviceSplit.length
        ? `<section class="log-block log-diagnosis"><h5>Why these specific devices were not verified</h5>
            <p>"Not compliant" covers three different situations, and each needs a different fix. This is the split for your data:</p>
            <ul class="log-diagnosis-split">
              ${finding.deviceSplit.map(s => `<li><strong>${esc(s.count)} — ${esc(s.label)}.</strong> ${esc(s.detail)}.</li>`).join('')}
            </ul>
          </section>`
        : '';
    const guide = LOG_REMEDIATION[finding.id] || {};
    const flow = (guide.flow || []).length ? `
      <div class="log-flow" role="img" aria-label="Sign-in path showing where protection is missing">
        ${guide.flow.map((step, i) => `<div class="log-flow-step log-flow-${esc(step.state)}">
          <span class="log-flow-index">${esc(i + 1)}</span>
          <span class="log-flow-label">${esc(step.label)}</span>
        </div>`).join('')}
      </div>
      <p class="log-flow-key"><span class="log-flow-swatch log-flow-ok"></span> working as intended
        <span class="log-flow-swatch log-flow-gap"></span> where protection is missing
        <span class="log-flow-swatch log-flow-result"></span> outcome</p>` : '';
    const why = guide.cause ? `<section class="log-block"><h5>Why this is happening</h5><p>${esc(guide.cause)}</p>${flow}</section>` : '';
    const attack = guide.attack ? `<section class="log-block"><h5>What this lets an attacker do</h5><p>${esc(guide.attack)}</p></section>` : '';
    const fixSteps = (guide.fix || []).length
      ? `<ol class="log-fix-steps">${guide.fix.map(step => `<li>${esc(step)}</li>`).join('')}</ol>`
      : '';
    const policyBlocks = finding.policies.length
      ? `<div class="log-policy-fixes">
          <h6>${esc(guide.caFixes === false ? 'Related baseline policies (partial coverage only)' : 'Policies that implement this fix')}</h6>
          ${finding.policies.map(p => renderPolicyFixDetail(p.id)).join('')}
        </div>`
      : '';
    const noCaNote = guide.caFixes === false
      ? '<p class="log-callout">Conditional Access cannot fix this on its own — the actions below are the ones that actually close it.</p>'
      : '';
    const fix = fixSteps || policyBlocks
      ? `<section class="log-block log-block-fix"><h5>How to fix it</h5>${noCaNote}${fixSteps}${policyBlocks}</section>`
      : '';
    const verify = guide.verify ? `<section class="log-block"><h5>How to confirm it worked</h5><p>${esc(guide.verify)}</p></section>` : '';
    const fallback = !guide.cause && finding.recommendation
      ? `<section class="log-block"><h5>Recommendation</h5><p>${esc(finding.recommendation)}</p></section>` : '';
    return `<details id="log-finding-${esc(finding.id)}" class="comparison-card ${cardClass}">
      <summary>
        <span class="status-chip ${chipClass} log-severity">${esc(finding.severity)}</span>
        <strong>${esc(finding.title)}</strong>
        <em>${esc(finding.metric.pct)}% of ${esc(scope)}</em>
      </summary>
      <div class="comparison-body">
        <p class="log-detail">${esc(finding.detail)}</p>
        <dl>
          <dt>Affected</dt><dd>${esc(finding.metric.affected)} of ${esc(finding.metric.total)} ${esc(scope)} (${esc(finding.metric.pct)}%)</dd>
          <dt>Evidence from</dt><dd>${esc(sourceNames)}</dd>
        </dl>
        ${tops ? `<div class="log-top-lists">${tops}</div>` : ''}
        ${samples}
        ${actionPlan}
        ${why}${platformNote}${attack}${fix}${verify}${fallback}
      </div>
    </details>`;
  }

  function renderPolicyFixDetail(policyId) {
    const item = baselinePolicies().find(b => b.id === policyId);
    if (!item) return '';
    const rows = policyFixSettings(item);
    return `<details class="log-policy-fix">
      <summary><span class="status-chip">${esc(item.id)}</span><strong>${esc(shortName(item.displayName))}</strong><em>${esc(item.summary || '')}</em></summary>
      <dl class="log-policy-settings">
        ${rows.map(r => `<div><dt>${esc(r.label)}</dt><dd>${esc(r.value)}${r.note ? `<em>${esc(r.note)}</em>` : ''}</dd></div>`).join('')}
      </dl>
    </details>`;
  }

  // The per-event triage panel: end-to-end narrative, root cause with confidence, the
  // specific fix for this one sign-in, and the policy simulation where one exists.
  function renderEventTriage(sample, triage) {
    const conf = level => {
      const meta = LOG_TRIAGE_CONFIDENCE[level] || { label: level, hint: '' };
      const chip = { definite: 'import-exact', likely: 'import-extra', verify: 'import-different' }[level] || 'import-extra';
      return `<span class="status-chip ${chip} log-triage-chip" title="${esc(meta.hint)}">${esc(meta.label)}</span>`;
    };
    const narrative = triage.narrative.filter(Boolean).map(p => `<p>${esc(p)}</p>`).join('');
    const fix = triage.fix;
    const fixSteps = (fix.steps || []).length ? `<ol class="log-fix-steps">${fix.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : '';
    const verifySteps = (fix.verifyInPortal || []).length
      ? `<p class="log-diagnosis-lead">Verify in the portal:</p><ul class="log-diagnosis-list">${fix.verifyInPortal.map(s => `<li><span class="count-pill">→</span> ${esc(s)}</li>`).join('')}</ul>`
      : '';
    const policyDetail = fix.policyId ? renderPolicyFixDetail(fix.policyId) : '';
    const sim = triage.simulation;
    const simBlock = sim ? `
      <div class="log-sim">
        <p class="log-diagnosis-lead">What would have happened with ${esc(sim.policyId)} deployed:</p>
        <p class="log-sim-verdict log-sim-${esc(sim.verdict)}">${esc(
          sim.verdict === 'would-apply'
            ? `This sign-in would have matched ${sim.policyId}, and it would have enforced: ${sim.enforced.join('; ') || 'its configured controls'}.`
            : sim.verdict === 'would-apply-if'
              ? `This sign-in would have matched ${sim.policyId} — subject to the caveats below — and it would have enforced: ${sim.enforced.join('; ') || 'its configured controls'}.`
              : `${sim.policyId} would not have applied to this sign-in.`)}</p>
        <div class="log-evidence-scroll"><table class="log-sim-table">
          <thead><tr><th>Condition</th><th>This sign-in</th><th>Policy setting</th><th>Match</th></tr></thead>
          <tbody>${sim.matchChain.map(r => `<tr>
            <td>${esc(r.condition)}</td>
            <td>${esc(r.eventValue)}</td>
            <td>${esc(r.policyValue)}</td>
            <td class="log-sim-${r.matched === true ? 'yes' : r.matched === false ? 'no' : 'unknown'}">${r.matched === true ? '✓' : r.matched === false ? '✗' : '?'}${r.note ? `<em>${esc(r.note)}</em>` : ''}</td>
          </tr>`).join('')}</tbody>
        </table></div>
        ${sim.caveats.length ? `<ul class="log-warnings">${sim.caveats.map(c => `<li>${esc(c)}</li>`).join('')}</ul>` : ''}
        <p class="log-evidence-note">Simulated against the baseline policy as shipped — a recommendation, not your tenant's current state.</p>
      </div>` : '';
    return `<div class="log-triage">
      <p class="log-triage-cause">${conf(triage.rootCause.confidence)} <strong>Root cause: ${esc(triage.rootCause.title)}</strong></p>
      <div class="log-triage-narrative"><h6>What happened, end to end</h6>${narrative}</div>
      <div class="log-triage-fix"><h6>The fix for this specific sign-in</h6>
        <p class="log-triage-headline">${conf(fix.confidence)} <strong>${esc(fix.headline)}</strong></p>
        ${fixSteps}${verifySteps}${policyDetail}
      </div>
      ${simBlock}
    </div>`;
  }

  function onEvidenceRowToggle(e) {
    const row = e.target.closest('tr.log-evidence-row');
    if (!row) return;
    if (!state.logAnalysis.expanded) state.logAnalysis.expanded = new Set();
    const fid = row.dataset.fid;
    const idx = Number(row.dataset.idx);
    const finding = state.logAnalysis.findings.find(f => f.id === fid);
    const sample = finding && finding.samples[idx];
    if (!sample || !sample.triage) return;
    const key = `${fid}:${idx}`;
    const next = row.nextElementSibling;
    if (next && next.classList.contains('log-event-detail')) {
      next.remove();
      row.setAttribute('aria-expanded', 'false');
      state.logAnalysis.expanded.delete(key);
      return;
    }
    row.insertAdjacentHTML('afterend',
      `<tr class="log-event-detail"><td colspan="${row.children.length}">${renderEventTriage(sample, sample.triage)}</td></tr>`);
    row.setAttribute('aria-expanded', 'true');
    state.logAnalysis.expanded.add(key);
  }

  // Inventory of the Conditional Access policies actually deployed in the tenant, derived
  // purely from what Entra evaluated — hit counts, what each enforces, and who trips it.
  function renderLogPolicyInventory() {
    const inv = state.logAnalysis.policyInventory;
    if (!inv || !inv.policies.length) {
      return state.logAnalysis.summary
        ? `<div class="status-box log-policy-empty">No Conditional Access policy evaluations were recorded in these logs. Per-policy results come from the JSON export — a CSV export does not carry them.</div>`
        : '';
    }
    const s = inv.summary;
    const stateMeta = {
      enforcing: { chip: 'import-exact', label: 'Enforcing' },
      reportOnly: { chip: 'import-different', label: 'Report-only' },
      neverMatched: { chip: 'import-extra', label: 'Never matched' }
    };
    const topList = (label, items, unit) => items.length
      ? `<div><strong>${esc(label)}</strong><ul>${items.map(i => `<li>${esc(i.name)} (${esc(i.count)} ${esc(unit)})</li>`).join('')}</ul></div>`
      : '';
    const rows = inv.policies.map(p => {
      const meta = stateMeta[p.state];
      const enforces = [...p.grants.map(g => g.label), ...p.sessions.map(x => x.label), ...p.authStrength.map(a => `Strength: ${a.name}`)];
      const uniqueEnforces = [...new Set(enforces)];
      const evidence = p.samples.length
        ? `<div class="log-evidence-scroll"><table class="log-evidence">
            <thead><tr><th>When (UTC)</th><th>Identity</th><th>App</th><th>Device</th><th>Result</th></tr></thead>
            <tbody>${p.samples.map(x => `<tr>
              <td>${esc(x.time)}<em>${esc(x.source)}${x.representedEvents > 1 ? ` · represents ${esc(x.representedEvents)} events` : ''}</em></td>
              <td>${esc(x.principal)}</td>
              <td>${esc(x.app)}${x.clientApp ? `<em>${esc(x.clientApp)}</em>` : ''}</td>
              <td>${esc(x.device)}${x.deviceDetail ? `<em>${esc(x.deviceDetail)}</em>` : ''}</td>
              <td>${esc(x.result)}${x.grants.length ? `<em>${esc(x.grants.map(controlLabelFor).join(', '))}</em>` : ''}</td>
            </tr>`).join('')}</tbody>
          </table></div>`
        : '<p class="log-evidence-note">This policy never engaged in this date range, so there are no sign-ins to show.</p>';
      return `<details id="log-policy-${logJourneyDomId(p.name)}" class="log-policy-usage">
        <summary>
          <span class="status-chip ${esc(meta.chip)} log-policy-state">${esc(meta.label)}</span>
          <strong>${esc(p.name)}</strong>
          <em>${esc(p.applied)} applied · ${esc(p.evaluations)} evaluated</em>
        </summary>
        <div class="log-policy-usage-body">
          <dl class="log-policy-settings">
            <div><dt>Outcome</dt><dd>${esc(p.applied)} applied${p.blocked ? ` (${esc(p.blocked)} blocked or challenged)` : ''} · ${esc(p.reportOnly)} report-only · ${esc(p.notApplied)} did not match${p.hitRate ? ` — engages on ${esc(p.hitRate)}% of its evaluations` : ''}</dd></div>
            ${uniqueEnforces.length ? `<div><dt>Enforces</dt><dd>${esc(uniqueEnforces.join(' · '))}</dd></div>` : ''}
            ${p.sources.length ? `<div><dt>Seen in</dt><dd>${esc(p.sources.map(k => LOG_SOURCES[k].label).join(', '))}</dd></div>` : ''}
            ${p.from && p.to ? `<div><dt>Active</dt><dd>${esc(p.from.slice(0, 10))} to ${esc(p.to.slice(0, 10))}</dd></div>` : ''}
            ${p.baselineId ? `<div><dt>Baseline match</dt><dd>Named like baseline policy ${esc(p.baselineId)} — verify the actual settings in Microsoft Entra.</dd></div>` : ''}
            ${p.notSatisfied.length ? `<div><dt>Does not match when</dt><dd>${esc(p.notSatisfied.map(c => `${c.label} (${c.count})`).join(' · '))}</dd></div>` : ''}
          </dl>
          ${p.observedConfig.length ? `<div class="log-policy-config">
            <strong class="log-policy-evidence-head">Configuration observed from its evaluations</strong>
            <dl class="log-policy-settings">
              ${p.observedConfig.map(r => `<div><dt>${esc(r.label)}</dt><dd>${esc(r.value)}${r.note ? `<em>${esc(r.note)}</em>` : ''}</dd></div>`).join('')}
            </dl>
            <p class="log-evidence-note">Reconstructed from the rules Entra reported as satisfied — this is the scope as exercised by real sign-ins, not the stored policy definition. Review the policy in Microsoft Entra for the authoritative configuration.</p>
          </div>` : ''}
          ${mfaExclusionPolicies([p]).length ? renderLogJourneyMfaExclusions([p]) : ''}
          ${(p.topUsers.length || p.topApps.length) ? `<div class="log-top-lists">
            ${topList('Top users', p.topUsers, 'hits')}${topList('Top apps', p.topApps, 'hits')}
            ${topList('Top devices', p.topDevices, 'hits')}${topList('Top locations', p.topLocations, 'hits')}
          </div>` : ''}
          <strong class="log-policy-evidence-head">Sign-ins this policy acted on</strong>
          ${evidence}
        </div>
      </details>`;
    }).join('');
    const coverage = `<div class="log-policy-coverage">
      ${s.controlsEnforced.length ? `<p><strong>Controls actually enforced:</strong> ${esc(s.controlsEnforced.join(' · '))}</p>` : ''}
      ${s.controlsMissing.length ? `<p class="log-policy-missing"><strong>Nothing enforced these in this date range:</strong> ${esc(s.controlsMissing.join(' · '))}</p>` : ''}
    </div>`;
    return `<section class="panel log-policy-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Policy usage</p>
          <h3>Conditional Access policies in use</h3>
          <p class="guided-intro">Every policy Entra evaluated in these logs, ranked by how often it actually applied. Expand one to see what it enforces and the sign-ins it acted on.</p>
        </div>
      </div>
      <div class="import-dashboard log-policy-metrics">
        <article><span>Policies seen</span><strong>${esc(s.total)}</strong></article>
        <article><span>Enforcing</span><strong>${esc(s.enforcing)}</strong></article>
        <article><span>Report-only</span><strong>${esc(s.reportOnly)}</strong></article>
        <article><span>Never matched</span><strong>${esc(s.neverMatched)}</strong></article>
      </div>
      ${coverage}
      <div class="log-policy-list">${rows}</div>
      <p class="log-evidence-note">Derived from ${esc(s.evaluations)} policy evaluations in the loaded logs. A policy absent here was never evaluated in this date range — it may still exist in the tenant.</p>
    </section>`;
  }

  function renderLogStrategyCta() {
    const findings = state.logAnalysis.findings;
    if (!findings.length) return '';
    const plan = strategyHandOffFromFindings(findings, state.logAnalysis.declarations);
    if (!plan.requirementKeys.length) return '';
    const labels = plan.requirementKeys.map(key => STRATEGY_REQUIREMENTS[key].label);
    const set = state.logAnalysis.recommendedPolicySet;
    return `<div class="status-box log-cta">
      <strong>Recommended strategy from these findings</strong>
      <p>Protection level: ${esc(STRATEGY_LEVELS[plan.protection].label)}. Requirements: ${esc(labels.join(', '))}.${set ? ` Builds ${esc(set.policies.length)} Conditional Access policies, listed below exactly as they will be named in your tenant.` : ''}</p>
      <button class="btn primary" id="logBuildStrategyBtn" type="button">Build this strategy</button>
    </div>
    ${renderLogDeclarations()}
    ${renderRecommendedPolicies()}`;
  }

  // A one-line read of coverage. "0% direct" alone is misleading for the many baseline
  // policies scoped by group or role, where the log genuinely cannot resolve membership —
  // and "depends on group or role membership" told the reader only that the simulator gave
  // up. Name the condition that actually decided it instead.
  function coverageHeadline(cov) {
    if (!cov || !cov.evaluated) return 'not simulated';
    if (cov.wouldApply) return `${cov.pct}% of ${cov.scope} (${cov.wouldApply} of ${cov.evaluated})`;
    const reason = cov.reason && LOG_COVERAGE_REASONS[cov.reason[0]];
    if (reason) return reason.headline;
    return cov.conditional ? 'scope not resolvable from logs' : 'no matching traffic in these logs';
  }

  // The question a percentage cannot answer: is this policy relevant to me, and what do I
  // check to find out? Built from the reason the simulator recorded, plus whether the policy
  // blocks — zero matches on a block policy is the healthy result, not a sign of irrelevance.
  function coverageRelevance(item, cov) {
    if (!cov || !cov.evaluated) return null;
    const outOfScope = cov.notApplicable
      ? ` The other ${cov.notApplicable} sign-ins in these logs are ${cov.scope === 'user sign-ins' ? 'workload identity' : 'user'} sign-ins, which this policy cannot apply to at all.`
      : '';
    if (cov.wouldApply && !cov.conditional) {
      return { verdict: 'Confirmed against your traffic', text: `${cov.wouldApply} of the ${cov.evaluated} ${cov.scope} would have matched this policy outright, so its effect is measured rather than assumed.${outOfScope}`, check: '' };
    }
    const reason = cov.reason && LOG_COVERAGE_REASONS[cov.reason[0]];
    if (!reason) return null;
    const counted = cov.wouldApply
      ? `${cov.wouldApply} sign-ins matched outright and the rest could not be counted. `
      : '';
    const conditionalCase = cov.conditional > cov.wouldNot;
    // The counts are the load-bearing part: a block policy showing zero confirmed matches is
    // reporting a healthy tenant, which a bare "cannot be counted" hides.
    const split = conditionalCase && cov.wouldNot
      ? ` Of the rest, ${cov.wouldNot} ${cov.wouldNot === 1 ? 'sign-in was' : 'sign-ins were'} confirmed not to match it${item.blocks ? ', so nothing in these logs would be blocked today' : ''}.`
      : '';
    const verdict = conditionalCase
      ? 'Relevance depends on your tenant, not your traffic'
      : (item.blocks ? 'Preventive — nothing to block in this window' : 'No matching traffic in this window');
    return { verdict, text: counted + reason.detail + split + outOfScope, check: reason.check };
  }

  // The questions the logs cannot answer. Deliberately placed above the policy list, because
  // the answers change what the list contains.
  function renderLogDeclarations() {
    const answers = state.logAnalysis.declarations || defaultDeclarations();
    const unanswered = LOG_DECLARATIONS.filter(d => answers[d.key] === 'unknown').length;
    const rows = LOG_DECLARATIONS.map(d => {
      const current = answers[d.key] || 'unknown';
      const buttons = LOG_DECLARATION_ANSWERS.map(value => `<button type="button"
        class="log-declaration-btn${current === value ? ' active' : ''}"
        data-declaration="${esc(d.key)}" data-answer="${esc(value)}"
        aria-pressed="${current === value}">${esc({ yes: 'Yes', unknown: 'Not sure', no: 'No' }[value])}</button>`).join('');
      return `<div class="log-declaration">
        <div>
          <strong>${esc(d.question)}</strong>
          <p>${esc(d.why)}</p>
        </div>
        <div class="log-declaration-answers" role="group" aria-label="${esc(d.question)}">${buttons}</div>
      </div>`;
    }).join('');
    return `<section class="panel log-declaration-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Before the recommendations</p>
          <h3>Things your sign-in logs cannot tell us</h3>
          <p class="guided-intro">A log records what happened, not what exists. A tenant full of guests who did not sign in during your exported window looks identical to a tenant with no guests at all. Answer these and the policy list below updates.${unanswered ? ` <strong>${esc(unanswered)} still unanswered</strong> — those policies are included with a caveat rather than dropped.` : ''}</p>
        </div>
      </div>
      <div class="log-declaration-list">${rows}</div>
    </section>`;
  }

  // Because the consolidated set replaces the baselines it names, any baseline that the
  // selected controls imply but that no recommended policy delivers is a silent downgrade.
  // Stating it plainly is the difference between a recommendation and an over-claim.
  // ---------------------------------------------------------------------------
  // Word build guide. Reuses manualGuideSections() — the same step-by-step content
  // the Policy recommendations tab shows — so the document cannot drift from the app.
  // ---------------------------------------------------------------------------
  function buildGuideBlocks(set, summary) {
    const b = [];
    const profile = set.profile || {};
    const stamp = new Date().toISOString().slice(0, 10);
    const push = (...items) => items.forEach(i => b.push(i));

    push(
      docxPara('Conditional Access build guide', { style: 'Title' }),
      docxPara(`Generated by CA Architect V2 on ${stamp} from ${summary.evaluated} sign-ins in your own Entra ID logs.${profile.tenantId ? ` Tenant ${profile.tenantId}.` : ''}`, { style: 'Subtitle' }),
      docxPara([docxRun('Read this first. ', { bold: true }), docxRun(`These ${set.policies.length} policies replace the Microsoft baseline policies each one names — they do not sit on top of them. Complete the prerequisites below before you create any policy, and create every policy in report-only state first.`)], { style: 'Callout' })
    );

    // ---- Prerequisites ----
    push(docxPara('1. Before you start', { style: 'Heading1' }));

    const groups = [...new Set(set.policies.flatMap(p => (p.requiredObjects || [])))];
    push(docxPara('Security groups to create', { style: 'Heading2' }));
    push(docxPara('Create these in Entra ID > Groups before building any policy. Every policy below references them; a policy saved with an empty exclusion group is what locks administrators out of their own tenant.'));
    const groupRows = [['Security group', 'Purpose and membership']];
    GLOBAL_PREREQUISITES.forEach(text => {
      const name = (text.match(/CA-[\w-]+/) || ['CA-BreakGlassAccounts-Exclude'])[0];
      groupRows.push([name, 'Break-glass and emergency access accounts. Add at least two cloud-only accounts with permanent Global Administrator, excluded from every policy in this guide. Store the credentials offline.']);
    });
    groups.filter(g => !groupRows.some(r => r[0] === g)).forEach(name => {
      groupRows.push([name, /service/i.test(name)
        ? `Human-operated service accounts. Service principals observed separately in your logs: ${(profile.servicePrincipals || []).join(', ') || 'none in this export'}.`
        : 'Referenced by one or more policies in this guide. Confirm membership before enabling.']);
    });
    push(docxTable(groupRows, { header: true, widths: [38, 62] }));

    push(docxPara('Your environment, as measured from these logs', { style: 'Heading2' }));
    push(docxPara('Use these values when a policy asks you to select platforms, locations or accounts. They are what actually signed in during the exported window, not assumptions.'));
    const envRows = [['What', 'Observed in your logs']];
    if ((profile.platforms || []).length) envRows.push(['Device platforms', profile.platforms.map(p => `${p.name} (${p.count})`).join(', ')]);
    if ((profile.operatingSystems || []).length) envRows.push(['Operating systems', profile.operatingSystems.map(p => `${p.name} (${p.count})`).join(', ')]);
    if ((profile.countries || []).length) envRows.push(['Countries', profile.countries.map(p => `${p.name} (${p.count})`).join(', ')]);
    if ((profile.externalTenants || []).length) envRows.push(['External tenants your users signed in to', profile.externalTenants.map(p => `${p.name} (${p.count})`).join(', ')]);
    if ((profile.servicePrincipals || []).length) envRows.push(['Service principals', profile.servicePrincipals.join(', ')]);
    if (profile.userCount) envRows.push(['Distinct accounts seen', String(profile.userCount)]);
    if (envRows.length > 1) push(docxTable(envRows, { header: true, widths: [38, 62] }));

    push(docxPara('What you told us', { style: 'Heading2' }));
    push(docxPara('Sign-in logs record what happened, not what exists. These answers decided which policy families are included below; "not confirmed" means the policy is here because the logs could not rule it out.'));
    push(docxTable([['Question', 'Answer']].concat(LOG_DECLARATIONS.map(d => [
      d.question,
      { yes: 'Yes', no: 'No — policies for this were excluded', unknown: 'Not confirmed — included with a caveat' }[(set.declarations || {})[d.key]] || 'Not confirmed'
    ])), { header: true, widths: [58, 42] }));

    push(docxPara('Licensing and rollout', { style: 'Heading2' }));
    const usesRisk = set.policies.some(p => (p.controls || []).some(id => ['sign_in_risk', 'user_risk'].includes(id)));
    const usesDevice = set.policies.some(p => (p.controls || []).some(id => ['device_compliance', 'app_protection'].includes(id)));
    [
      'Microsoft Entra ID P1 is required for Conditional Access itself.',
      usesRisk ? 'Microsoft Entra ID P2 is required for the sign-in risk and user risk policies in this guide. Without it those policies save but never trigger.' : '',
      usesDevice ? 'Microsoft Intune is required for the device compliance and app protection policies. Enrol and mark devices compliant before enforcing, or compliant-device policies will block everyone.' : '',
      'Create every policy with State = Report-only. Leave it there for at least one full working week and review Insights and reporting before enforcing.',
      'Enable one policy at a time. If sign-ins break, set that single policy back to report-only rather than disabling the whole set.',
      'Confirm Security Defaults is disabled — Conditional Access policies do not take effect while it is on.'
    ].filter(Boolean).forEach(text => push(docxPara(text, { bullet: true, style: 'ListParagraph' })));

    // ---- Per policy, grouped by the identity type each one protects ----
    const categories = groupPoliciesByCategory(set.policies);
    const ordered = categories.flatMap(g => g.policies.map(p => ({ item: p, group: g })));
    let lastGroup = '';
    ordered.forEach(({ item, group }, index) => {
      push(docxPara(`${index + 2}. ${item.displayName}`, { style: 'Heading1' }));
      if (group.key !== lastGroup) {
        lastGroup = group.key;
        push(docxPara([docxRun(`${group.label}. `, { bold: true }), docxRun(group.identity)], { style: 'Callout' }));
      }
      if (item.summary) push(docxPara(item.summary, { italic: true }));

      push(docxPara('Why you need this', { style: 'Heading2' }));
      push(docxPara([docxRun(`${item.basis.label}. `, { bold: true }), docxRun(item.basis.detail)]));
      item.drivers.forEach(d => push(docxPara(`${d.severity.toUpperCase()} — ${d.title}: ${d.affected} of your ${d.scope} (${d.pct}%).`, { bullet: true, style: 'ListParagraph' })));
      const relevance = coverageRelevance(item, item.coverage);
      if (relevance) {
        push(docxPara([docxRun(`${relevance.verdict}. `, { bold: true }), docxRun(relevance.text + (relevance.check ? ` ${relevance.check}` : ''))], { style: 'Callout' }));
      }

      if (item.tailoring.length) {
        push(docxPara('Settings specific to your tenant', { style: 'Heading2' }));
        push(docxTable([['Setting', 'What to enter and why']].concat(
          item.tailoring.map(t => [t.label, t.value + (t.warn ? ` ${t.warn}` : '')])
        ), { header: true, widths: [32, 68] }));
      }

      push(docxPara('Step by step in the Entra admin center', { style: 'Heading2' }));
      push(docxPara('Entra ID > Protection > Conditional Access > Policies > New policy. Work through the sections in order; the numbering matches the portal blade.'));
      const original = item.source || item;
      const exported = exportPolicy(original, 'configured');
      // Rows that describe how this app models the policy rather than anything you type into
      // Entra. They belong in the app, not in a build guide handed to an engineer.
      const APP_ONLY_ROWS = new Set(['Rollout decision', 'Graph shape']);
      const reportOnly = !NON_REPORT_ONLY.has(original.id);
      manualGuideSections(original, exported, 'include').forEach(section => {
        const rows = section.rows.filter(row => !row.empty && !APP_ONLY_ROWS.has(row.label));
        if (!rows.length) return;
        push(docxPara(`${section.step}. ${section.title}`, { style: 'Heading3' }));
        if (section.desc) push(docxPara(section.desc, { italic: true, spaceAfter: 80 }));
        push(docxTable([['Setting', 'Value']].concat(rows.map(row => {
          // Keep the State row consistent with the rollout instruction at the top of the
          // guide, rather than echoing the shipped baseline's own state.
          if (row.label === 'State') {
            return ['State', reportOnly
              ? 'Report-only — leave it here for at least a week, review Insights and reporting, then set On.'
              : 'On — this policy cannot run in report-only mode, so review its scope carefully before saving.'];
          }
          return [
            row.label,
            (row.entries ? manualEntriesText(row.entries, false) : String(row.value || '')) + (row.help ? ` — ${row.help}` : '')
          ];
        })), { header: true, widths: [32, 68] }));
      });

      if (item.represents.length) {
        push(docxPara('What this replaces', { style: 'Heading2' }));
        push(docxPara(`This single policy carries the controls of baseline ${item.represents.length === 1 ? 'policy' : 'policies'} ${item.represents.join(', ')}. Do not also create ${item.represents.length === 1 ? 'that policy' : 'those policies'} separately.${item.mergeReason ? ` ${item.mergeReason}` : ''}`));
      }
    });

    // ---- Gaps ----
    if ((set.uncovered || []).length) {
      push(docxPara(`${set.policies.length + 2}. Controls these policies do not create`, { style: 'Heading1' }));
      push(docxPara(`Your sign-in logs point to the controls below, but none of the ${set.policies.length} policies in this guide configures them. Because those policies replace the baseline rather than adding to it, building only this guide leaves the controls below unimplemented anywhere in your tenant. Build each one separately, using the named Microsoft baseline policy as the starting point.`));
      push(docxTable([['Build this policy as well', 'Because you still need']].concat(
        set.uncovered.map(g => [
          `${g.id}\n${g.displayName}`,
          g.controls.map(id => (CONTROLS[id] || {}).label).filter(Boolean).join(', ') || 'Baseline control'
        ])
      ), { header: true, widths: [55, 45] }));
      push(docxPara('This list reflects only the traffic your export contained. Guest, location and agent policies will not appear here at all if none of that traffic occurred in the exported window — which is not the same as not needing them.', { italic: true }));
    }

    return b;
  }

  function exportBuildGuideDocx() {
    const set = state.logAnalysis.recommendedPolicySet;
    if (!set || !set.policies.length) {
      toast('Analyse sign-in logs first');
      return;
    }
    try {
      const blob = buildDocx(buildGuideBlocks(set, { evaluated: set.evaluated }));
      downloadBlob(blob, `conditional-access-build-guide-${new Date().toISOString().slice(0, 10)}.docx`);
      toast(`Build guide exported — ${set.policies.length} policies`);
    } catch (err) {
      toast(`Could not build the document: ${err.message}`);
    }
  }

  // Every policy carries one of these tags, so the page has to say what they mean. Counts come
  // from the live set, which also shows at a glance how much rests on evidence versus judgement.
  const LOG_BASIS_LEGEND = [
    { kind: 'evidenced', label: 'Evidenced', meaning: 'your logs proved this gap' },
    { kind: 'standard', label: 'Standard', meaning: 'baseline practice for any tenant' },
    { kind: 'declared', label: 'Declared', meaning: 'you answered yes above' },
    { kind: 'unconfirmed', label: 'Unconfirmed', meaning: 'you left the question unanswered, so it is included with a caveat' }
  ];

  function renderBasisLegend(items) {
    const counts = {};
    items.forEach(item => { counts[item.basis.kind] = (counts[item.basis.kind] || 0) + 1; });
    // All severity levels always show, including zeroes: a tag the reader has not hit yet still needs
    // explaining, and "Declared 0" tells them the answer is to use the questions above.
    const entries = LOG_BASIS_LEGEND.map(l => `<li${counts[l.kind] ? '' : ' class="empty"'}>
      <span class="status-chip ${esc(basisChip(l.kind))} log-basis-chip">${esc(l.label)}</span>
      <span><strong>${esc(counts[l.kind] || 0)}</strong> — ${esc(l.meaning)}</span>
    </li>`).join('');
    return `<ul class="log-basis-legend">${entries}</ul>`;
  }

  // Evidenced reads strongest, unconfirmed weakest — the chip colour should carry that.
  function basisChip(kind) {
    return {
      evidenced: 'import-risk',
      declared: 'import-exact',
      standard: 'import-different',
      unconfirmed: 'import-extra'
    }[kind] || 'import-different';
  }

  function logSeverityChip(severity) {
    return { high: 'import-risk', medium: 'import-different', low: 'import-extra', info: 'import-exact' }[severity] || 'import-risk';
  }

  // Turning a family off is a decision, not a disappearance — especially when the logs
  // already showed the gap it would have closed.
  function renderDeclinedFamilies(set) {
    const declined = set.declined || [];
    if (!declined.length) return '';
    const rows = declined.map(d => `<li><strong>${esc(d.question.replace(/\?$/, ''))} — no.</strong> ${d.contradictsEvidence
      ? `These logs disagree: ${esc(d.findings.map(f => `${f.title.toLowerCase()} (${f.affected} of your ${f.scope})`).join('; '))}. The policies that would have closed that are not in the list above.`
      : 'The policies for this are not in the list above.'}</li>`).join('');
    return `<div class="status-box log-policy-declined">
      <strong>${esc(declined.length)} policy ${declined.length === 1 ? 'family' : 'families'} excluded by your answers</strong>
      <ul>${rows}</ul>
    </div>`;
  }

  function renderRecommendedGaps(set) {
    const gaps = set.uncovered || [];
    if (!gaps.length) return '';
    const setSize = set.policies.length;
    const rows = gaps.map(g => {
      const labels = g.controls.map(id => (CONTROLS[id] || {}).label).filter(Boolean);
      return `<tr>
        <td><strong>${esc(g.id)}</strong><em>${esc(g.displayName)}</em></td>
        <td>${esc(labels.join(', ') || 'Baseline control')}</td>
      </tr>`;
    }).join('');
    return `<div class="status-box log-policy-gaps">
      <strong>${esc(gaps.length)} more ${gaps.length === 1 ? 'control is' : 'controls are'} still needed — the policies above do not create ${gaps.length === 1 ? 'it' : 'them'}</strong>
      <p>Your sign-in logs point to the controls in this table, but none of the ${esc(setSize)} policies above configures them. Remember those ${esc(setSize)} policies <strong>replace</strong> the baseline policies they list — they do not sit on top of it. So if you build only what is above, nothing in your tenant will be enforcing these:</p>
      <div class="log-evidence-scroll"><table class="log-evidence">
        <thead><tr><th>Build this policy as well</th><th>Because you still need</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <p class="log-policy-check">Build each one separately, using the Microsoft baseline policy named in the left column as your starting point. Note also that this list only reflects traffic your logs actually contained — guest, location and agent policies will not appear here at all if none of that traffic occurred in the window you exported, which is not the same as not needing them.</p>
    </div>`;
  }

  // The recommended baseline policies, in the same expandable format as the deployed
  // inventory — with each policy's real configuration and how much of THIS tenant's
  // traffic it would have applied to if deployed.
  function renderRecommendedPolicies() {
    const set = state.logAnalysis.recommendedPolicySet;
    if (!set || !set.policies.length) return '';
    const deployed = state.logAnalysis.policyInventory;
    const deployedNames = new Set((deployed ? deployed.policies : []).map(p => normToken(p.name)));
    const items = set.policies;
    const renderCard = item => {
      const cov = item.coverage;
      const rows = item.settings;
      const already = deployedNames.has(normToken(item.displayName));
      const relevance = coverageRelevance(item, cov);
      const controlLabels = (item.controls || []).map(id => (CONTROLS[id] || {}).label).filter(Boolean);
      const outcome = item.summary || (controlLabels.length
        ? `Applies ${controlLabels.join(', ')} to ${policyCategory(item.id).label.toLowerCase()}.`
        : 'Applies the selected Conditional Access controls to this identity scope.');
      const covLine = cov && cov.evaluated
        ? (cov.wouldApply || cov.conditional
          ? `${cov.wouldApply} of ${cov.evaluated} ${cov.scope} would have matched it outright (${cov.pct}%)${cov.conditional ? `; a further ${cov.conditional} could not be counted` : ''}${cov.notApplicable ? `. ${cov.notApplicable} further sign-ins are out of scope for this policy's identity type` : ''}`
          : `None of the ${cov.evaluated} ${cov.scope} would have matched it.`)
        : 'No coverage simulation available for this policy.';
      const evidence = cov && cov.samples.length
        ? `<div class="log-evidence-scroll"><table class="log-evidence">
            <thead><tr><th>When (UTC)</th><th>Identity</th><th>App</th></tr></thead>
            <tbody>${cov.samples.map(s => `<tr>
              <td>${esc(s.time)}<em>${esc(s.source)}</em></td>
              <td>${esc(s.principal)}</td>
              <td>${esc(s.app)}</td>
            </tr>`).join('')}</tbody>
          </table></div>`
        : '';
      return `<details class="log-policy-usage log-policy-recommended">
        <summary>
          <span class="status-chip ${already ? 'import-exact' : 'import-different'} log-policy-state">${already ? 'Already deployed' : 'Recommended'}</span>
          <span class="status-chip ${esc(basisChip(item.basis.kind))} log-basis-chip" title="${esc(item.basis.detail)}">${esc(item.basis.label)}</span>
          <span class="log-policy-summary-copy">
            <strong>${esc(tenantPolicyName(item.displayName))}</strong>
            <small><span>What it does</span>${esc(outcome)}</small>
          </span>
          <em>${esc(coverageHeadline(cov))}</em>
        </summary>
        <div class="log-policy-usage-body">
          <p class="log-policy-purpose">${esc(item.summary || '')}</p>
          <div class="log-policy-driver">
            <strong>Why this is recommended for you</strong>
            <p class="log-policy-basis-detail"><span class="status-chip ${esc(basisChip(item.basis.kind))} log-basis-chip">${esc(item.basis.label)}</span>${esc(item.basis.detail)}</p>
            ${item.drivers.length
              ? `<ul>${item.drivers.map(d => `<li><span class="status-chip ${esc(logSeverityChip(d.severity))} log-severity">${esc(d.severity)}</span> ${esc(d.title)} — ${esc(d.affected)} of your ${esc(d.scope)} (${esc(d.pct)}%)</li>`).join('')}</ul>`
              : ''}
          </div>
          ${relevance ? `<div class="log-policy-relevance">
            <strong>${esc(relevance.verdict)}</strong>
            <p>${esc(relevance.text)}</p>
            ${relevance.check ? `<p class="log-policy-check">${esc(relevance.check)}</p>` : ''}
          </div>` : ''}
          ${item.tailoring.length ? `<div class="log-policy-tailoring">
            <strong>Settings to enter for your tenant</strong>
            <dl>${item.tailoring.map(t => `<div><dt>${esc(t.label)}</dt><dd>${esc(t.value)}${t.warn ? `<em>${esc(t.warn)}</em>` : ''}</dd></div>`).join('')}</dl>
          </div>` : ''}
          <dl class="log-policy-settings">
            <div><dt>Policy name</dt><dd>${esc(tenantPolicyName(item.displayName))}<em>This is the name it will be created with in your tenant.</em></dd></div>
            ${rows.map(r => `<div><dt>${esc(r.label)}</dt><dd>${esc(r.value)}${r.note ? `<em>${esc(r.note)}</em>` : ''}</dd></div>`).join('')}
            <div><dt>Would apply to</dt><dd>${esc(covLine)}</dd></div>
            ${item.represents.length ? `<div><dt>Replaces baseline</dt><dd>${esc(item.represents.join(', '))}<em>${esc(item.mergeReason ? item.mergeReason + ' ' : '')}Deploying this policy means the listed baseline policies are not created separately — their controls are merged into this one.</em></dd></div>` : ''}
            ${already ? '<div><dt>Note</dt><dd>A policy with this name already exists in your tenant — verify its settings in Microsoft Entra rather than creating a duplicate.</dd></div>' : ''}
          </dl>
          ${evidence ? `<strong class="log-policy-evidence-head">Example sign-ins it would have applied to</strong>${evidence}` : ''}
        </div>
      </details>`;
    };
    // Grouped by which identity type each policy protects, in escalating scope order.
    const cards = groupPoliciesByCategory(items).map(group => `<div class="log-policy-group">
      <div class="log-policy-group-head">
        <h4><span class="log-policy-group-label">${esc(group.label)}</span><span class="log-policy-group-count">${esc(group.policies.length)} ${group.policies.length === 1 ? 'policy' : 'policies'}</span></h4>
        <p>${esc(group.identity)}</p>
      </div>
      ${group.policies.map(renderCard).join('')}
    </div>`).join('');
    const deployedCount = deployed ? deployed.policies.length : 0;
    return `<section class="panel log-policy-panel log-recommended-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Recommended policies</p>
          <h3>What the recommended strategy would deploy</h3>
          <p class="guided-intro">The ${esc(items.length)} policies "Build this strategy" will create, named exactly as they will appear in your tenant. Expand one to see why it is recommended for you, its configuration, and how much of your own traffic it would have applied to.</p>
          ${renderBasisLegend(items)}
        </div>
        <div class="import-actions">
          <button class="btn secondary" id="logBuildGuideBtn" type="button">Download build guide (.docx)</button>
        </div>
      </div>
      <div class="status-box log-policy-disposition">
        <strong>This is a replacement model, not an addition</strong>
        <p>These ${esc(items.length)} consolidated policies are designed to <em>supersede</em> the ${esc(set.replaces.length)} baseline policies they name under "Replaces baseline" — the controls are merged, not duplicated. Run them alongside your existing policies in report-only mode first, then retire what they replace. Deploying both permanently means two policies enforcing the same control, where the most restrictive always wins.</p>
        ${deployedCount ? `<p>Your tenant currently has ${esc(deployedCount)} Conditional Access ${deployedCount === 1 ? 'policy' : 'policies'} deployed. This set is derived from your sign-in logs, not from those policies, so map each one to what it replaces yourself before retiring anything — use the deployed policy inventory above.</p>` : ''}
      </div>
      ${renderDeclinedFamilies(set)}
      ${renderRecommendedGaps(set)}
      <div class="log-policy-list">${cards}</div>
      <p class="log-evidence-note">Coverage simulated against ${esc(set.evaluated)} sign-ins from the loaded logs${set.capped ? ' (capped for performance)' : ''}. Group, role, location and device-filter conditions cannot be resolved from sign-in logs; those policies are reported by what decides their scope rather than counted as matches.</p>
    </section>`;
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
    const authBlocked = selectedPolicies().filter(configuredAuthenticationExportBlocked);
    if (authBlocked.length) {
      const missing = authenticationReadinessMissing(state.appliedStrategy?.requirements || state.strategy, authBlocked.find(policy => policy.persona === 'Guests') || authBlocked[0]);
      warnings.push({ text: `Enabled phishing-resistant rollout is not ready. Complete: ${missing.map(key => AUTHENTICATION_READINESS_STEPS.find(step => step.id === key)?.label || key).join(', ')}. Report-only export is still available.`, critical: true });
    }
    if (state.appliedStrategy?.requirements?.retirePhishableMethods && state.appliedStrategy?.type === 'strategy') {
      warnings.push({ text: 'Retiring non-phishing-resistant methods is a separate Authentication methods policy change and is intentionally not included in Conditional Access JSON.', critical: false });
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
