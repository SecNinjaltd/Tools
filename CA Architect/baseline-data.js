window.CA_BASELINE = {
  "version": "2026.6.1",
  "commit": "1af233f9ab6bbf609d6e42b383bd0af5aa258774",
  "upstream": {
    "repo": "https://github.com/j0eyv/ConditionalAccessBaseline",
    "version": "2026.6.1",
    "commit": "1af233f9ab6bbf609d6e42b383bd0af5aa258774"
  },
  "approvedOverrides": [
    {
      "id": "CA102",
      "sourceFile": "Config/ConditionalAccess/CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json",
      "path": "sessionControls.signInFrequency.value",
      "local": 4,
      "upstream": 12,
      "summary": "Admin sign-in frequency is intentionally hardened to 4 hours in CA Architect V2."
    }
  ],
  "policies": [
    {
      "id": "CA000",
      "persona": "Global",
      "displayName": "CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Catch-all MFA for authentications not captured by more specific persona policies.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "8e75af29-5176-4372-a718-724b8a4620dc",
              "cfa1f128-ec48-4ee1-9ea9-1c28fdb57722",
              "2eee133e-3427-4860-81b9-057d5b28b022",
              "349156c1-2fb1-4ffa-9cd3-5c4418e24e4c",
              "7452a2db-063a-4048-84b0-ff691fa2900e",
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "68ce874b-21a9-4ca9-b447-f09a037be53a"
            ],
            "excludeRoles": [
              "d29b2b05-8046-44ba-8758-1e26182fcf32"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA001",
      "persona": "Global",
      "displayName": "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist",
      "sourceFile": "Config/ConditionalAccess/CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist.json",
      "state": "enabled",
      "risk": "critical",
      "summary": "Block sign-ins from countries outside the approved country named location.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed",
        "ALLOWED COUNTRIES named location configured"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "ALLOWED COUNTRIES"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "6499f521-8620-4f4e-92a1-db47c79362e8",
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "813e2655-e8b9-4255-91f5-7761ee2824bb"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ],
            "excludeLocations": [
              "185c993e-10a9-44fa-98d1-230c8f72f497"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA002",
      "persona": "Global",
      "displayName": "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication",
      "sourceFile": "Config/ConditionalAccess/CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block legacy authentication protocols that cannot satisfy modern MFA controls.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "exchangeActiveSync",
            "other"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "8861a932-f1d1-4d1d-a5e6-cdce20fada27"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA003",
      "persona": "Global",
      "displayName": "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA when users register or join devices to the tenant.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeUserActions": [
              "urn:user:registerdevice"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "c4906422-18aa-47d8-b808-8c4919b655d8"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA004",
      "persona": "Global",
      "displayName": "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows",
      "sourceFile": "Config/ConditionalAccess/CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block authentication flow transfer/device-code style handoff abuse.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "f389fc8e-3965-4ae0-aa53-87511ab05f2b"
            ]
          },
          "authenticationFlows": {
            "transferMethods": "deviceCodeFlow,authenticationTransfer"
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA005",
      "persona": "Global",
      "displayName": "CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-RequireAppProtection",
      "sourceFile": "Config/ConditionalAccess/CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-RequireAppProtection.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require app protection for Office 365 data access on unmanaged devices.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-RequireAppProtection",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "Office365"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "20cd89e3-25e2-4fcd-82c5-de666dfd31a4"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "android",
              "iOS"
            ]
          },
          "devices": {
            "deviceFilter": {
              "mode": "exclude",
              "rule": "device.isCompliant -eq True -and device.deviceOwnership -eq \"Company\""
            }
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantApplication"
          ]
        },
        "sessionControls": {
          "applicationEnforcedRestrictions": {
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA005",
      "persona": "Global",
      "displayName": "CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-RequireAppProtection",
      "sourceFile": "Config/ConditionalAccess/CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-RequireAppProtection.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require app protection for Office 365 data access on unmanaged devices.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "variant",
      "policy": {
        "displayName": "CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-RequireAppProtection",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "Office365"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "20cd89e3-25e2-4fcd-82c5-de666dfd31a4"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "android",
              "iOS"
            ]
          },
          "devices": {
            "deviceFilter": {
              "mode": "exclude",
              "rule": "device.isCompliant -eq True -and device.deviceOwnership -eq \"Company\""
            }
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantApplication"
          ]
        },
        "sessionControls": {
          "applicationEnforcedRestrictions": {
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA006",
      "persona": "Global",
      "displayName": "CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions",
      "sourceFile": "Config/ConditionalAccess/CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Apply app-enforced restrictions or app protection for Office 365 browser/mobile access.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser"
          ],
          "applications": {
            "includeApplications": [
              "00000003-0000-0ff1-ce00-000000000000",
              "00000002-0000-0ff1-ce00-000000000000"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "a8e55fcf-f8ed-43c2-bb4f-0c62edd62963"
            ]
          },
          "devices": {
            "deviceFilter": {
              "mode": "exclude",
              "rule": "device.isCompliant -eq True -and device.deviceOwnership -eq \"Company\""
            }
          }
        },
        "sessionControls": {
          "applicationEnforcedRestrictions": {
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA006",
      "persona": "Global",
      "displayName": "CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection",
      "sourceFile": "Config/ConditionalAccess/CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Apply app-enforced restrictions or app protection for Office 365 browser/mobile access.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "variant",
      "policy": {
        "displayName": "CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "00000002-0000-0ff1-ce00-000000000000",
              "00000003-0000-0ff1-ce00-000000000000"
            ]
          },
          "users": {
            "includeUsers": [
              "All"
            ],
            "excludeGroups": [
              "a8e55fcf-f8ed-43c2-bb4f-0c62edd62963",
              "2802b872-ccfb-4b29-a9a9-459808dfb11b"
            ],
            "excludeRoles": [
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "62e90394-69f5-4237-9190-012177145e10",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "3a2c62db-5318-420d-8d74-23affee5d9d5"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "android",
              "iOS"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantApplication"
          ]
        }
      }
    },
    {
      "id": "CA100",
      "persona": "Admins",
      "displayName": "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA for administrator access to Microsoft admin portals.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "MicrosoftAdminPortals"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "70899f87-a5ba-4145-8bd5-2230db5dbbff"
            ],
            "includeRoles": [
              "62e90394-69f5-4237-9190-012177145e10",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "authenticationStrength": {
            "displayName": "Multifactor authentication",
            "description": "Combinations of methods that satisfy strong authentication, such as a password + SMS",
            "policyType": "builtIn",
            "requirementsSatisfied": "mfa",
            "allowedCombinations": [
              "windowsHelloForBusiness",
              "fido2",
              "x509CertificateMultiFactor",
              "deviceBasedPush",
              "temporaryAccessPassOneTime",
              "temporaryAccessPassMultiUse",
              "password,microsoftAuthenticatorPush",
              "password,softwareOath",
              "password,hardwareOath",
              "password,sms",
              "password,voice",
              "federatedMultiFactor",
              "microsoftAuthenticatorPush,federatedSingleFactor",
              "softwareOath,federatedSingleFactor",
              "hardwareOath,federatedSingleFactor",
              "sms,federatedSingleFactor",
              "voice,federatedSingleFactor"
            ]
          }
        }
      }
    },
    {
      "id": "CA101",
      "persona": "Admins",
      "displayName": "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA for administrator roles across cloud apps.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "8e75af29-5176-4372-a718-724b8a4620dc"
            ],
            "includeRoles": [
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "62e90394-69f5-4237-9190-012177145e10",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA102",
      "persona": "Admins",
      "displayName": "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency",
      "sourceFile": "Config/ConditionalAccess/CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Limit administrator session lifetime with a 4 hour sign-in frequency.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "5dcf5173-9efb-4f3f-a19d-2f03760d4e1d"
            ],
            "includeRoles": [
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "62e90394-69f5-4237-9190-012177145e10",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3"
            ]
          }
        },
        "sessionControls": {
          "signInFrequency": {
            "value": 4,
            "type": "hours",
            "authenticationType": "primaryAndSecondaryAuthentication",
            "frequencyInterval": "timeBased",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA103",
      "persona": "Admins",
      "displayName": "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
      "sourceFile": "Config/ConditionalAccess/CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Prevent persistent browser sessions for administrators.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "b89d30c2-3cbb-4431-aaad-c866aec9d7ba"
            ],
            "includeRoles": [
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "62e90394-69f5-4237-9190-012177145e10",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13"
            ]
          }
        },
        "sessionControls": {
          "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA104",
      "persona": "Admins",
      "displayName": "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation",
      "sourceFile": "Config/ConditionalAccess/CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Enable Continuous Access Evaluation for administrator sessions.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed",
        "Continuous Access Evaluation cannot be report-only"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "None"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "03267499-cd03-41bd-865b-70703b9bdb4d"
            ],
            "includeRoles": [
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "62e90394-69f5-4237-9190-012177145e10",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25"
            ]
          }
        },
        "sessionControls": {
          "continuousAccessEvaluation": {
            "mode": "strictLocation"
          }
        }
      }
    },
    {
      "id": "CA105",
      "persona": "Admins",
      "displayName": "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA",
      "sourceFile": "Config/ConditionalAccess/CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA.json",
      "state": "enabledForReportingButNotEnforced",
      "risk": "high",
      "summary": "Require phishing-resistant MFA for administrator roles.",
      "prerequisites": [
        "Security Defaults disabled",
        "Break-glass exclusion group reviewed"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ],
            "excludeApplications": [
              "14d82eec-204b-4c2f-b7e8-296a70dab67e"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "ab2172b3-67e0-4b55-b538-21467c8ebd45"
            ],
            "includeRoles": [
              "62e90394-69f5-4237-9190-012177145e10",
              "194ae4cb-b126-40b2-bd5b-6091b380977d",
              "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
              "29232cdf-9323-42fd-ade2-1d097af3e4de",
              "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
              "729827e3-9c14-49f7-bb1b-9608f156bbb8",
              "b0f54661-2d74-4c50-afa3-1ec803f12efe",
              "fe930be7-5e62-47db-91af-98c3a49a38b1",
              "c4e39bd9-1100-46d3-8c65-fb160da0071f",
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
              "158c047a-c907-4556-b7ef-446551a6b5f7",
              "966707d0-3269-4727-9be2-8c3a10f19b9d",
              "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
              "e8611ab8-c189-46e8-94e1-60213ab1f814",
              "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
              "3a2c62db-5318-420d-8d74-23affee5d9d5",
              "db506228-d27e-4b7d-95e5-295956d6615f",
              "6b942400-691f-4bf0-9d12-d8a254a2baf5",
              "d2562ede-74db-457e-a7b6-544e236ebb61",
              "e93e3737-fa85-474a-aee4-7d3fb86510f3",
              "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
              "1707125e-0aa2-4d4d-8655-a7c786c76a25",
              "69091246-20e8-4a56-aa4d-066075b2a7a8",
              "11451d60-acb2-45eb-a7d6-43d0f0125c13"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "authenticationStrength": {
            "displayName": "Phishing-resistant MFA",
            "description": "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
            "policyType": "builtIn",
            "requirementsSatisfied": "mfa",
            "allowedCombinations": [
              "windowsHelloForBusiness",
              "fido2",
              "x509CertificateMultiFactor"
            ]
          }
        }
      }
    },
    {
      "id": "CA200",
      "persona": "Internals",
      "displayName": "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA for internal users across cloud apps.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "cfa1f128-ec48-4ee1-9ea9-1c28fdb57722",
              "2802b872-ccfb-4b29-a9a9-459808dfb11b"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA201",
      "persona": "Internals",
      "displayName": "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser",
      "sourceFile": "Config/ConditionalAccess/CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block high-risk internal users.",
      "prerequisites": [
        "Security Defaults disabled",
        "Microsoft Entra ID Protection / P2 risk signals available"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser",
        "state": "enabled",
        "conditions": {
          "userRiskLevels": [
            "high"
          ],
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "c80b6cc8-5981-484b-80f2-da0387fe4393"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA202",
      "persona": "Internals",
      "displayName": "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices",
      "sourceFile": "Config/ConditionalAccess/CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Apply 12 hour sign-in frequency for unmanaged Windows and macOS internal devices.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "663dad60-a2c9-4228-afa5-a39fef078ad7"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "windows",
              "macOS"
            ]
          },
          "devices": {
            "deviceFilter": {
              "mode": "exclude",
              "rule": "device.deviceOwnership -eq \"Company\" -or device.isCompliant -eq True"
            }
          }
        },
        "sessionControls": {
          "signInFrequency": {
            "value": 12,
            "type": "hours",
            "authenticationType": "primaryAndSecondaryAuthentication",
            "frequencyInterval": "timeBased",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA203",
      "persona": "Internals",
      "displayName": "CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA when internal users enroll devices in Microsoft Intune.",
      "prerequisites": [
        "Security Defaults disabled",
        "Microsoft Intune Enrollment service principal exists"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "d4ebce55-015a-49b5-a083-c84d1797ae8c"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "2eee133e-3427-4860-81b9-057d5b28b022"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        },
        "sessionControls": {
          "signInFrequency": {
            "authenticationType": "primaryAndSecondaryAuthentication",
            "frequencyInterval": "everyTime",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA204",
      "persona": "Internals",
      "displayName": "CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms",
      "sourceFile": "Config/ConditionalAccess/CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block unknown or unsupported platforms for internal users.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "5002e94c-71d0-49ef-9633-b15168b0774c"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "all"
            ],
            "excludePlatforms": [
              "android",
              "iOS",
              "windows",
              "macOS"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA205",
      "persona": "Internals",
      "displayName": "CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ",
      "sourceFile": "Config/ConditionalAccess/CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require Windows devices to be compliant or hybrid joined.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ],
            "excludeApplications": [
              "0000000a-0000-0000-c000-000000000000",
              "d4ebce55-015a-49b5-a083-c84d1797ae8c"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "a76676e6-d7f2-45ff-9973-d6a28680db56"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "windows"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantDevice",
            "domainJoinedDevice"
          ]
        }
      }
    },
    {
      "id": "CA206",
      "persona": "Internals",
      "displayName": "CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
      "sourceFile": "Config/ConditionalAccess/CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Prevent persistent browser sessions for internal users on unmanaged devices.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "9168105d-1b57-4863-8008-94e8c619ca45"
            ]
          },
          "devices": {
            "deviceFilter": {
              "mode": "exclude",
              "rule": "device.deviceOwnership -eq \"Company\" -or device.isCompliant -eq True"
            }
          }
        },
        "sessionControls": {
          "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA207",
      "persona": "Internals",
      "displayName": "CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK",
      "sourceFile": "Config/ConditionalAccess/CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block selected applications for internal users.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "f53895d3-095d-408f-8e93-8f94b391404e"
            ],
            "excludeApplications": [
              "Office365"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "25114fcf-1656-47dc-9b4e-5dd4a2f680d7"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA208",
      "persona": "Internals",
      "displayName": "CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant",
      "sourceFile": "Config/ConditionalAccess/CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require macOS devices to be compliant.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ],
            "excludeApplications": [
              "0000000a-0000-0000-c000-000000000000",
              "d4ebce55-015a-49b5-a083-c84d1797ae8c"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "814dd6f8-2cc8-49a7-b360-b4887d686dc3"
            ]
          },
          "platforms": {
            "includePlatforms": [
              "macOS"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantDevice"
          ]
        }
      }
    },
    {
      "id": "CA209",
      "persona": "Internals",
      "displayName": "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation",
      "sourceFile": "Config/ConditionalAccess/CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Enable Continuous Access Evaluation for internal users.",
      "prerequisites": [
        "Security Defaults disabled",
        "Continuous Access Evaluation cannot be report-only"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "e7bb9f14-58fa-4a3f-9a7a-3c67cabc8788"
            ]
          }
        },
        "sessionControls": {
          "continuousAccessEvaluation": {
            "mode": "strictLocation"
          }
        }
      }
    },
    {
      "id": "CA210",
      "persona": "Internals",
      "displayName": "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn",
      "sourceFile": "Config/ConditionalAccess/CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block high-risk internal sign-ins.",
      "prerequisites": [
        "Security Defaults disabled",
        "Microsoft Entra ID Protection / P2 risk signals available"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "APP_Microsoft365_E5"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn",
        "state": "enabled",
        "conditions": {
          "signInRiskLevels": [
            "high"
          ],
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "ceeac9b8-ddf5-48cb-afcb-e2ab8bfd1a57"
            ],
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "669c1f87-63ac-40c3-8fc2-fcc72e690e68"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA300",
      "persona": "Service Accounts",
      "displayName": "CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA for service accounts.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "CA-ServiceAccounts"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "77c1ed37-10d0-4ef1-93dc-198e70abb166"
            ],
            "excludeGroups": [
              "cfa1f128-ec48-4ee1-9ea9-1c28fdb57722",
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "70899f87-a5ba-4145-8bd5-2230db5dbbff",
              "349156c1-2fb1-4ffa-9cd3-5c4418e24e4c",
              "7452a2db-063a-4048-84b0-ff691fa2900e",
              "68ce874b-21a9-4ca9-b447-f09a037be53a",
              "8e75af29-5176-4372-a718-724b8a4620dc"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA301",
      "persona": "Service Accounts",
      "displayName": "CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations",
      "sourceFile": "Config/ConditionalAccess/CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block service-account sign-ins from untrusted locations.",
      "prerequisites": [
        "Security Defaults disabled",
        "ALLOWED COUNTRIES - SERVICE ACCOUNTS named location configured"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude",
        "ALLOWED COUNTRIES - SERVICE ACCOUNTS",
        "CA-ServiceAccounts"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeGroups": [
              "77c1ed37-10d0-4ef1-93dc-198e70abb166"
            ],
            "excludeGroups": [
              "813e2655-e8b9-4255-91f5-7761ee2824bb"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ],
            "excludeLocations": [
              "1cc7e30b-f894-43a2-9da6-30aa7c085dda"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA400",
      "persona": "Guests",
      "displayName": "CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA",
      "sourceFile": "Config/ConditionalAccess/CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Require MFA for guests and external users.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "349156c1-2fb1-4ffa-9cd3-5c4418e24e4c"
            ],
            "includeGuestsOrExternalUsers": {
              "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
              "externalTenants": {
                "membershipKind": "all"
              }
            }
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "mfa"
          ]
        }
      }
    },
    {
      "id": "CA401",
      "persona": "Guests",
      "displayName": "CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess",
      "sourceFile": "Config/ConditionalAccess/CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block guests from non-approved applications.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ],
            "excludeApplications": [
              "2793995e-0a7d-40d7-bd35-6968ba142197",
              "Office365"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "dd82b6e5-6500-4616-93ec-c2558ba20813"
            ],
            "includeGuestsOrExternalUsers": {
              "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser",
              "externalTenants": {
                "membershipKind": "all"
              }
            }
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA402",
      "persona": "Guests",
      "displayName": "CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency",
      "sourceFile": "Config/ConditionalAccess/CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Limit guest session lifetime with sign-in frequency.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "0e4ab0ed-e589-46ad-80a2-f913b6b6b0ed"
            ],
            "includeGuestsOrExternalUsers": {
              "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
              "externalTenants": {
                "membershipKind": "all"
              }
            }
          }
        },
        "sessionControls": {
          "signInFrequency": {
            "value": 12,
            "type": "hours",
            "authenticationType": "primaryAndSecondaryAuthentication",
            "frequencyInterval": "timeBased",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA403",
      "persona": "Guests",
      "displayName": "CA403-GuestUsers-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
      "sourceFile": "Config/ConditionalAccess/CA403-GuestUsers-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
      "state": "enabled",
      "risk": "medium",
      "summary": "Prevent persistent browser sessions for guests.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA403-GuestUsers-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "ffba4a95-5986-4d87-804a-1f354533a930"
            ],
            "includeGuestsOrExternalUsers": {
              "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
              "externalTenants": {
                "membershipKind": "all"
              }
            }
          }
        },
        "sessionControls": {
          "persistentBrowser": {
            "mode": "never",
            "isEnabled": true
          }
        }
      }
    },
    {
      "id": "CA404",
      "persona": "Guests",
      "displayName": "CA404-GuestUsers-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK",
      "sourceFile": "Config/ConditionalAccess/CA404-GuestUsers-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block selected applications for guests.",
      "prerequisites": [
        "Security Defaults disabled"
      ],
      "requiredObjects": [
        "CA-BreakGlassAccounts-Exclude"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA404-GuestUsers-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "browser",
            "mobileAppsAndDesktopClients"
          ],
          "applications": {
            "includeApplications": [
              "MicrosoftAdminPortals"
            ]
          },
          "users": {
            "excludeGroups": [
              "2802b872-ccfb-4b29-a9a9-459808dfb11b",
              "86e8b29d-f7f2-4962-8a2d-65b8f0e5602f"
            ],
            "includeGuestsOrExternalUsers": {
              "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
              "externalTenants": {
                "membershipKind": "all"
              }
            }
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA501",
      "persona": "Agents",
      "displayName": "CA501-Agents-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskAgent",
      "sourceFile": "Config/ConditionalAccess/CA501-Agents-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskAgent.json",
      "state": "enabled",
      "risk": "high",
      "summary": "Block high-risk agent identities.",
      "prerequisites": [
        "Security Defaults disabled",
        "Entra Agent Conditional Access licensing and preview support reviewed"
      ],
      "requiredObjects": [],
      "rolloutDefault": "include",
      "kind": "canonical",
      "policy": {
        "displayName": "CA501-Agents-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskAgent",
        "state": "enabled",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "agentIdRiskLevels": "high",
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "None"
            ]
          },
          "clientApplications": {
            "includeAgentIdServicePrincipals": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA502",
      "persona": "Agents",
      "displayName": "CA502-Agents-AttackSurfaceReduction-AllAgentIdentities-AllAgentResources-BLOCK",
      "sourceFile": "Config/ConditionalAccess/CA502-Agents-AttackSurfaceReduction-AllAgentIdentities-AllAgentResources-BLOCK.json",
      "state": "enabledForReportingButNotEnforced",
      "risk": "critical",
      "summary": "Block all agent identities unless explicitly approved.",
      "prerequisites": [
        "Security Defaults disabled",
        "Entra Agent Conditional Access licensing and preview support reviewed"
      ],
      "requiredObjects": [],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA502-Agents-AttackSurfaceReduction-AllAgentIdentities-AllAgentResources-BLOCK",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "AllAgentIdResources"
            ]
          },
          "users": {
            "includeUsers": [
              "None"
            ]
          },
          "clientApplications": {
            "includeAgentIdServicePrincipals": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA503",
      "persona": "Agents",
      "displayName": "CA503-Agents-BaseProtection-AllAgentUsers-RequireCompliantDevice",
      "sourceFile": "Config/ConditionalAccess/CA503-Agents-BaseProtection-AllAgentUsers-RequireCompliantDevice.json",
      "state": "enabledForReportingButNotEnforced",
      "risk": "medium",
      "summary": "Require compliant devices for agent user identities.",
      "prerequisites": [
        "Security Defaults disabled",
        "Entra Agent Conditional Access licensing and preview support reviewed"
      ],
      "requiredObjects": [],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA503-Agents-BaseProtection-AllAgentUsers-RequireCompliantDevice",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "None"
            ]
          },
          "agents": {
            "includeAgentUsers": [
              "All"
            ]
          },
          "agentContext": {
            "includeAgentContexts": [
              "agentUserSessionsInitiatedFromEndpoints"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "compliantDevice"
          ]
        }
      }
    },
    {
      "id": "CA504",
      "persona": "Agents",
      "displayName": "CA504-Agents-IdentityProtection-AllAgentUsers-AllResources-BlockRiskyAgents",
      "sourceFile": "Config/ConditionalAccess/CA504-Agents-IdentityProtection-AllAgentUsers-AllResources-BlockRiskyAgents.json",
      "state": "enabledForReportingButNotEnforced",
      "risk": "high",
      "summary": "Block risky autonomous agent user identities.",
      "prerequisites": [
        "Security Defaults disabled",
        "Entra Agent Conditional Access licensing and preview support reviewed"
      ],
      "requiredObjects": [],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA504-Agents-IdentityProtection-AllAgentUsers-AllResources-BlockRiskyAgents",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "agentIdRiskLevels": "medium,high",
          "applications": {
            "includeApplications": [
              "All"
            ]
          },
          "users": {
            "includeUsers": [
              "None"
            ]
          },
          "agents": {
            "includeAgentUsers": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    },
    {
      "id": "CA505",
      "persona": "Agents",
      "displayName": "CA505-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-RequireCompliantNetWork",
      "sourceFile": "Config/ConditionalAccess/CA505-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-RequireCompliantNetWork.json",
      "state": "enabledForReportingButNotEnforced",
      "risk": "high",
      "summary": "Block agent user sessions outside compliant Global Secure Access network locations.",
      "prerequisites": [
        "Security Defaults disabled",
        "All Compliant Network locations named location configured",
        "Entra Agent Conditional Access licensing and preview support reviewed"
      ],
      "requiredObjects": [
        "All Compliant Network locations"
      ],
      "rolloutDefault": "monitor",
      "kind": "canonical",
      "policy": {
        "displayName": "CA505-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-RequireCompliantNetWork",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
          "clientAppTypes": [
            "all"
          ],
          "applications": {
            "includeApplications": [
              "AllAgentIdResources"
            ]
          },
          "users": {
            "includeUsers": [
              "None"
            ]
          },
          "locations": {
            "includeLocations": [
              "All"
            ],
            "excludeLocations": [
              "3d46dbda-8382-466a-856d-eb00cbc6b910"
            ]
          },
          "agents": {
            "includeAgentUsers": [
              "All"
            ]
          }
        },
        "grantControls": {
          "operator": "OR",
          "builtInControls": [
            "block"
          ]
        }
      }
    }
  ],
  "groups": [
    "APP_Microsoft365_E5",
    "CA-BreakGlassAccounts-Exclude",
    "CA-ServiceAccounts",
    "CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist - Exclude",
    "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication - Exclude",
    "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA - Exclude",
    "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows - Exclude",
    "CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-RequireAppProtection - Exclude",
    "CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-RequireAppProtection - Exclude",
    "CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions - Exclude",
    "CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection - Exclude",
    "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA - Exclude",
    "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency - Exclude",
    "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation - Exclude",
    "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA - Exclude",
    "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser - Exclude",
    "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices - Exclude",
    "CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA - Exclude",
    "CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms - Exclude",
    "CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ - Exclude",
    "CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK - Exclude",
    "CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant - Exclude",
    "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation - Exclude",
    "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn - Exclude",
    "CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations - Exclude",
    "CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess - Exclude",
    "CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency - Exclude",
    "CA403-Guests-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA404-Guests-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK - Exclude"
  ],
  "namedLocations": [
    "ALLOWED COUNTRIES - SERVICE ACCOUNTS",
    "ALLOWED COUNTRIES",
    "All Compliant Network locations"
  ],
  "migrationTableAware": true
};
