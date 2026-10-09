# API

The gateway is the only service the web apps call. Its contract is the GraphQL schema in
`graphql/` (one file per backend area); the browser routes are below. Every GraphQL error carries
`code`, `codeNum`, `domain`, `kind` (`business` or `reach`), `requestId` and `traceId` in its
`extensions` ([error-codes.md](error-codes.md)).

## HTTP routes

| Route | Auth | What it does |
|---|---|---|
| `POST /query` | session and CSRF, except the public operations | GraphQL queries and mutations |
| `GET /query` | session cookie plus `csrfToken` in `connection_init` | GraphQL subscriptions over websocket |
| `GET /collab/ws/{draftID}` | session cookie, origin allow-list, collab's own token | the co-editing websocket, relayed to collab |
| `POST /documents/extract`, `POST /documents/validate-url` | session and CSRF | text from an uploaded file; whether a URL can be read (SSRF-guarded) |
| `POST /api/assets`, `GET /api/assets/{id}` | session; the GET skips CSRF for `<img src>` | editor images through core |
| `/auth/*`, `/setup/*`, `/maintenance`, `/notify/*` | see [auth.md](auth.md) | sign-in, first-run setup, maintenance state, notification links |
| `GET /livez`, `GET /readyz` | none | probes ([runbook.md](runbook.md)) |

**Public operations** run without a session even for a signed-in user, so nothing on them
identifies the caller: the queries `globalSettings` and `__typename`, and the anonymous
reporting mutations `submitAnonymousReport`, `checkReport` and `replyToReport`. The last two are
throttled per hash of the case code and overall, failing closed.

**Act-as:** while a site admin acts as another user, every call is made as that user with the
admin as the impersonator, and high-risk mutations (passwords, factors, roles, deletions,
sessions, audit shreds and legal holds) are refused with `IMPERSONATION_DENIED`.

**Platform groups vs categories:** `platformGroups` and `createPlatformGroup` (site-admin only)
list and create identity's platform groups, the groups that memberships (`addUserToGroup`),
group managers, SSO group mappings and reporting's `REPORTING_OFFICER_GROUPS` name by id. They
are not core's categories, which the admin app's "Groups" pages manage through `createCategory`.

**Group managers:** `myManagedGroups` returns the platform groups the signed-in caller is a local
group manager of (id, name, parent), sorted by name; any signed-in caller may run it and it only
reads their own grants. `managedGroupMembers`, `addUserToGroup` and `removeUserFromGroup` are open
to a site admin or to a manager of that group, and a manager cannot remove an IdP-synced
membership.

**Audit reads:** `auditLog` and `verifyAuditChain` are open to a caller with `audit.read`, who
reads every group, and to a group manager: the gateway reads the caller's managed group ids from
identity and sends them as `managed_groups`, and audit lets a manager query only a group it
manages (named in `groupId`) and verify. Anyone else is refused with `PermissionDenied`.
`auditSegment` (the raw export) needs `audit.read`, because record ids span every group.

**Shred and legal holds:** `shredAuditSubject` (crypto-shred a subject: audit erases its key and
clears its personal data from activity records), `createAuditLegalHold`, `releaseAuditLegalHold`
and the query `auditLegalHolds` need `compliance.manage` (`compliance-admin` and `site-admin`
today). The gateway checks it and sends the caller as the requester; audit checks it again and
records every call, including the list. The three mutations are refused during act-as.

**OIDC client secrets:** `addOrganization`, `changeOrgProtocol` and `updateIdPConnection` take
an OIDC connection's client secret as `clientSecret`, write-only: the gateway passes it to
identity, which keeps it in a Kubernetes Secret, never in its database, and no field returns it.
`secretRef` instead names a key an operator created in that Secret. Send one or the other, never
both. `Organization.secretReentryRequired` says identity cleared a stored reference that wasn't a
key and an admin must enter the secret again. The first-run `/setup/bootstrap` SSO block takes
the same `clientSecret`.

**Live updates:** `liveEvents` streams every audit event, so it needs `audit.read`; anyone else
is refused with `PermissionDenied`.

## Diagnostics

`diagnostics` takes no arguments and needs a signed-in user. It returns the caller's own id,
username and roles (during act-as, the admin as `actor` and the target as `actingAs`), the
gateway's and every service's version and commit (read from the `steward-version` and
`steward-commit` headers on each service's standard gRPC health check), the release and appliance
versions, and Kratos, Polis, Postgres, Valkey, RabbitMQ, OPA and Kubernetes versions. Probes run in
parallel, one second each inside two seconds, and are cached for a minute (ten seconds when one
failed). An unreadable entry is `unavailable` (`unknown` for a service without the headers) and
never fails the read. It never returns tokens, cookies, request headers, secrets, policy content,
addresses or probe errors.

## Reading version content

Every field that returns a policy version's content applies the same read decision as
`policyVersion`: `policyVersion`, `policyVersions`, `diffVersions`, `policyDiff`,
`renderedContent`, `requestPDFExport`, `createMagicLink` and `policyVersionSummary`. The decision
is taken on each version the field draws from (both sides of a diff), and the most restrictive one
wins. No backend is asked for content the caller may not read.

- **Deny:** an unknown version, a draft for anyone but an editor of the policy, or a denied read is
  `NotFound` (`policyVersionSummary` returns no summary).
- **Obfuscate:** `policyVersion(s)` return scrambled content; `diffVersions` and `policyDiff` keep
  the sections but drop the word diff (`diffVersions` also scrambles the titles); `renderedContent`,
  `requestPDFExport` and `createMagicLink` are `NotFound`, because delivery serves the real
  text; and `policyVersionSummary` returns no summary.
- **Allow:** the real content. A read that only a break-glass grant allows is recorded first (see
  below), once per version.

`pdfDownloadLink` takes only a job id. Delivery serves the link only to the user who requested the
job, read from the signed-in user the gateway passes on every call; anyone else gets `NotFound`, the
same as for an unknown job.

## Break-glass reads

A site admin who sees a document obfuscated can ask for a time-boxed reveal of that one document
(`breakGlassReveal`, with a reason). Identity grants it and sets the expiry. While the grant is
active, the content fields above serve that document's real content to that admin and no other
document's.

Each such read is recorded first: when only the grant allows it, the gateway calls core's
`RecordBreakGlassRead` (the policy and, for one version, the version) before returning anything.
Core audits it, naming the real admin and the user acted as during act-as, and obligations alerts
the owner and the compliance admins. If the call fails, the gateway returns its error and serves
nothing. A read the access rules already allow is not a break-glass read and isn't recorded.

## Calling other services

The gateway calls every Steward service over gRPC, never importing their Go modules: each proto is
pinned at a commit on its owner's main in `proto-refs.env` and `scripts/proto-generate.sh` writes
the clients to `gen/go/thirdparty`. Every call carries the gateway's projected service-account
token (audience `steward`, re-read on every call) and the signed-in user through go-grpc-actor;
the three anonymous reporting calls carry no user. The methods it calls:

- obligations AckService: RecordAck, RecordView, GetAckStatus
- obligations ObligationService: GetMyObligations, GetObligatedAudienceCount, MyAckSummary
- obligations NotifPrefService: UpsertNotifPref, GetNotifPref, ListNotifTypes, GetNotificationSettings, SetCategoryCadence, SetTypeCadence, SetDigestWindow
- obligations WelcomeService: ResendWelcome
- obligations ReportingService: GetCompletionReport, GetAckRoster, GetAckActivity, ExportAcks
- audit AuditService: QueryAuditLog, ExportAuditSegment, VerifyAuditChain, ShredSubject, CreateLegalHold, ListLegalHolds, ReleaseLegalHold
- ai AiService: SearchAndAnswer, AuthoringAssist, SubmitAIJob, GetAIJob, GetProviderStatus, GetAIEnabled, SetAIEnabled, GetAIConfig, SetProviderConfig, SetProviderCredential, TestProvider, AcceptDataNotice, GetTopQuestions, GetPolicySummary, SetAIRetrievalConfig, SetUserAiQueryLimit, GetRelatedPolicies
- identity IdentityAdminService: EnableUser, DisableUser, PreviewUserDeletion, DeleteUser, PreviewAccountMerge, MergeAccounts, GrantRole, RevokeRole, CreateGroup, AddUserToGroup, RemoveUserFromGroup, GrantGroupManager, RevokeGroupManager, SetUserPolicyOverride, RequestStepUpOtp, TransferRoot, RevokeUserSessions, ListUserSessions, BreakGlassReveal, ActiveBreakGlass, CreateLocalUser, ResetUserPassword, UpdateUserProfile, CompleteOnboarding, UpdateMyProfile, AdminListUserFactors, AdminRemoveUserFactor, AdminRenameUserFactor
- identity IdentityReadService: GetUser, GetUserByEmail, JitProvisionByEmail, ListUsersInGroup, GetGroup, ListGroups, ListUsersByEmail, ListAllUsers, ListUserIdpGroups, RevokeMySessions, GetSetupState, BootstrapRoot, GetAuthConfig, RequestPasswordReset, ResetPasswordWithCode, RequestLoginOtp, VerifyLoginOtp, MarkEmailVerified, EnrollTotpBegin, EnrollTotpConfirm, VerifyTotp, SendEmailOtp, VerifyEmailOtp, ListUserFactors, RemoveFactor, WebauthnRegisterBegin, WebauthnRegisterFinish, WebauthnAssertBegin, WebauthnAssertFinish, ListWebauthnCredentials, RemoveWebauthnCredential, RenameMFAMethod, Discover, CheckBreakGlassEligibility
- identity IdentitySSOAdminService: AddOrganization, ListOrganizations, GetOrganization, UpdateIdPConnection, ChangeOrgProtocol, DeleteOrganization, StartDomainVerification, VerifyDomain, RecordIdPTestResult, ActivateOrganization, DisableOrganization, AddGroupMapping, ListGroupMappings, DeleteGroupMapping, GetSPCertificate, ListSPCertificates, ForceRotateSPCertificate, RecordBreakGlassLogin
- workflow WorkflowService: Submit, Signal, GetStatus, ListPendingTasks, ListUpcomingTasks, SwapAssignee, BulkDecide, GetAssignmentHistory, GetStageEligiblePool, ListWorkflowDefs, GetWorkflowDef, CreateWorkflowDef, UpdateWorkflowDef, ArchiveWorkflowDef, ResolveWorkflow
- collab CollabTokenService: IssueToken
- collab CollabRoomService: FlushDraft, NotifyDraftPublished
- core TemplateService: CreateTemplate, CreateTemplateVersion, PublishTemplateVersion, GetLatestTemplateVersion, UpdateTemplateVersionSections, ListTemplateVersions, DeleteTemplateVersion, ListTemplates, RetireTemplate, DeleteTemplate, RenameTemplate
- core AssetService: UploadAsset, GetAsset
- core RelationService: ListRelatedPolicies, SetRelatedPolicies
- core DefinitionLibraryService: ListDefinitionEntries, ListPolicyDefinitionCandidates, CreateDefinitionEntry, UpdateDefinitionEntry, DeleteDefinitionEntry, SetDefinitionEntryArchived, ListPolicyDefinitionEntries, SetPolicyDefinitionEntries
- core AppendixService: ListAppendices, AddAppendix, UpdateAppendix, ReorderAppendices, DeleteAppendix
- core ContactService: ListContactBlocks, CreateContactBlock, UpdateContactBlock, DeleteContactBlock, SetContactBlockArchived, ListPolicyContactBlocks, SetPolicyContactBlocks
- core SettingsService: GetGlobalSettings, SetGlobalSettings, SetEmailServiceConfig, EmailServiceConfigStatus
- core ReferenceService: ListReferences, CreateReference, UpdateReference, DeleteReference, SetReferenceArchived, ListPolicyReferences, SetPolicyReferences
- core CategoryService: CreateCategory, GetCategory, ListCategoryChildren, SetCategoryDefaults, RenameCategory, DeleteCategory, MoveCategory, SetGovernance, GetEffectiveGovernance, GetCategoryRuleset, SetCategoryRuleset
- core PolicyService: CreatePolicy, GetPolicy, GetPolicyByNumber, ListPolicies, GetPolicyVersion, ListPolicyVersions, SaveDraft, PublishDraft, DiscardDraft, DeletePolicy, RetirePolicy, RecordBreakGlassRead, SetPolicyOwner, ListPoliciesByOwner, ReassignUserPolicies, MovePolicy, DiffVersions, GetEffectiveTemplate, SetPolicyTemplate, SetPolicySensitivity, RenamePolicy, SetAck, ReindexPolicy, ReindexPolicyVersion
- delivery DeliveryService: GetRenderedContent, GetDiff, RequestPDFExport, GetPDFDownloadLink, CreateMagicLink, RevokeMagicLink
- reporting IntakeService: SubmitAnonymousReport, CheckReport, ReplyToReport, SubmitNamedReport, ListMyReports, GetMyReport, ReplyToMyReport
- reporting CaseService: ListCases, GetCase, GetAttachment, PostMessage, AddNote, AssignCase, SetCaseStatus, SetDiscoveryDate, RecordRiskAssessment, AddNotice, UpdateNotice, CloseCase
- every service: `grpc.health.v1.Health/Check` (readiness and diagnostics)
