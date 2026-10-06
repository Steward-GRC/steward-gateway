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
sessions) are refused with `IMPERSONATION_DENIED`.

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
- audit AuditService: QueryAuditLog, ExportAuditSegment, VerifyAuditChain
- ai AiService: SearchAndAnswer, AuthoringAssist, SubmitAIJob, GetAIJob, GetProviderStatus, GetAIEnabled, SetAIEnabled, GetAIConfig, SetProviderConfig, SetProviderCredential, TestProvider, AcceptDataNotice, GetTopQuestions, GetPolicySummary, SetAIRetrievalConfig, SetUserAiQueryLimit, GetRelatedPolicies
- identity IdentityAdminService: EnableUser, DisableUser, PreviewUserDeletion, DeleteUser, PreviewAccountMerge, MergeAccounts, GrantRole, RevokeRole, AddUserToGroup, RemoveUserFromGroup, GrantGroupManager, RevokeGroupManager, SetUserPolicyOverride, RequestStepUpOtp, TransferRoot, RevokeUserSessions, ListUserSessions, BreakGlassReveal, ActiveBreakGlass, CreateLocalUser, ResetUserPassword, UpdateUserProfile, CompleteOnboarding, UpdateMyProfile, AdminListUserFactors, AdminRemoveUserFactor, AdminRenameUserFactor
- identity IdentityReadService: GetUser, GetUserByEmail, JitProvisionByEmail, ListUsersInGroup, GetGroup, ListUsersByEmail, ListAllUsers, ListUserIdpGroups, RevokeMySessions, GetSetupState, BootstrapRoot, GetAuthConfig, RequestPasswordReset, ResetPasswordWithCode, RequestLoginOtp, VerifyLoginOtp, MarkEmailVerified, EnrollTotpBegin, EnrollTotpConfirm, VerifyTotp, SendEmailOtp, VerifyEmailOtp, ListUserFactors, RemoveFactor, WebauthnRegisterBegin, WebauthnRegisterFinish, WebauthnAssertBegin, WebauthnAssertFinish, ListWebauthnCredentials, RemoveWebauthnCredential, RenameMFAMethod, Discover, CheckBreakGlassEligibility
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
- core PolicyService: CreatePolicy, GetPolicy, ListPolicies, GetPolicyVersion, ListPolicyVersions, SaveDraft, PublishDraft, DiscardDraft, DeletePolicy, RetirePolicy, SetPolicyOwner, ListPoliciesByOwner, ReassignUserPolicies, MovePolicy, DiffVersions, GetEffectiveTemplate, SetPolicyTemplate, SetPolicySensitivity, RenamePolicy, SetAck, ReindexPolicy, ReindexPolicyVersion
- delivery DeliveryService: GetRenderedContent, GetDiff, RequestPDFExport, GetPDFDownloadLink, CreateMagicLink, RevokeMagicLink
- reporting IntakeService: SubmitAnonymousReport, CheckReport, ReplyToReport, SubmitNamedReport, ListMyReports, GetMyReport, ReplyToMyReport
- reporting CaseService: ListCases, GetCase, GetAttachment, PostMessage, AddNote, AssignCase, SetCaseStatus, SetDiscoveryDate, RecordRiskAssessment, AddNotice, UpdateNotice, CloseCase
- every service: `grpc.health.v1.Health/Check` (readiness and diagnostics)
