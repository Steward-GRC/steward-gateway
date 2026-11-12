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
| `GET /collab/ws/{draftID}` | session cookie, origin allow-list, collab's own token | the co-editing websocket, relayed to collab; an appendix's room is `appendix:<id>`, and the path reaches collab with the colon escaped (`appendix%3A<id>`), as collab names it |
| `POST /documents/extract`, `POST /documents/validate-url` | session and CSRF | text from an uploaded file; whether a URL can be read (SSRF-guarded) |
| `POST /api/assets`, `GET /api/assets/{id}` | session; the GET skips CSRF for `<img src>` | editor images and files through core: any kind the admin setting allows, at most 25 MiB (core caps images at 10 MiB and text at 5 MiB); an image is served inline, any other file only as a download (`Content-Disposition: attachment`, `nosniff`) |
| `GET /api/admin/assets[?unlinked=true]`, `DELETE /api/admin/assets/{id}` | session and CSRF, site admin only | the stored editor files with where each is used, and delete one at once even when a document links to it; the answer lists the documents it was removed from (core writes the audit entry; reporting attachments never appear) |
| `/auth/*`, `/setup/*`, `/maintenance`, `/notify/*` | see [auth.md](auth.md) | sign-in, first-run setup, maintenance state, notification links |
| `GET /livez`, `GET /readyz` | none | probes ([runbook.md](runbook.md)) |

**Public operations** run without a session even for a signed-in user, so nothing on them
identifies the caller: the queries `globalSettings` and `__typename`, and the anonymous
reporting mutations `submitAnonymousReport`, `checkReport` and `replyToReport`. The last two are
throttled per hash of the case code and overall, failing closed.

**Act-as:** while a site admin acts as another user, every call is made as that user with the
admin as the impersonator, and high-risk mutations (passwords, factors, roles, deletions,
sessions, audit shreds and legal holds) are refused with `IMPERSONATION_DENIED`.
`startImpersonation` and `impersonationStatus` name the acting admin (`actorUserId`, `actorName`)
from the admin's session record, so the banner can say whose account the actions are audited under.

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
`auditLog` also takes `actions` (several action codes), `subjectType` (the kind before the colon in a
subject, such as `policy`) and `actorGroupId` (records made by a member of that group). They combine
with each other and with the existing arguments. The gateway reads the group's members from
identity and sends their ids, because audit calls no other service; a group with no members returns
no records, and a failed lookup fails the query rather than returning an unfiltered page. A group
manager may name only a group they manage in `actorGroupId`; any other group is refused with
`PermissionDenied`.
`auditActions` lists the distinct action codes the log holds, sorted by code, each as
`{ code, label }`, so a client can fill the `actions` filter. The label is made from the code by the
gateway (`policy.break_glass_read` becomes `Policy break glass read`). It has the same access as
`auditLog`.
`auditSegment` (the raw export) needs `audit.read`, because record ids span every group.

**Policy history:** `policyHistory(policyId, pageSize, pageToken)` returns one policy's whole
timeline, newest first, in the `AuditQueryPage` shape of `auditLog`. Core files a policy's
creation and a discarded draft under `policy:<id>`, and its draft saves, publishes and status
changes under `policy_version:<id>`; workflow files every approval event (submission, signals,
decisions, withdrawal) under `policy_version:<id>`. Audit matches one exact subject a query, so the
gateway asks for `policy:<id>` and for each version it may show, and merges the answers. It needs
no `audit.read`: it is open to anyone who can read the policy, and a caller who cannot gets
`NotFound` with audit never asked. A draft, a version in review or a rejected one is shown only to
an editor or the holder of a pending approval seat on it; for anyone else its records are left
out. Each record carries `versionNumber` (null for a policy-level record). `pageSize` is 1 to 200
(anything else means 50) and `pageToken` is the previous page's `nextPageToken`. A draft that was
discarded no longer exists in core, so only its `policy.draft_discarded` record (filed under the
policy) is shown, not its earlier saves. The gateway reads at most 5000 records for one policy.

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
`renderedContent`, `requestPDFExport`, `createMagicLink`, `policyVersionSummary` and
`workflowStatus` (a version's approval run: its approvers, decisions and comments). The decision
is taken on each version the field draws from (both sides of a diff), and the most restrictive one
wins. No backend is asked for content the caller may not read.

- **Deny:** an unknown version, a draft for anyone but an editor of the policy, or a denied read is
  `NotFound` (`policyVersionSummary` returns no summary). The holder of a pending approval seat on
  a draft gets the full review of that draft until they decide: `policyVersion`, `workflowStatus`,
  `diffVersions` and `policyDiff` (against the published version), `renderedContent`,
  `requestPDFExport` and `policyVersionSummary`. The seat covers only the version it sits on, and
  the policy's read decision still applies, so a seat is not clearance for a sensitive policy. For
  the same seat holder, `policy`, `policyByNumber` and `policies` keep `currentDraftVersionId` (and
  list a policy that has nothing published yet). `createMagicLink` keeps drafts for editors.
- **Obfuscate:** `policyVersion(s)` return scrambled content; `diffVersions` and `policyDiff` keep
  the sections but drop the word diff (`diffVersions` also scrambles the titles); `renderedContent`,
  `requestPDFExport` and `createMagicLink` are `NotFound`, because delivery serves the real
  text; `policyVersionSummary` returns no summary; and `workflowStatus` returns the run without the
  decision comments (the approvers' names, states and decision times stay, as the policy's
  metadata does).
- **Allow:** the real content. A read that only a break-glass grant allows is recorded first (see
  below), once per version.

`pdfDownloadLink` takes only a job id. Delivery serves the link only to the user who requested the
job, read from the signed-in user the gateway passes on every call; anyone else gets `NotFound`, the
same as for an unknown job.

## Recording a sensitive print or export

A print or export of a SENSITIVE policy is written to the audit log (tier `audit`, action
`policy.exported`, subject `policy:<id>`). The entry carries the policy id, the version id, the
kind (`print` or `pdf`), `include_history` and the time, never the content. The actor is the real
user: during act-as it is the admin, and `acting_as` names the user they act as.

- `requestPDFExport` records a sensitive PDF itself before the render job starts, so a client
  cannot skip it. If the entry cannot be written, no job starts.
- A browser print has no server call, so the web calls `recordPolicyExport(policyId, kind,
  includeHistory)`. It returns `true` when an entry was written and `false` when nothing was owed:
  the policy is not sensitive, or the caller sees it obfuscated. A caller who cannot read the
  policy gets `NotFound`. An unwritable entry is an error, not a quiet `false`.
- A standard policy is never recorded. steward-audit stores any non-empty action name, so no audit
  change was needed.

## Changes since the approver last reviewed

`versionChangesSinceReview(policyVersionId)` returns the sections of a version that changed since
the caller last reviewed it, and `markVersionReviewed(policyVersionId)` moves the caller's snapshot
to the version as it is now. Core keeps one snapshot per approver and version and lists every
section; the gateway returns only the changed ones (an empty list when nothing changed, and on the
first read, which takes the snapshot). Both fields apply the version read decision first (a denied
read is `NotFound`; an obfuscated reader gets the sections without word diffs), then require that
the caller is seated on the version's approval run, in any stage and in any state, read from
workflow's `GetStatus`. The author, anyone else, and a version with no run get `PermissionDenied`
and core is never asked. The user id core receives is always the signed-in user's.

The snapshot also moves when the approver acts, so nothing they have just dealt with shows as
changed. After `signalWorkflow` with approve, reject or request_changes succeeds, and for each item
`bulkDecide` decided, the gateway marks that version reviewed for the caller. After
`addReviewThread`, `replyReviewThread`, `setReviewThreadResolved` (resolve and reopen),
`counterReviewSuggestion` and `closeReviewSuggestion` by a caller who holds a seat on the version's
run, it does the same; the author side holds no seat and moves nobody. Sending comments
(request_changes) changes no status and leaves the seat open. A failed mark is logged as a warning
(version id, user id and status code only) and never fails the act, because the vote or comment
already happened.

## Inline review threads

`reviewThreads(policyVersionId)`, `addReviewThread`, `replyReviewThread`, `setReviewThreadResolved`
and `deleteReviewThread` keep a discussion tied to a quoted piece of a version's text. Core stores the
threads; the gateway decides the rest. Each call applies the version read decision first (a denied
read is `NotFound`), then reads the seats on the version's run from workflow's `GetStatus`:

- **Author side:** whoever may edit the policy and holds no seat. Core is told `AUTHOR`. The author
  lists every thread and starts one for a single named approver, who must hold a seat
  (`InvalidArgument` otherwise).
- **Reviewer side:** anyone with a seat, a site admin on the approvers included. Core is told
  `REVIEWER`, and the thread is always with the reviewer. A reviewer lists only their own threads
  and core refuses them on another approver's thread.
- Anyone else is `PermissionDenied` on a write and gets an empty list; core is never asked.
- An obfuscated reader gets every message without its body. Message authors are named from
  identity. Blank text and an occurrence below 1 are `InvalidArgument`.
- An obfuscated reader also gets no suggested text (see below).
- Replying to, resolving and deleting a thread name only the thread, so the gateway reads it from
  core (`GetReviewThread`) first to find its version; an unknown thread is `NotFound`.

### Suggestions

A thread may carry a `suggestion`: replacement text for its quote. `addReviewThread` takes
`suggestedText`; blank text, or text equal to the quote, is a plain comment and `suggestion` is null.
Otherwise the proposal is round 1 and the turn is the other side's. `counterReviewSuggestion(threadId,
text)` adds a round on the caller's turn and flips the turn; `closeReviewSuggestion(threadId, outcome,
reason)` ends it with one outcome (`CHANGED`, `REMOVED`, `AGREED`, `NOT_AGREED`, `WITHDRAWN`) and
resolves the thread. The text current at the close is kept as `closedText`; the client applies it to
the document, the gateway never edits content.

- Both mutations run the same pre-checks as the other thread calls: the thread is read from core
  to find its version, then the version read decision, the caller's side and seat, then the core
  call. Someone who takes no part is `PermissionDenied` and core is never asked. An outcome that is
  not one of the five is `InvalidArgument` before core is asked.
- Core enforces the rules and the gateway relays its refusals: `InvalidArgument` for a blank counter
  or a `NOT_AGREED` with no reason; `FailedPrecondition` for a counter out of turn, a thread with no
  suggestion, a suggestion that has ended, an outcome that is not the caller's to choose now, or
  a round that changed since the caller read it; `PermissionDenied` for a reviewer who is not the
  thread's approver; `NotFound` for an unknown thread.
- An obfuscated reader gets `text`, each round's `text` and `closedText` empty, like a message body;
  the rounds, who acted, the turn, the outcome and the reason stay.
- Suggestion text is never logged, and core's audit never carries it.

## Appendix life cycle

An appendix belongs to a policy, not to one of its versions, and has a version table of its own.
`policyAppendices(policyId, includeRetired)`, `policyAppendix(id)`, `createPolicyAppendix`,
`saveAppendixDraft`, `publishAppendix`, `retireAppendix`, `restoreAppendix` and
`reorderPolicyAppendices` serve it from core's
`PolicyAppendixService`. Core returns the published row and the draft side by side and applies no
reader filtering; the gateway shapes the answer per caller. Each call applies the policy read
decision first (a denied read is `NotFound`; an obfuscating one scrambles the text), then asks
whether the caller may edit the policy:

- **Editors** (whoever may edit the policy, a site admin included) see the draft, every row in
  `versions` (oldest first, the draft last), `publishedVersions` newest first, the contributors, and
  the retired appendices when `includeRetired` is set.
- **Anyone else who may read** sees only the latest published row, only for live appendices that
  have one, and no contributors. A write is `PermissionDenied` and core is never asked. A reader
  asking for a retired or never-published appendix by id gets `NotFound`.
- The calls that name only an appendix id (`policyAppendix`, save, publish, retire, restore) read
  it from core's `GetPolicyAppendix` first to find its policy, before any write.
- Contributors come from identity: a user that is disabled or removed is `active: false`; one
  identity does not know stays listed with the id as the name.
- `createdAt` and `createdBy` are read off the first row; `retiredBy` is always null because core does
  not record it. `PolicyVersion.appendices` keeps the older `Appendix` shape, filled from the latest
  published row of each live appendix of the policy on every version.
- `reorderPolicyAppendices(policyId, orderedIds)` sets the order of the live appendices (editors
  only, decided as for `createPolicyAppendix`; a reader is `PermissionDenied` and core is never
  asked). It sends the caller as the actor and returns the live appendices in the new order, shaped
  for an editor, with the new letters. A list that misses, repeats, or adds a foreign or retired
  appendix is core's `InvalidArgument` and leaves the order as it was. It makes no draft. The older
  `reorderAppendices` (by policy version) is unchanged.
- `appendixDiff(id, contentJson)` diffs the appendix against its latest published row, section by
  section, through core's `DiffPolicyAppendix`. It diffs the open draft, or `contentJson` (what the
  author is typing, not saved) when one is passed; the text goes to core as it is and an unreadable
  one is core's `InvalidArgument`. It writes nothing and starts no draft. Only whoever may edit the
  policy (the same check as the drafts, a site admin included) may ask; anyone else is
  `PermissionDenied`, an unknown id is `NotFound`. An obfuscated reader gets the section shape
  without the word diff and with scrambled titles, as for `diffVersions`. The mock's compliance
  reader waits on the access model.
- `issueAppendixCollabToken(appendixId)` returns `{token, wsUrl, expiresAt}` for the appendix's own
  co-editing room (`appendix:<id>`), never the policy's. The checks run in order: signed in
  (`Unauthenticated`), the appendix exists (`NotFound`, from core's `GetPolicyAppendix`), the caller
  may edit the policy (`PermissionDenied`; a reader never learns whether it is retired), the
  appendix is not retired (`FailedPrecondition`, before collab is asked). Then collab's
  `IssueAppendixToken` mints it for the signed-in user; its refusals (`APPENDIX_NOT_FOUND`,
  `DRAFT_EDIT_FORBIDDEN`, `APPENDIX_RETIRED`, `POLICY_NOT_FOUND`, `EDIT_CHECK_UNAVAILABLE`,
  `ACTOR_REQUIRED`, `APPENDIX_ID_REQUIRED`) reach the caller with collab's gRPC code and message.
  Without a collab client it is `Unavailable`. The token is never logged.
- `publishAppendix` also settles the appendix's room when collab is wired: collab's `FlushDraft`
  (draft id `appendix:<id>`), then core's `PublishAppendix`, then `NotifyDraftPublished` with the
  version that went live. As for `publishDraft`, a failed flush fails closed with the same coded
  error (`COLLAB_FLUSH_UNAVAILABLE`, `COLLAB_FLUSH_REJECTED` or `COLLAB_FLUSH_FAILED`): core is not
  called and no notify is sent. A failed notify is only logged and never turns a successful publish
  into an error. With no collab client the publish is core's alone.
- Not served yet: deleting for good.

## Library links per policy version

What a policy or procedure version links to from the libraries (definitions, references, contact
blocks and related policies) is stored with the version, so it goes through approval with it, stays
as approved once published and is copied into a new draft. Core's `VersionLinkService` keeps it; the
gateway serves `relationshipTypes`, `policyVersionLinks(policyVersionId)` and the full-replace
`setVersionReferences`, `setVersionContacts`, `setVersionDefinitions` and `setVersionRelated`. The
shapes follow the mock server's schema.

- **Read.** The version is read under the same gate as any version: an unknown version, a draft the
  caller may not see and a denied read are `NotFound`. References and contacts keep the order the
  author gave, definitions are listed alphabetically (core sorts), and `related` holds the version's
  own links (`OUTGOING`) and the incoming ones from the published version of other policies, read as
  the inverse type. A related policy that is not in the caller's read model (denied, or never
  published and not theirs to edit) is left out, so a link does not give it away.
- **`editable`** is core's flag (the version holds the draft slot) AND the caller's right to edit the
  policy.
- **Write.** The read gate runs first, then the edit check: a caller who may not edit gets
  `PermissionDenied` (`NotFound` for a draft they cannot see) and core is never asked. A related
  target the caller cannot read is `NotFound`, the same as one that does not exist. Linking never
  creates a draft.
- **Core's refusals** keep their code with a fixed sentence (core's text is logged, not sent):
  `NotFound` (version, library item or policy), `FailedPrecondition` (the version is not a draft or
  in review) and `InvalidArgument` (an id named twice, an unknown relationship type, a policy related
  to itself, a repeated link). `createDefinition` and `updateDefinition` relay `AlreadyExists` for a
  taken title and `InvalidArgument` for an empty one the same way.
- **Older queries.** `relatedPolicies`, `policyReferences`, `policyContactBlocks` and
  `policyDefinitionEntries` are answered from the links of the policy's published version, else its
  draft (for those who may see the draft; anyone else, and a policy with no version, gets an empty
  list). `relatedPolicies` lists the policy's own links only. The older `setRelatedPolicies`,
  `setPolicyReferences`, `setPolicyContactBlocks` and `setPolicyDefinitionEntries` still write
  core's per-policy store and no longer show in those reads.

## Policy text search

`searchPolicies(query, documentType, first, after)` asks core's `PolicyService.SearchPolicies` for the
documents whose title, number or published text (appendices included) hold every word of the query,
as whole words ignoring case, and returns a page `{hits, nextPageToken}`. Each hit has the `policy`
(through the same read model as `policies`), a `rank` and a `snippet` of plain text with `matches`
counted in UTF-16 code units. `first` is the page size (default 20, at most 100) and `after` the
`nextPageToken` of the page before; a token the gateway did not hand out is `INVALID_ARGUMENT`, and
so is `first` under 1. A blank query finds nothing.

- A document the caller may not read never appears.
- For a caller whose content is obfuscated on a document, or who reads it only under a break-glass
  grant, the document matches on its title and number alone: a hit stays only when every word is in
  the title and number, it carries the title-only rank, and it has no snippet. Search cannot reveal
  hidden text one guess at a time, and a break-glass read is never made through search.
- Core pages the ranked hits and the gateway filters after it, so the token is core's offset of the
  first hit not yet returned and a page can end in the middle of a core page. A page can be shorter
  than `first` and still carry a token when the caller cannot read many of the hits that follow
  (the gateway reads at most five core pages per request).
- Neither the query nor any document text is logged, only the query's length.

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
- obligations NotifPrefService: UpsertNotifPref, GetNotifPref, ListNotifTypes, GetNotificationSettings, SetCategoryCadence, SetTypeCadence, SetDigestWindow, GetQuietHours, SetQuietHours
- obligations WelcomeService: ResendWelcome
- obligations ReportingService: GetCompletionReport, GetAckRoster, GetAckActivity, ExportAcks
- audit AuditService: QueryAuditLog, ExportAuditSegment, VerifyAuditChain, ShredSubject, CreateLegalHold, ListLegalHolds, ReleaseLegalHold
- ai AiService: SearchAndAnswer, AuthoringAssist, SubmitAIJob, GetAIJob, GetProviderStatus, GetAIEnabled, SetAIEnabled, GetAIConfig, SetProviderConfig, SetProviderCredential, TestProvider, AcceptDataNotice, SetMonthlyLimit, GetTopQuestions, GetPolicySummary, SetAIRetrievalConfig, SetUserAiQueryLimit, GetRelatedPolicies
- identity IdentityAdminService: EnableUser, DisableUser, PreviewUserDeletion, DeleteUser, PreviewAccountMerge, MergeAccounts, GrantRole, RevokeRole, CreateGroup, AddUserToGroup, RemoveUserFromGroup, GrantGroupManager, RevokeGroupManager, SetUserPolicyOverride, RequestStepUpOtp, GrantRoot, RevokeRoot, RequestHardReset, ApproveHardReset, CancelHardReset, ListHardResetRequests, RevokeUserSessions, ListUserSessions, BreakGlassReveal, ActiveBreakGlass, CreateLocalUser, ResetUserPassword, UpdateUserProfile, CompleteOnboarding, UpdateMyProfile, AdminListUserFactors, AdminRemoveUserFactor, AdminRenameUserFactor
- identity IdentityReadService: GetUser, GetUserByEmail, JitProvisionByEmail, ListUsersInGroup, GetGroup, ListGroups, ListUsersByEmail, ListAllUsers, ListUserIdpGroups, RevokeMySessions, ListMySessions, RevokeMySession, GetSetupState, BootstrapRoot, GetAuthConfig, RequestPasswordReset, ResetPasswordWithCode, RequestLoginOtp, VerifyLoginOtp, MarkEmailVerified, EnrollTotpBegin, EnrollTotpConfirm, VerifyTotp, SendEmailOtp, VerifyEmailOtp, ListUserFactors, RemoveFactor, WebauthnRegisterBegin, WebauthnRegisterFinish, WebauthnAssertBegin, WebauthnAssertFinish, ListWebauthnCredentials, RemoveWebauthnCredential, RenameMFAMethod, Discover, CheckBreakGlassEligibility
- identity IdentitySSOAdminService: AddOrganization, ListOrganizations, GetOrganization, UpdateIdPConnection, ChangeOrgProtocol, DeleteOrganization, StartDomainVerification, VerifyDomain, RecordIdPTestResult, ActivateOrganization, DisableOrganization, AddGroupMapping, ListGroupMappings, DeleteGroupMapping, GetSPCertificate, ListSPCertificates, ForceRotateSPCertificate, RecordBreakGlassLogin
- workflow WorkflowService: Submit, Signal, GetStatus, ListPendingTasks, ListUpcomingTasks, SwapAssignee, BulkDecide, GetAssignmentHistory, GetStageEligiblePool, ListWorkflowDefs, GetWorkflowDef, CreateWorkflowDef, UpdateWorkflowDef, ArchiveWorkflowDef, SetWorkflowVetoEnabled, ResolveWorkflow
- collab CollabTokenService: IssueToken, IssueAppendixToken
- collab CollabRoomService: FlushDraft, NotifyDraftPublished
- core TemplateService: CreateTemplate, CreateTemplateVersion, PublishTemplateVersion, GetLatestTemplateVersion, UpdateTemplateVersionSections, ListTemplateVersions, DeleteTemplateVersion, ListTemplates, RetireTemplate, DeleteTemplate, RenameTemplate
- core AssetService: UploadAsset, GetAsset, GetAssetSettings, SetAssetSettings, ListAssets, DeleteAsset
- core RelationService: ListRelatedPolicies, SetRelatedPolicies
- core DefinitionLibraryService: ListDefinitionEntries, ListPolicyDefinitionCandidates, CreateDefinitionEntry, UpdateDefinitionEntry, DeleteDefinitionEntry, SetDefinitionEntryArchived, ListPolicyDefinitionEntries, SetPolicyDefinitionEntries
- core AppendixService: ListAppendices, AddAppendix, UpdateAppendix, ReorderAppendices, DeleteAppendix
- core PolicyAppendixService: ListPolicyAppendices, GetPolicyAppendix, CreatePolicyAppendix, SaveAppendixDraft, PublishAppendix, RetireAppendix, RestoreAppendix, ReorderPolicyAppendices, DiffPolicyAppendix
- core ContactService: ListContactBlocks, CreateContactBlock, UpdateContactBlock, DeleteContactBlock, SetContactBlockArchived, ListPolicyContactBlocks, SetPolicyContactBlocks
- core SettingsService: GetGlobalSettings, SetGlobalSettings, SetEmailServiceConfig, EmailServiceConfigStatus
- core ReferenceService: ListReferences, CreateReference, UpdateReference, DeleteReference, SetReferenceArchived, ListPolicyReferences, SetPolicyReferences
- core CategoryService: CreateCategory, GetCategory, ListCategoryChildren, SetCategoryDefaults, RenameCategory, DeleteCategory, MoveCategory, ReorderCategories, SetGovernance, GetEffectiveGovernance, GetCategoryRuleset, SetCategoryRuleset
- core PolicyService: CreatePolicy, GetPolicy, GetPolicyByNumber, ListPolicies, GetPolicyVersion, ListPolicyVersions, SaveDraft, PublishDraft, DiscardDraft, DeletePolicy, RetirePolicy, RecordBreakGlassRead, SetPolicyOwner, ListPoliciesByOwner, ReassignUserPolicies, MovePolicy, PreviewMovePolicies, MovePolicies, DiffVersions, GetEffectiveTemplate, SetPolicyTemplate, SetPolicySensitivity, RenamePolicy, SetAck, ReindexPolicy, ReindexPolicyVersion
- delivery DeliveryService: GetRenderedContent, GetDiff, RequestPDFExport, GetPDFDownloadLink, CreateMagicLink, RevokeMagicLink
- reporting IntakeService: SubmitAnonymousReport, CheckReport, ReplyToReport, SubmitNamedReport, ListMyReports, GetMyReport, ReplyToMyReport
- reporting CaseService: ListCases, GetCase, GetAttachment, PostMessage, AddNote, AssignCase, SetCaseStatus, SetDiscoveryDate, RecordRiskAssessment, AddNotice, UpdateNotice, CloseCase
- every service: `grpc.health.v1.Health/Check` (readiness and diagnostics)
