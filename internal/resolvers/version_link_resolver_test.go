// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// The library links per policy version (#135). Each test names the mock server
// test it ports (steward-mock-server src/product/version-links.test.ts), which
// is the acceptance list. Core owns the store, the rules on what may be linked
// and the carry-over into a new draft; the fake below plays the parts of core
// the gateway leans on, so the tests pin what the gateway adds: who may read a
// version's links, who may change them (before core is asked), the old
// per-policy queries, and the code each core refusal reaches the client as.

const (
	vlPolicy        = "policy-1"
	vlPublished     = "version-2"
	vlSuperseded    = "version-10"
	vlRejected      = "version-8"
	vlDraft         = "draft-1"
	vlTargetPolicy  = "policy-7"
	vlDraftOnly     = "policy-3"
	vlDraftOnlyVer  = "draft-3"
	vlNothing       = "policy-4"
	vlHiddenPolicy  = "policy-9"
	vlLeakMarker    = "SQLSTATE 23505 uuid 0c2f9d1e"
	vlTypeRelatedTo = "RELATED_TO"
)

var vlTypes = []*corev1.RelationshipType{
	{Id: "RELATED_TO", Label: "is related to", InverseId: "RELATED_BY", InverseLabel: "is related by"},
	{Id: "RELATED_BY", Label: "is related by", InverseId: "RELATED_TO", InverseLabel: "is related to"},
	{Id: "SUPERSEDES", Label: "supersedes", InverseId: "SUPERSEDED_BY", InverseLabel: "is superseded by"},
	{Id: "SUPERSEDED_BY", Label: "is superseded by", InverseId: "SUPERSEDES", InverseLabel: "supersedes"},
}

type vlStored struct {
	refs, contacts, defs []string
	related              []*corev1.RelatedLinkInput
}

// vlCore is a small stateful stand-in for core's VersionLinkService: it keeps
// the links per version, applies the refusals core documents and counts every
// Set so a test can show core was never asked.
type vlCore struct {
	corev1.VersionLinkServiceClient
	policies *fakePolicyClient
	stored   map[string]*vlStored
	library  struct{ refs, contacts, defs map[string]string }

	// forceEditable makes core report editable whatever the status, to show the
	// gateway still ANDs the caller's own right to edit.
	forceEditable bool
	// leak is the raw text core puts in a refusal, which must never reach a client.
	leak string

	sets      int
	lastActor string
	lastReq   any
}

func newVLCore(pc *fakePolicyClient) *vlCore {
	c := &vlCore{policies: pc, stored: map[string]*vlStored{}, leak: vlLeakMarker}
	c.library.refs = map[string]string{"reference-1": "ISO 27001", "reference-2": "NIST", "reference-3": "SOC 2", "reference-4": "Code of conduct"}
	c.library.contacts = map[string]string{"contact-block-1": "Help desk", "contact-block-2": "Legal", "contact-block-3": "Finance"}
	c.library.defs = map[string]string{"definition-1": "RTO", "definition-2": "RPO", "definition-4": "Business expense"}
	c.stored[vlPublished] = &vlStored{
		refs: []string{"reference-1", "reference-4"}, contacts: []string{"contact-block-3", "contact-block-1"},
		defs: []string{"definition-4"}, related: []*corev1.RelatedLinkInput{{PolicyId: vlTargetPolicy, RelationType: vlTypeRelatedTo}},
	}
	// the draft starts as a copy of the published version, as core's SaveDraft does
	c.stored[vlDraft] = &vlStored{
		refs: slices.Clone(c.stored[vlPublished].refs), contacts: slices.Clone(c.stored[vlPublished].contacts),
		defs: slices.Clone(c.stored[vlPublished].defs), related: slices.Clone(c.stored[vlPublished].related),
	}
	return c
}

func vlType(id string) *corev1.RelationshipType {
	for _, t := range vlTypes {
		if t.GetId() == id {
			return t
		}
	}
	return nil
}

func (c *vlCore) version(id string) (*corev1.PolicyVersion, error) {
	v, ok := c.policies.versions[id]
	if !ok {
		return nil, status.Error(codes.NotFound, "version not found: "+c.leak)
	}
	return v, nil
}

func (c *vlCore) ListRelationshipTypes(context.Context, *corev1.ListRelationshipTypesRequest, ...grpc.CallOption) (*corev1.ListRelationshipTypesResponse, error) {
	return &corev1.ListRelationshipTypesResponse{Types: vlTypes}, nil
}

func (c *vlCore) links(id string) (*corev1.VersionLinks, error) {
	v, err := c.version(id)
	if err != nil {
		return nil, err
	}
	s := c.stored[id]
	if s == nil {
		s = &vlStored{}
	}
	out := &corev1.VersionLinks{
		PolicyVersionId: id,
		Editable:        v.GetStatus() == corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT || c.forceEditable,
	}
	for _, d := range s.defs {
		out.Definitions = append(out.Definitions, &corev1.DefinitionEntry{Id: d, Term: c.library.defs[d]})
	}
	sort.SliceStable(out.Definitions, func(i, j int) bool {
		return strings.ToLower(out.Definitions[i].Term) < strings.ToLower(out.Definitions[j].Term)
	})
	for _, r := range s.refs {
		out.References = append(out.References, &corev1.Reference{Id: r, Label: c.library.refs[r]})
	}
	for _, b := range s.contacts {
		out.Contacts = append(out.Contacts, &corev1.ContactBlock{Id: b, Label: c.library.contacts[b]})
	}
	for _, l := range s.related {
		t := vlType(l.GetRelationType())
		p := c.policies.policies[l.GetPolicyId()]
		out.Related = append(out.Related, &corev1.RelatedVersionLink{
			PolicyId: p.GetId(), Number: p.GetNumber(), Title: p.GetTitle(), RelationType: t.GetId(), Label: t.GetLabel(),
			Direction: corev1.RelatedDirection_RELATED_DIRECTION_OUTGOING,
		})
	}
	// the published version of every other policy that names this one reads as the inverse
	var others []string
	for pid := range c.policies.policies {
		others = append(others, pid)
	}
	sort.Strings(others)
	for _, pid := range others {
		other := c.policies.policies[pid]
		if pid == v.GetPolicyId() || other.GetCurrentPublishedVersionId() == "" {
			continue
		}
		if st := c.stored[other.GetCurrentPublishedVersionId()]; st != nil {
			for _, l := range st.related {
				if l.GetPolicyId() != v.GetPolicyId() {
					continue
				}
				inv := vlType(vlType(l.GetRelationType()).GetInverseId())
				out.Related = append(out.Related, &corev1.RelatedVersionLink{
					PolicyId: other.GetId(), Number: other.GetNumber(), Title: other.GetTitle(), RelationType: inv.GetId(),
					Label: inv.GetLabel(), Direction: corev1.RelatedDirection_RELATED_DIRECTION_INCOMING,
				})
			}
		}
	}
	return out, nil
}

func (c *vlCore) GetVersionLinks(_ context.Context, in *corev1.GetVersionLinksRequest, _ ...grpc.CallOption) (*corev1.GetVersionLinksResponse, error) {
	l, err := c.links(in.GetPolicyVersionId())
	if err != nil {
		return nil, err
	}
	return &corev1.GetVersionLinksResponse{Links: l}, nil
}

// begin is the part every Set shares: count it, find the version, refuse one
// that is no longer editable.
func (c *vlCore) begin(id, actor string, req any) (*vlStored, error) {
	c.sets++
	c.lastActor, c.lastReq = actor, req
	v, err := c.version(id)
	if err != nil {
		return nil, err
	}
	if v.GetStatus() != corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT {
		return nil, status.Error(codes.FailedPrecondition, "version "+id+" is not editable: "+c.leak)
	}
	if c.stored[id] == nil {
		c.stored[id] = &vlStored{}
	}
	return c.stored[id], nil
}

func vlCheckIDs(ids []string, library map[string]string, leak string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return status.Error(codes.InvalidArgument, "id named twice: "+id+" "+leak)
		}
		seen[id] = true
	}
	for _, id := range ids {
		if _, ok := library[id]; !ok {
			return status.Error(codes.NotFound, "item not found: "+id+" "+leak)
		}
	}
	return nil
}

func (c *vlCore) SetVersionReferences(_ context.Context, in *corev1.SetVersionReferencesRequest, _ ...grpc.CallOption) (*corev1.SetVersionReferencesResponse, error) {
	s, err := c.begin(in.GetPolicyVersionId(), in.GetActorUserId(), in)
	if err != nil {
		return nil, err
	}
	if err := vlCheckIDs(in.GetReferenceIds(), c.library.refs, c.leak); err != nil {
		return nil, err
	}
	s.refs = slices.Clone(in.GetReferenceIds())
	l, _ := c.links(in.GetPolicyVersionId())
	return &corev1.SetVersionReferencesResponse{Links: l}, nil
}

func (c *vlCore) SetVersionContactBlocks(_ context.Context, in *corev1.SetVersionContactBlocksRequest, _ ...grpc.CallOption) (*corev1.SetVersionContactBlocksResponse, error) {
	s, err := c.begin(in.GetPolicyVersionId(), in.GetActorUserId(), in)
	if err != nil {
		return nil, err
	}
	if err := vlCheckIDs(in.GetContactBlockIds(), c.library.contacts, c.leak); err != nil {
		return nil, err
	}
	s.contacts = slices.Clone(in.GetContactBlockIds())
	l, _ := c.links(in.GetPolicyVersionId())
	return &corev1.SetVersionContactBlocksResponse{Links: l}, nil
}

func (c *vlCore) SetVersionDefinitions(_ context.Context, in *corev1.SetVersionDefinitionsRequest, _ ...grpc.CallOption) (*corev1.SetVersionDefinitionsResponse, error) {
	s, err := c.begin(in.GetPolicyVersionId(), in.GetActorUserId(), in)
	if err != nil {
		return nil, err
	}
	if err := vlCheckIDs(in.GetDefinitionIds(), c.library.defs, c.leak); err != nil {
		return nil, err
	}
	s.defs = slices.Clone(in.GetDefinitionIds())
	l, _ := c.links(in.GetPolicyVersionId())
	return &corev1.SetVersionDefinitionsResponse{Links: l}, nil
}

func (c *vlCore) SetVersionRelated(_ context.Context, in *corev1.SetVersionRelatedRequest, _ ...grpc.CallOption) (*corev1.SetVersionRelatedResponse, error) {
	s, err := c.begin(in.GetPolicyVersionId(), in.GetActorUserId(), in)
	if err != nil {
		return nil, err
	}
	own := c.policies.versions[in.GetPolicyVersionId()].GetPolicyId()
	seen := map[string]bool{}
	for _, l := range in.GetLinks() {
		key := l.GetPolicyId() + "|" + l.GetRelationType()
		switch {
		case vlType(l.GetRelationType()) == nil:
			return nil, status.Error(codes.InvalidArgument, "unknown relationship type "+c.leak)
		case l.GetPolicyId() == own:
			return nil, status.Error(codes.InvalidArgument, "a policy cannot relate to itself "+c.leak)
		case seen[key]:
			return nil, status.Error(codes.InvalidArgument, "repeated link "+c.leak)
		case c.policies.policies[l.GetPolicyId()] == nil:
			return nil, status.Error(codes.NotFound, "policy not found "+c.leak)
		}
		seen[key] = true
	}
	s.related = in.GetLinks()
	l, _ := c.links(in.GetPolicyVersionId())
	return &corev1.SetVersionRelatedResponse{Links: l}, nil
}

type vlEnv struct {
	core *vlCore
	pc   *fakePolicyClient
	r    *resolvers.Resolver
}

// newVLEnv is the mock's data: policy-1 (owned by bob) is published as
// version-2 with links, has an open draft and an older superseded version;
// policy-7 was never published and has only a rejected version; policy-3 has
// only a draft; policy-4 has no version at all; policy-9 sits in a category
// the Outsiders group cannot read.
func newVLEnv(t *testing.T) *vlEnv {
	t.Helper()
	groups := newRaciReadClient(
		map[string]*corev1.Category{"g-it": {Id: "g-it", Name: "IT"}, "g-hidden": {Id: "g-hidden", Name: "Hidden"}},
		map[string][]*corev1.CategoryRule{
			"g-it":     {allowEveryoneRule()},
			"g-hidden": {denyGroupRule("Outsiders"), allowEveryoneRule()},
		})
	published := corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED
	draft := corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_DRAFT
	pc := &fakePolicyClient{
		policies: map[string]*corev1.Policy{
			vlPolicy:       {Id: vlPolicy, HomeCategoryId: "g-it", Number: "POL-EXPENSES-000002", Title: "Expenses", OwnerUserId: "bob", CurrentPublishedVersionId: vlPublished, CurrentDraftVersionId: vlDraft},
			"policy-2":     {Id: "policy-2", HomeCategoryId: "g-it", Number: "POL-TRAVEL-000001", Title: "Travel", OwnerUserId: "bob", CurrentPublishedVersionId: "version-20"},
			vlTargetPolicy: {Id: vlTargetPolicy, HomeCategoryId: "g-it", Number: "PRC-CONDUCT-000001", Title: "Gifts and Hospitality Procedure", OwnerUserId: "bob"},
			vlDraftOnly:    {Id: vlDraftOnly, HomeCategoryId: "g-it", Number: "POL-NEW-000001", Title: "New", OwnerUserId: "bob", CurrentDraftVersionId: vlDraftOnlyVer},
			vlNothing:      {Id: vlNothing, HomeCategoryId: "g-it", Number: "POL-NONE-000001", Title: "None", OwnerUserId: "bob"},
			vlHiddenPolicy: {Id: vlHiddenPolicy, HomeCategoryId: "g-hidden", Number: "POL-SECRET-000001", Title: "Secret plans", OwnerUserId: "bob", CurrentPublishedVersionId: "version-90"},
		},
		versions: map[string]*corev1.PolicyVersion{
			vlPublished:    {Id: vlPublished, PolicyId: vlPolicy, VersionNo: 2, Status: published},
			vlSuperseded:   {Id: vlSuperseded, PolicyId: vlPolicy, VersionNo: 1, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_SUPERSEDED},
			vlDraft:        {Id: vlDraft, PolicyId: vlPolicy, Status: draft},
			vlRejected:     {Id: vlRejected, PolicyId: vlTargetPolicy, Status: corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_ARCHIVED},
			vlDraftOnlyVer: {Id: vlDraftOnlyVer, PolicyId: vlDraftOnly, Status: draft},
			"version-20":   {Id: "version-20", PolicyId: "policy-2", VersionNo: 1, Status: published},
			"version-90":   {Id: "version-90", PolicyId: vlHiddenPolicy, VersionNo: 1, Status: published},
		},
	}
	core := newVLCore(pc)
	core.stored[vlDraftOnlyVer] = &vlStored{refs: []string{"reference-2"}}
	core.stored["version-20"] = &vlStored{}
	core.stored["version-90"] = &vlStored{}
	return &vlEnv{core: core, pc: pc, r: &resolvers.Resolver{
		VersionLinkClient: core, PolicyClient: pc, CategoryClient: groups, IdentityAdminClient: noGrant(), Log: log.Nop(),
	}}
}

func vlCtx(t *testing.T, user string) context.Context {
	t.Helper()
	switch user {
	case "alice":
		return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: []string{"site-admin"}, IsRootValue: true})
	case "outsider":
		return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Outsiders"}})
	}
	return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: []string{"reader"}})
}

func (e *vlEnv) links(t *testing.T, user, version string) *resolvers.PolicyVersionLinks {
	t.Helper()
	got, err := e.r.Query().PolicyVersionLinks(vlCtx(t, user), version)
	if err != nil {
		t.Fatalf("policyVersionLinks(%s) as %s: %v", version, user, err)
	}
	return got
}

func vlCode(err error) codes.Code { return status.Code(err) }

func refIDs(rs []*resolvers.Reference) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func contactIDs(cs []*resolvers.ContactBlock) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func defIDs(ds []*resolvers.DefinitionEntry) []string {
	out := []string{}
	for _, d := range ds {
		out = append(out, d.ID)
	}
	return out
}

func defTerms(ds []*resolvers.DefinitionEntry) []string {
	out := []string{}
	for _, d := range ds {
		out = append(out, d.Term)
	}
	return out
}

func relatedKeys(rs []*resolvers.RelatedLink) [][3]string {
	out := [][3]string{}
	for _, r := range rs {
		out = append(out, [3]string{r.PolicyID, r.Type, string(r.Direction)})
	}
	return out
}

func equalKeys(a, b [][3]string) bool {
	return slices.EqualFunc(a, b, func(x, y [3]string) bool { return x == y })
}

// mock: "reads the seeded links of the published version"
func TestPolicyVersionLinks_ReadsThePublishedVersion(t *testing.T) {
	e := newVLEnv(t)
	got := e.links(t, "bob", vlPublished)
	if got.PolicyVersionID != vlPublished {
		t.Fatalf("policyVersionId = %q", got.PolicyVersionID)
	}
	if !slices.Equal(refIDs(got.References), []string{"reference-1", "reference-4"}) {
		t.Fatalf("references = %v", refIDs(got.References))
	}
	if !slices.Equal(contactIDs(got.Contacts), []string{"contact-block-3", "contact-block-1"}) {
		t.Fatalf("contacts = %v", contactIDs(got.Contacts))
	}
	if !slices.Equal(defIDs(got.Definitions), []string{"definition-4"}) {
		t.Fatalf("definitions = %v", defIDs(got.Definitions))
	}
	if want := [][3]string{{vlTargetPolicy, "RELATED_TO", "OUTGOING"}}; !equalKeys(relatedKeys(got.Related), want) {
		t.Fatalf("related = %v, want %v", relatedKeys(got.Related), want)
	}
	if r := got.Related[0]; r.Number != "PRC-CONDUCT-000001" || r.Title == "" || r.Label != "is related to" {
		t.Fatalf("related[0] = %+v, want the target's number, title and the label", r)
	}
	if got.Editable {
		t.Fatal("a published version is not editable")
	}
}

// mock: "lets a reader see the links of a published version"
func TestPolicyVersionLinks_AReaderSeesThePublishedVersion(t *testing.T) {
	e := newVLEnv(t)
	got := e.links(t, "erin", vlPublished)
	if !slices.Equal(refIDs(got.References), []string{"reference-1", "reference-4"}) {
		t.Fatalf("references = %v", refIDs(got.References))
	}
	if got.Editable {
		t.Fatal("a reader must not be told the links are editable")
	}
}

// gateway: a draft's links are for those who may see the draft; a reader is
// not told the draft exists.
func TestPolicyVersionLinks_ADraftIsNotFoundForAReader(t *testing.T) {
	e := newVLEnv(t)
	_, err := e.r.Query().PolicyVersionLinks(vlCtx(t, "erin"), vlDraft)
	if vlCode(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if e.links(t, "bob", vlDraft).Editable != true {
		t.Fatal("the author of an open draft must see it editable")
	}
}

// gateway: a caller who cannot read the policy gets nothing about its version.
func TestPolicyVersionLinks_UnreadablePolicyIsNotFound(t *testing.T) {
	e := newVLEnv(t)
	_, err := e.r.Query().PolicyVersionLinks(vlCtx(t, "outsider"), "version-90")
	if vlCode(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
}

// gateway: core's editable is status only, so the caller's own right to edit is
// ANDed in. Core says editable here; a reader may not edit.
func TestPolicyVersionLinks_EditableIsAndedWithTheCallersRightToEdit(t *testing.T) {
	e := newVLEnv(t)
	e.core.forceEditable = true
	if e.links(t, "erin", vlPublished).Editable {
		t.Fatal("a reader must not get editable even when core says the status allows it")
	}
	if !e.links(t, "bob", vlPublished).Editable {
		t.Fatal("the author must get editable when core says the status allows it")
	}
	if !e.links(t, "alice", vlPublished).Editable {
		t.Fatal("a site admin must get editable when core says the status allows it")
	}
}

// gateway: a related policy the caller cannot read is left out, so its number
// and title are not given away (the mock lists only what the person can see).
func TestPolicyVersionLinks_LeavesOutRelatedPoliciesTheCallerCannotRead(t *testing.T) {
	e := newVLEnv(t)
	e.core.stored[vlPublished].related = []*corev1.RelatedLinkInput{
		{PolicyId: "policy-2", RelationType: vlTypeRelatedTo}, {PolicyId: vlHiddenPolicy, RelationType: vlTypeRelatedTo},
	}
	outsider := e.links(t, "outsider", vlPublished)
	if want := [][3]string{{"policy-2", "RELATED_TO", "OUTGOING"}}; !equalKeys(relatedKeys(outsider.Related), want) {
		t.Fatalf("outsider related = %v, want only %v", relatedKeys(outsider.Related), want)
	}
	if len(e.links(t, "bob", vlPublished).Related) != 2 {
		t.Fatal("a caller who can read both must see both")
	}
}

// gateway: a related policy that was never published is no one's to see but those who
// may edit it, so a link does not give a draft away (the leak the older
// relatedPolicies query was fixed for).
func TestPolicyVersionLinks_ANeverPublishedRelatedPolicyIsHiddenFromAReader(t *testing.T) {
	e := newVLEnv(t)
	if got := e.links(t, "erin", vlPublished); len(got.Related) != 0 {
		t.Fatalf("a reader sees %v, want the never-published policy-7 left out", relatedKeys(got.Related))
	}
	for _, user := range []string{"bob", "alice"} {
		if got := e.links(t, user, vlPublished); len(got.Related) != 1 {
			t.Fatalf("%s sees %v, want policy-7 (may edit it)", user, relatedKeys(got.Related))
		}
	}
}

// mock: "reads from both sides: the target shows the link under the inverse type"
func TestPolicyVersionLinks_TheOtherSideReadsTheInverse(t *testing.T) {
	e := newVLEnv(t)
	got := e.links(t, "alice", vlRejected)
	want := [][3]string{{vlPolicy, "RELATED_BY", "INCOMING"}}
	if !equalKeys(relatedKeys(got.Related), want) || got.Related[0].Label != "is related by" {
		t.Fatalf("related = %+v, want %v labelled %q", relatedKeys(got.Related), want, "is related by")
	}
}

// mock: "returns them in the stored order, not the library's" and
// "keeps a change in the draft out of the published version until it is published"
func TestSetVersionReferences_KeepsTheOrderAndTheDraftApart(t *testing.T) {
	e := newVLEnv(t)
	ids := []string{"reference-4", "reference-2", "reference-1"}
	got, err := e.r.Mutation().SetVersionReferences(vlCtx(t, "bob"), vlDraft, ids)
	if err != nil {
		t.Fatalf("setVersionReferences: %v", err)
	}
	if !slices.Equal(refIDs(got.References), ids) {
		t.Fatalf("references = %v, want the order given %v", refIDs(got.References), ids)
	}
	if !slices.Equal(e.core.lastReq.(*corev1.SetVersionReferencesRequest).GetReferenceIds(), ids) {
		t.Fatal("core must be given the ids in the order the author gave")
	}
	if e.core.lastActor != "bob" {
		t.Fatalf("core actor = %q, want the signed-in user", e.core.lastActor)
	}
	if got := e.links(t, "bob", vlPublished); !slices.Equal(refIDs(got.References), []string{"reference-1", "reference-4"}) {
		t.Fatalf("published references = %v, want them as approved", refIDs(got.References))
	}
	// publishing the draft is core's move: the same version then reads for everyone
	e.pc.versions[vlDraft].Status = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED
	if got := e.links(t, "erin", vlDraft); !slices.Equal(refIDs(got.References), ids) {
		t.Fatalf("after publish a reader sees %v, want %v", refIDs(got.References), ids)
	}
}

func TestSetVersionContacts_KeepsTheOrderAndLeavesThePublishedVersion(t *testing.T) {
	e := newVLEnv(t)
	ids := []string{"contact-block-3", "contact-block-2", "contact-block-1"}
	got, err := e.r.Mutation().SetVersionContacts(vlCtx(t, "bob"), vlDraft, ids)
	if err != nil {
		t.Fatalf("setVersionContacts: %v", err)
	}
	if !slices.Equal(contactIDs(got.Contacts), ids) {
		t.Fatalf("contacts = %v, want %v", contactIDs(got.Contacts), ids)
	}
	if got := e.links(t, "erin", vlPublished); !slices.Equal(contactIDs(got.Contacts), []string{"contact-block-3", "contact-block-1"}) {
		t.Fatalf("published contacts = %v, want the seeded order", contactIDs(got.Contacts))
	}
	// copies rather than shares: emptying the draft's contacts leaves the old version alone
	if _, err := e.r.Mutation().SetVersionContacts(vlCtx(t, "bob"), vlDraft, []string{}); err != nil {
		t.Fatalf("clearing contacts: %v", err)
	}
	if got := e.links(t, "bob", vlPublished); len(got.Contacts) != 2 {
		t.Fatalf("published contacts = %v, want them untouched", contactIDs(got.Contacts))
	}
}

// mock: "accepts a draft, a version in review and a withdrawn one". Core puts a
// version in review or withdrawn under the draft status, so the draft stands for them.
func TestSetVersionReferences_AcceptsADraftAndReportsItEditable(t *testing.T) {
	e := newVLEnv(t)
	got, err := e.r.Mutation().SetVersionReferences(vlCtx(t, "bob"), vlDraft, []string{"reference-3"})
	if err != nil {
		t.Fatalf("setVersionReferences: %v", err)
	}
	if !got.Editable {
		t.Fatal("the draft must come back editable for its author")
	}
}

// mock: "refuses a published version and a superseded one" and "refuses a
// rejected version, which is final"
func TestSetVersionLinks_FailedPreconditionWhenTheVersionIsNotEditable(t *testing.T) {
	for _, version := range []string{vlPublished, vlSuperseded, vlRejected} {
		t.Run(version, func(t *testing.T) {
			e := newVLEnv(t)
			_, err := e.r.Mutation().SetVersionReferences(vlCtx(t, "alice"), version, []string{})
			if vlCode(err) != codes.FailedPrecondition {
				t.Fatalf("got %v, want FailedPrecondition", err)
			}
			if strings.Contains(err.Error(), vlLeakMarker) || strings.Contains(err.Error(), version) {
				t.Fatalf("the refusal leaks core's text: %q", err.Error())
			}
		})
	}
}

// mock: "refuses someone who may not edit the policy". Core is never asked.
func TestSetVersionLinks_RefusesACallerWhoMayNotEditBeforeCoreIsAsked(t *testing.T) {
	sets := map[string]func(e *vlEnv, ctx context.Context, version string) error{
		"references": func(e *vlEnv, ctx context.Context, v string) error {
			_, err := e.r.Mutation().SetVersionReferences(ctx, v, []string{})
			return err
		},
		"contacts": func(e *vlEnv, ctx context.Context, v string) error {
			_, err := e.r.Mutation().SetVersionContacts(ctx, v, []string{})
			return err
		},
		"definitions": func(e *vlEnv, ctx context.Context, v string) error {
			_, err := e.r.Mutation().SetVersionDefinitions(ctx, v, []string{})
			return err
		},
		"related": func(e *vlEnv, ctx context.Context, v string) error {
			_, err := e.r.Mutation().SetVersionRelated(ctx, v, []*resolvers.RelatedLinkInput{})
			return err
		},
	}
	for name, set := range sets {
		t.Run(name, func(t *testing.T) {
			e := newVLEnv(t)
			// a draft the reader cannot see is not found; a published version she can read is denied
			if err := set(e, vlCtx(t, "erin"), vlDraft); vlCode(err) != codes.NotFound {
				t.Fatalf("draft: got %v, want NotFound", err)
			}
			if err := set(e, vlCtx(t, "erin"), vlPublished); vlCode(err) != codes.PermissionDenied {
				t.Fatalf("published: got %v, want PermissionDenied", err)
			}
			if err := set(e, vlCtx(t, "outsider"), "version-90"); vlCode(err) != codes.NotFound {
				t.Fatalf("unreadable policy: got %v, want NotFound", err)
			}
			if e.core.sets != 0 {
				t.Fatalf("core Set was called %d times for a caller who may not edit", e.core.sets)
			}
			if got := e.links(t, "bob", vlDraft); !slices.Equal(refIDs(got.References), []string{"reference-1", "reference-4"}) {
				t.Fatalf("draft references = %v, want them untouched", refIDs(got.References))
			}
		})
	}
}

func TestSetVersionLinks_NeedsASignedInUser(t *testing.T) {
	e := newVLEnv(t)
	if _, err := e.r.Mutation().SetVersionReferences(context.Background(), vlDraft, []string{}); err == nil {
		t.Fatal("an anonymous caller must be refused")
	}
	if _, err := e.r.Query().PolicyVersionLinks(context.Background(), vlPublished); err == nil {
		t.Fatal("an anonymous caller must be refused")
	}
	if _, err := e.r.Query().RelationshipTypes(context.Background()); err == nil {
		t.Fatal("an anonymous caller must be refused")
	}
	if e.core.sets != 0 {
		t.Fatal("core must not be asked")
	}
}

func TestVersionLinks_UnavailableWithoutACoreClient(t *testing.T) {
	e := newVLEnv(t)
	e.r.VersionLinkClient = nil
	if _, err := e.r.Query().PolicyVersionLinks(vlCtx(t, "bob"), vlPublished); vlCode(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}

// mock: "does not make a draft by itself: linking needs the draft to exist"
func TestSetVersionLinks_NeverSavesADraft(t *testing.T) {
	e := newVLEnv(t)
	_, _ = e.r.Mutation().SetVersionReferences(vlCtx(t, "bob"), vlPublished, []string{})
	if e.pc.lastSave != nil {
		t.Fatalf("SaveDraft was called: %+v", e.pc.lastSave)
	}
}

// mock: "names each reference only once" and "refuses an item that is not in the library"
func TestSetVersionReferences_MapsCoreRefusalsToCodesWithoutLeaking(t *testing.T) {
	e := newVLEnv(t)
	cases := []struct {
		name string
		ids  []string
		want codes.Code
	}{
		{"named twice", []string{"reference-1", "reference-1"}, codes.InvalidArgument},
		{"not in the library", []string{"reference-nope"}, codes.NotFound},
	}
	for _, c := range cases {
		_, err := e.r.Mutation().SetVersionReferences(vlCtx(t, "bob"), vlDraft, c.ids)
		if vlCode(err) != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), vlLeakMarker) || strings.Contains(err.Error(), "reference-nope") {
			t.Fatalf("%s: the refusal leaks core's text: %q", c.name, err.Error())
		}
	}
	if got := e.links(t, "bob", vlDraft); !slices.Equal(refIDs(got.References), []string{"reference-1", "reference-4"}) {
		t.Fatalf("a refused set must change nothing, got %v", refIDs(got.References))
	}
}

// mock: "are listed alphabetically on a version, whatever order they were linked"
func TestSetVersionDefinitions_ListedAsCoreSortsThem(t *testing.T) {
	e := newVLEnv(t)
	got, err := e.r.Mutation().SetVersionDefinitions(vlCtx(t, "bob"), vlDraft, []string{"definition-4", "definition-2", "definition-1"})
	if err != nil {
		t.Fatalf("setVersionDefinitions: %v", err)
	}
	if want := []string{"Business expense", "RPO", "RTO"}; !slices.Equal(defTerms(got.Definitions), want) {
		t.Fatalf("definitions = %v, want %v", defTerms(got.Definitions), want)
	}
	older, err := e.r.Query().PolicyDefinitionEntries(vlCtx(t, "erin"), vlPolicy)
	if err != nil {
		t.Fatalf("policyDefinitionEntries: %v", err)
	}
	if want := []string{"Business expense"}; !slices.Equal(defTerms(older), want) {
		t.Fatalf("policyDefinitionEntries = %v, want the published version's %v", defTerms(older), want)
	}
}

// mock: "offers a fixed list, each type with its inverse"
func TestRelationshipTypes_EachTypeWithItsInverse(t *testing.T) {
	e := newVLEnv(t)
	got, err := e.r.Query().RelationshipTypes(vlCtx(t, "bob"))
	if err != nil {
		t.Fatalf("relationshipTypes: %v", err)
	}
	byID := map[string]*resolvers.RelationshipTypeInfo{}
	for _, ty := range got {
		byID[ty.ID] = ty
	}
	related := byID["RELATED_TO"]
	if related == nil || related.Label != "is related to" || related.InverseID != "RELATED_BY" || related.InverseLabel != "is related by" {
		t.Fatalf("RELATED_TO = %+v", related)
	}
	for _, ty := range got {
		inv := byID[ty.InverseID]
		if inv == nil || inv.InverseID != ty.ID || inv.Label != ty.InverseLabel {
			t.Fatalf("%s: inverse %+v does not round trip", ty.ID, inv)
		}
	}
}

// mock: "stores the type chosen for each link"
func TestSetVersionRelated_StoresTheTypeChosen(t *testing.T) {
	e := newVLEnv(t)
	got, err := e.r.Mutation().SetVersionRelated(vlCtx(t, "bob"), vlDraft, []*resolvers.RelatedLinkInput{
		{PolicyID: vlTargetPolicy, Type: "SUPERSEDES"}, {PolicyID: "policy-2", Type: "RELATED_TO"},
	})
	if err != nil {
		t.Fatalf("setVersionRelated: %v", err)
	}
	want := [][3]string{{vlTargetPolicy, "SUPERSEDES", "OUTGOING"}, {"policy-2", "RELATED_TO", "OUTGOING"}}
	if !equalKeys(relatedKeys(got.Related), want) || got.Related[0].Label != "supersedes" {
		t.Fatalf("related = %v, want %v", relatedKeys(got.Related), want)
	}
	req := e.core.lastReq.(*corev1.SetVersionRelatedRequest)
	if req.GetPolicyVersionId() != vlDraft || req.GetActorUserId() != "bob" || len(req.GetLinks()) != 2 || req.GetLinks()[0].GetRelationType() != "SUPERSEDES" {
		t.Fatalf("core request = %+v, want the version, the actor and the links in order", req)
	}
}

// mock: "shows a link added in a draft on the other side only once that draft is published"
func TestSetVersionRelated_TheOtherSideSeesItOnceThePolicyIsPublished(t *testing.T) {
	e := newVLEnv(t)
	if _, err := e.r.Mutation().SetVersionRelated(vlCtx(t, "bob"), vlDraft, []*resolvers.RelatedLinkInput{{PolicyID: vlTargetPolicy, Type: "SUPERSEDES"}}); err != nil {
		t.Fatalf("setVersionRelated: %v", err)
	}
	if got := e.links(t, "alice", vlRejected); len(got.Related) != 1 || got.Related[0].Type != "RELATED_BY" {
		t.Fatalf("before publish related = %v, want the published version's RELATED_BY", relatedKeys(got.Related))
	}
	e.pc.versions[vlDraft].Status = corev1.PolicyVersionStatus_POLICY_VERSION_STATUS_PUBLISHED
	e.pc.policies[vlPolicy].CurrentPublishedVersionId = vlDraft
	got := e.links(t, "alice", vlRejected)
	if len(got.Related) != 1 || got.Related[0].Type != "SUPERSEDED_BY" || got.Related[0].Label != "is superseded by" {
		t.Fatalf("after publish related = %+v, want SUPERSEDED_BY", relatedKeys(got.Related))
	}
}

// mock: "refuses an unknown type, a link to itself and a repeated link" and
// "refuses a policy that does not exist"
func TestSetVersionRelated_MapsCoreRefusalsToCodesWithoutLeaking(t *testing.T) {
	e := newVLEnv(t)
	cases := []struct {
		name  string
		links []*resolvers.RelatedLinkInput
		want  codes.Code
	}{
		{"unknown type", []*resolvers.RelatedLinkInput{{PolicyID: vlTargetPolicy, Type: "LOVES"}}, codes.InvalidArgument},
		{"itself", []*resolvers.RelatedLinkInput{{PolicyID: vlPolicy, Type: "RELATED_TO"}}, codes.InvalidArgument},
		{"repeated", []*resolvers.RelatedLinkInput{{PolicyID: vlTargetPolicy, Type: "RELATED_TO"}, {PolicyID: vlTargetPolicy, Type: "RELATED_TO"}}, codes.InvalidArgument},
		{"no such policy", []*resolvers.RelatedLinkInput{{PolicyID: "policy-does-not-exist", Type: "RELATED_TO"}}, codes.NotFound},
	}
	for _, c := range cases {
		_, err := e.r.Mutation().SetVersionRelated(vlCtx(t, "bob"), vlDraft, c.links)
		if vlCode(err) != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), vlLeakMarker) {
			t.Fatalf("%s: the refusal leaks core's text: %q", c.name, err.Error())
		}
	}
}

// gateway: a link to a policy the caller cannot read is NotFound before core is
// asked, the same as one that does not exist (the mock does the same).
func TestSetVersionRelated_APolicyTheCallerCannotReadIsNotFound(t *testing.T) {
	e := newVLEnv(t)
	e.pc.policies[vlPolicy].OwnerUserId = "outsider"
	_, err := e.r.Mutation().SetVersionRelated(vlCtx(t, "outsider"), vlDraft, []*resolvers.RelatedLinkInput{{PolicyID: vlHiddenPolicy, Type: "RELATED_TO"}})
	if vlCode(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if e.core.sets != 0 {
		t.Fatalf("core Set was called %d times", e.core.sets)
	}
}

// mock: "keeps answering the older relatedPolicies query for the published version"
func TestRelatedPolicies_AnswersFromThePublishedVersionOutgoingOnly(t *testing.T) {
	e := newVLEnv(t)
	got, err := e.r.Query().RelatedPolicies(vlCtx(t, "alice"), vlPolicy)
	if err != nil {
		t.Fatalf("relatedPolicies: %v", err)
	}
	want := []*resolvers.RelatedPolicy{{PolicyID: vlTargetPolicy, Number: "PRC-CONDUCT-000001", Title: "Gifts and Hospitality Procedure"}}
	if len(got) != 1 || *got[0] != *want[0] {
		t.Fatalf("relatedPolicies = %+v, want %+v", got, want)
	}
	// policy-7 is named by policy-1, not the other way: the incoming link is no related policy of policy-7
	back, err := e.r.Query().RelatedPolicies(vlCtx(t, "alice"), vlTargetPolicy)
	if err != nil || len(back) != 0 {
		t.Fatalf("relatedPolicies(policy-7) = %+v, %v; want none (outgoing only)", back, err)
	}
}

func TestRelatedPolicies_LeavesOutWhatTheCallerCannotRead(t *testing.T) {
	e := newVLEnv(t)
	e.core.stored[vlPublished].related = []*corev1.RelatedLinkInput{
		{PolicyId: "policy-2", RelationType: vlTypeRelatedTo}, {PolicyId: vlHiddenPolicy, RelationType: vlTypeRelatedTo}, {PolicyId: vlTargetPolicy, RelationType: vlTypeRelatedTo},
	}
	got, err := e.r.Query().RelatedPolicies(vlCtx(t, "outsider"), vlPolicy)
	if err != nil {
		t.Fatalf("relatedPolicies: %v", err)
	}
	if len(got) != 1 || got[0].PolicyID != "policy-2" {
		t.Fatalf("relatedPolicies = %+v, want only the readable, published policy", got)
	}
}

// mock: "answers the older per-policy queries in that order too"
func TestPolicyReferencesAndContactBlocks_AnswerFromThePublishedVersionInOrder(t *testing.T) {
	e := newVLEnv(t)
	// an open draft with other links exists; readers still get the published version's
	if _, err := e.r.Mutation().SetVersionReferences(vlCtx(t, "bob"), vlDraft, []string{"reference-2"}); err != nil {
		t.Fatalf("setVersionReferences: %v", err)
	}
	refs, err := e.r.Query().PolicyReferences(vlCtx(t, "erin"), vlPolicy)
	if err != nil {
		t.Fatalf("policyReferences: %v", err)
	}
	if !slices.Equal(refIDs(refs), []string{"reference-1", "reference-4"}) {
		t.Fatalf("policyReferences = %v", refIDs(refs))
	}
	contacts, err := e.r.Query().PolicyContactBlocks(vlCtx(t, "erin"), vlPolicy)
	if err != nil {
		t.Fatalf("policyContactBlocks: %v", err)
	}
	if !slices.Equal(contactIDs(contacts), []string{"contact-block-3", "contact-block-1"}) {
		t.Fatalf("policyContactBlocks = %v", contactIDs(contacts))
	}
}

// gateway: with no published version the old queries answer from the draft, for
// those who may see the draft; anyone else gets an empty answer, not a hint
// that a draft exists. A policy with neither answers empty.
func TestPolicyLinkQueries_FallBackToTheDraftForItsEditors(t *testing.T) {
	e := newVLEnv(t)
	refs, err := e.r.Query().PolicyReferences(vlCtx(t, "bob"), vlDraftOnly)
	if err != nil || !slices.Equal(refIDs(refs), []string{"reference-2"}) {
		t.Fatalf("editor: policyReferences = %v, %v; want the draft's reference-2", refIDs(refs), err)
	}
	refs, err = e.r.Query().PolicyReferences(vlCtx(t, "erin"), vlDraftOnly)
	if err != nil || len(refs) != 0 {
		t.Fatalf("reader: policyReferences = %v, %v; want none", refIDs(refs), err)
	}
	refs, err = e.r.Query().PolicyReferences(vlCtx(t, "bob"), vlNothing)
	if err != nil || refs == nil || len(refs) != 0 {
		t.Fatalf("no version: policyReferences = %v, %v; want an empty list", refs, err)
	}
	rel, err := e.r.Query().RelatedPolicies(vlCtx(t, "bob"), vlNothing)
	if err != nil || rel == nil || len(rel) != 0 {
		t.Fatalf("no version: relatedPolicies = %v, %v; want an empty list", rel, err)
	}
}

func TestPolicyLinkQueries_UnreadablePolicyIsNotFound(t *testing.T) {
	e := newVLEnv(t)
	if _, err := e.r.Query().PolicyReferences(vlCtx(t, "outsider"), vlHiddenPolicy); vlCode(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if _, err := e.r.Query().PolicyContactBlocks(vlCtx(t, "outsider"), vlHiddenPolicy); vlCode(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
}

// definitionRefusals plays core's CreateDefinitionEntry and UpdateDefinitionEntry
// refusing a taken or empty title, with the raw text core puts in them.
type definitionRefusals struct {
	fakeDefinitionLibraryClient
	err error
}

func (d *definitionRefusals) CreateDefinitionEntry(context.Context, *corev1.CreateDefinitionEntryRequest, ...grpc.CallOption) (*corev1.CreateDefinitionEntryResponse, error) {
	return nil, d.err
}

func (d *definitionRefusals) UpdateDefinitionEntry(context.Context, *corev1.UpdateDefinitionEntryRequest, ...grpc.CallOption) (*corev1.UpdateDefinitionEntryResponse, error) {
	return nil, d.err
}

// mock: "are unique by title..." / "are unique across categories..." / "refuse a
// rename onto another title..." / "refuse an empty title"
func TestDefinitions_TitleRefusalsReachTheClientAsCodes(t *testing.T) {
	cases := []struct {
		name string
		core codes.Code
		want codes.Code
	}{
		{"a taken title", codes.AlreadyExists, codes.AlreadyExists},
		{"an empty title", codes.InvalidArgument, codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &definitionRefusals{
				fakeDefinitionLibraryClient: fakeDefinitionLibraryClient{library: defLibrary()},
				err:                         status.Error(c.core, "definition title: "+vlLeakMarker),
			}
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "alice", RolesValue: []string{"site-admin"}, IsRootValue: true})
			in := &resolvers.DefinitionEntryInput{CategoryID: "cat-1", Term: "RTO", Definition: "A meaning."}

			_, err := resolvers.CreateDefinitionResolver(ctx, client, in)
			if vlCode(err) != c.want || strings.Contains(err.Error(), vlLeakMarker) {
				t.Fatalf("create: got %v, want %v without core's text", err, c.want)
			}
			_, err = resolvers.UpdateDefinitionResolver(ctx, client, "def-1", in)
			if vlCode(err) != c.want || strings.Contains(err.Error(), vlLeakMarker) {
				t.Fatalf("update: got %v, want %v without core's text", err, c.want)
			}
		})
	}
}

func TestDefinitions_OtherCoreFailuresStayFaults(t *testing.T) {
	client := &definitionRefusals{
		fakeDefinitionLibraryClient: fakeDefinitionLibraryClient{library: defLibrary()},
		err:                         status.Error(codes.Internal, "boom "+vlLeakMarker),
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "alice", RolesValue: []string{"site-admin"}, IsRootValue: true})
	_, err := resolvers.CreateDefinitionResolver(ctx, client, &resolvers.DefinitionEntryInput{CategoryID: "cat-1", Term: "RTO", Definition: "x"})
	if vlCode(err) != codes.Internal {
		t.Fatalf("got %v, want an Internal fault the presenter hides", err)
	}
}
