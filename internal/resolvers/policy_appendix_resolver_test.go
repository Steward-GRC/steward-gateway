// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// The appendix life cycle over GraphQL. Each test names the mock server test it
// ports (steward-mock-server src/product/appendices.test.ts and
// appendix-titles-contributors.test.ts), which is the acceptance list.

const (
	apxPolicy = "pol-1"
	apxSeeded = "appendix-1"
	apxBody   = `{"root":{"children":[{"type":"text","text":"Terms."}]}}`
)

// apxIdentity names the people. A user missing from the map is unknown to
// identity, as a removed one can be.
type apxIdentity struct {
	identityv1.IdentityReadServiceClient
	users map[string]*identityv1.User
}

func (i apxIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	u, ok := i.users[in.GetUserId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such user")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

type apxEnv struct {
	core  *appendixCore
	users map[string]*identityv1.User
	r     *resolvers.Resolver
}

// newApxEnv is the policy pol-1 owned by bob (so an author), a site admin
// alice, a plain reader erin, and the seeded appendix A, published v1 by bob.
func newApxEnv(t *testing.T) *apxEnv {
	t.Helper()
	pc, gc, _ := breakGlassReadSetup(t, false)
	pc.policies[apxPolicy].OwnerUserId = "bob"
	core := &appendixCore{}
	core.seed(apxSeeded, apxPolicy, "Per-diem rates", apxBody, "bob")
	users := map[string]*identityv1.User{
		"bob":   {Id: "bob", Name: "Bob Author", Enabled: true},
		"alice": {Id: "alice", Name: "Alice Admin", Enabled: true},
		"erin":  {Id: "erin", Name: "Erin Reader", Enabled: true},
	}
	return &apxEnv{core: core, users: users, r: &resolvers.Resolver{
		PolicyAppendixClient: core, PolicyClient: pc, CategoryClient: gc, IdentityAdminClient: noGrant(),
		IdentityClient: apxIdentity{users: users}, Log: log.Nop(),
	}}
}

func apxCtx(t *testing.T, user string) context.Context {
	t.Helper()
	roles := []string{"reader"}
	if user == "alice" {
		// Alice is the root site admin: a site admin who is not root follows
		// the category rules like anyone else.
		return ctxRoot(t, user)
	}
	return ctxWithStubClaims(t, principal.Static{UserIDValue: user, RolesValue: roles})
}

func (e *apxEnv) list(t *testing.T, user string, retired bool) []*resolvers.PolicyAppendix {
	t.Helper()
	got, err := e.r.Query().PolicyAppendices(apxCtx(t, user), apxPolicy, &retired)
	if err != nil {
		t.Fatalf("policyAppendices as %s: %v", user, err)
	}
	return got
}

func (e *apxEnv) create(t *testing.T, user string, title *string) *resolvers.PolicyAppendix {
	t.Helper()
	got, err := e.r.Mutation().CreatePolicyAppendix(apxCtx(t, user), apxPolicy, title, apxBody)
	if err != nil {
		t.Fatalf("createPolicyAppendix as %s: %v", user, err)
	}
	return got
}

func (e *apxEnv) publish(t *testing.T, user, id string) *resolvers.PolicyAppendix {
	t.Helper()
	got, err := e.r.Mutation().PublishAppendix(apxCtx(t, user), id)
	if err != nil {
		t.Fatalf("publishAppendix as %s: %v", user, err)
	}
	return got
}

func (e *apxEnv) save(t *testing.T, user, id, title, content string) *resolvers.PolicyAppendix {
	t.Helper()
	got, err := e.r.Mutation().SaveAppendixDraft(apxCtx(t, user), id, title, content)
	if err != nil {
		t.Fatalf("saveAppendixDraft as %s: %v", user, err)
	}
	return got
}

// readerTitles is PolicyVersion.appendices for one version, as titles.
func (e *apxEnv) readerTitles(t *testing.T, version, user string) []*resolvers.Appendix {
	t.Helper()
	got, err := e.r.PolicyVersion().Appendices(apxCtx(t, user), &resolvers.PolicyVersion{ID: version, PolicyID: apxPolicy})
	if err != nil {
		t.Fatalf("PolicyVersion.appendices(%s) as %s: %v", version, user, err)
	}
	return got
}

func apxTitles(as []*resolvers.Appendix) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, a.Title)
	}
	return out
}

func strp(s string) *string { return &s }

func apxIDs(as []*resolvers.PolicyAppendix) []string {
	out := []string{}
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

func contribIDs(cs []*resolvers.AppendixContributor) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.UserID)
	}
	return out
}

func versionNos(vs []*resolvers.AppendixVersion) []int {
	out := []int{}
	for _, v := range vs {
		out = append(out, v.VersionNo)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// mock: "an appendix belongs to the policy, not to a version" / "has the
// seeded appendix as published v1 of the policy"
func TestPolicyAppendices_SeededIsPublishedV1(t *testing.T) {
	e := newApxEnv(t)
	got := e.list(t, "bob", false)
	if len(got) != 1 || deref(got[0].Letter) != "A" || got[0].Published == nil || got[0].Published.VersionNo != 1 || got[0].Draft != nil {
		t.Fatalf("got %+v, want one appendix A, published v1, no draft", got)
	}
	if got[0].PolicyID != apxPolicy || got[0].CreatedBy != "bob" || got[0].CreatedAt == "" {
		t.Fatalf("policy/created = %q %q %q", got[0].PolicyID, got[0].CreatedBy, got[0].CreatedAt)
	}
	if got[0].RetiredAt != nil || got[0].RetiredBy != nil {
		t.Fatalf("a live appendix must not be retired: %v %v", got[0].RetiredAt, got[0].RetiredBy)
	}
}

// mock: "shows readers the same published appendices on every version of the
// policy"
func TestPolicyVersionAppendices_SamePublishedOnEveryVersion(t *testing.T) {
	e := newApxEnv(t)
	current := e.readerTitles(t, "version-2", "erin")
	old := e.readerTitles(t, "version-10", "erin")
	if !slices.Equal(apxTitles(current), []string{"Per-diem rates"}) || !slices.Equal(apxTitles(old), apxTitles(current)) {
		t.Fatalf("current %v old %v, want the same published titles", apxTitles(current), apxTitles(old))
	}
	for _, a := range old {
		if a.PolicyVersionID != "version-10" || a.Letter != "A" || a.OrderIndex != 0 {
			t.Fatalf("old shape = %+v, want policyVersionId = the version asked, letter A, order 0", a)
		}
	}
	if current[0].PolicyVersionID != "version-2" {
		t.Fatalf("policyVersionId = %q, want version-2", current[0].PolicyVersionID)
	}
}

// mock: "starts a new appendix as a draft only an editor sees"
func TestCreatePolicyAppendix_DraftOnlyAnEditorSees(t *testing.T) {
	e := newApxEnv(t)
	made := e.create(t, "bob", strp("Glossary"))
	if made.Published != nil || made.Draft == nil || made.Draft.VersionNo != 1 || deref(made.Letter) != "B" {
		t.Fatalf("made = %+v, want draft v1, no published, letter B", made)
	}
	if got := e.core.lastActor; got != "bob" {
		t.Fatalf("core actor = %q, want the signed-in user", got)
	}
	if !slices.Contains(apxIDs(e.list(t, "bob", false)), made.ID) {
		t.Fatal("the editor must list the new draft appendix")
	}
	if slices.Contains(apxTitles(e.readerTitles(t, "version-2", "erin")), "Glossary") {
		t.Fatal("a reader must not see an appendix with no published row")
	}
	if slices.Contains(apxIDs(e.list(t, "erin", false)), made.ID) {
		t.Fatal("a reader must not list an appendix with no published row")
	}
	// the editor's own PolicyVersion.appendices also carries published rows only
	if slices.Contains(apxTitles(e.readerTitles(t, "version-2", "bob")), "Glossary") {
		t.Fatal("PolicyVersion.appendices must hold published rows only")
	}
}

// mock: "autosaves into the draft, and shows readers nothing until it is
// published"
func TestSaveAppendixDraft_AutosavesAndReadersSeeNothing(t *testing.T) {
	e := newApxEnv(t)
	made := e.create(t, "bob", strp("Glossary"))
	saved := e.save(t, "bob", made.ID, "Glossary of terms", `{"root":{"children":[]}}`)
	if saved.Draft == nil || saved.Draft.Title != "Glossary of terms" {
		t.Fatalf("draft = %+v", saved.Draft)
	}
	for _, title := range apxTitles(e.readerTitles(t, "version-2", "erin")) {
		if strings.HasPrefix(title, "Glossary") {
			t.Fatalf("reader saw %q before publish", title)
		}
	}
}

// mock: "publishes to the version readers see, with who and when"
func TestPublishAppendix_ShowsReadersWithWhoAndWhen(t *testing.T) {
	e := newApxEnv(t)
	made := e.create(t, "bob", strp("Glossary"))
	got := e.publish(t, "bob", made.ID)
	if got.Published == nil || got.Published.VersionNo != 1 || got.Published.State != resolvers.AppendixStatePublished {
		t.Fatalf("published = %+v", got.Published)
	}
	if deref(got.Published.PublishedBy) != "bob" || deref(got.Published.PublishedAt) == "" {
		t.Fatalf("publishedBy/At = %s / %s", deref(got.Published.PublishedBy), deref(got.Published.PublishedAt))
	}
	if got.Draft != nil {
		t.Fatalf("draft = %+v, want none after publish", got.Draft)
	}
	if !slices.Contains(apxTitles(e.readerTitles(t, "version-2", "erin")), "Glossary") {
		t.Fatal("a reader must see the published appendix on a version")
	}
}

// mock: "keeps showing the published appendix while a newer draft is being
// written"
func TestSaveAppendixDraft_KeepsPublishedWhileDraftIsWritten(t *testing.T) {
	e := newApxEnv(t)
	e.save(t, "bob", apxSeeded, "Approval limits (draft)", `{"root":{"children":[]}}`)
	row := e.list(t, "bob", false)[0]
	if row.Published.Title != "Per-diem rates" || row.Draft == nil || row.Draft.Title != "Approval limits (draft)" || row.Draft.VersionNo != 2 {
		t.Fatalf("row = published %q draft %+v", row.Published.Title, row.Draft)
	}
	if got := e.readerTitles(t, "version-2", "erin")[0].Title; got != "Per-diem rates" {
		t.Fatalf("reader title = %q, want the published one", got)
	}
	e.publish(t, "bob", apxSeeded)
	if got := e.readerTitles(t, "version-2", "erin")[0].Title; got != "Approval limits (draft)" {
		t.Fatalf("after publish the reader title = %q", got)
	}
	versions := e.list(t, "bob", false)[0].Versions
	if !slices.Equal(versionNos(versions), []int{1, 2}) || versions[0].State != resolvers.AppendixStatePublished || versions[1].State != resolvers.AppendixStatePublished {
		t.Fatalf("versions = %v, want 1 and 2 both PUBLISHED", versionNos(versions))
	}
}

// mock: "who may: refuses a reader every write and shows them no draft"
func TestAppendixWrites_ReaderRefusedAndCoreNotWritten(t *testing.T) {
	e := newApxEnv(t)
	ctx := apxCtx(t, "erin")
	m := e.r.Mutation()
	cases := map[string]func() error{
		"create":  func() error { _, err := m.CreatePolicyAppendix(ctx, apxPolicy, strp("X"), "{}"); return err },
		"save":    func() error { _, err := m.SaveAppendixDraft(ctx, apxSeeded, "X", "{}"); return err },
		"publish": func() error { _, err := m.PublishAppendix(ctx, apxSeeded); return err },
		"retire":  func() error { _, err := m.RetireAppendix(ctx, apxSeeded); return err },
		"restore": func() error { _, err := m.RestoreAppendix(ctx, apxSeeded); return err },
	}
	for name, run := range cases {
		if err := run(); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s as a reader: err = %v, want PermissionDenied", name, err)
		}
	}
	if e.core.writes != 0 {
		t.Fatalf("core saw %d writes from a refused reader, want none", e.core.writes)
	}
	// ... and an unknown appendix is NotFound, relayed from the lookup
	if _, err := m.PublishAppendix(apxCtx(t, "bob"), "nope"); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown appendix: err = %v, want NotFound", err)
	}
}

func TestAppendixReads_NeedSignIn(t *testing.T) {
	e := newApxEnv(t)
	if _, err := e.r.Query().PolicyAppendices(context.Background(), apxPolicy, nil); err == nil {
		t.Fatal("policyAppendices without a signed-in user must fail")
	}
	if _, err := e.r.Mutation().PublishAppendix(context.Background(), apxSeeded); err == nil || e.core.writes != 0 {
		t.Fatal("publishAppendix without a signed-in user must fail before core")
	}
}

// A reader the read decision denies gets NotFound, as for a policy version.
func TestAppendixReads_DeniedReaderGetsNotFound(t *testing.T) {
	e := newApxEnv(t)
	pc, gc, _ := breakGlassReadSetup(t, true)
	e.r.PolicyClient, e.r.CategoryClient = pc, gc
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "erin", RolesValue: []string{"reader"}, IdpGroupsValue: []string{"Admins"}})
	if _, err := e.r.Query().PolicyAppendices(ctx, apxPolicy, nil); status.Code(err) != codes.NotFound {
		t.Fatalf("policyAppendices: err = %v, want NotFound", err)
	}
	if _, err := e.r.Query().PolicyAppendix(ctx, apxSeeded); status.Code(err) != codes.NotFound {
		t.Fatalf("policyAppendix: err = %v, want NotFound", err)
	}
}

// An obfuscated reader gets the structure with scrambled text.
func TestAppendixReads_ObfuscatedReaderGetsScrambledText(t *testing.T) {
	e := newApxEnv(t)
	pc, gc, ctx := breakGlassReadSetup(t, true) // a site admin whose group is denied on merit
	pc.policies[apxPolicy].OwnerUserId = "bob"
	e.r.PolicyClient, e.r.CategoryClient = pc, gc
	got, err := e.r.Query().PolicyAppendices(ctx, apxPolicy, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("policyAppendices: %v %v", got, err)
	}
	if strings.Contains(got[0].Published.ContentJSON, "Terms.") || got[0].Published.Title != "Per-diem rates" {
		t.Fatalf("content = %q, want scrambled text and the real title", got[0].Published.ContentJSON)
	}
	old, err := e.r.PolicyVersion().Appendices(ctx, &resolvers.PolicyVersion{ID: "version-2", PolicyID: apxPolicy})
	if err != nil || strings.Contains(old[0].ContentJSON, "Terms.") {
		t.Fatalf("PolicyVersion.appendices = %+v, %v; want scrambled text", old, err)
	}
}

// mock: "retiring and restoring: keeps a retired appendix, hides it from
// readers, and re-letters the rest"
func TestRetireAppendix_HidesFromReadersAndReletters(t *testing.T) {
	e := newApxEnv(t)
	for _, title := range []string{"Quote checklist", "Supplier terms"} {
		e.publish(t, "bob", e.create(t, "bob", strp(title)).ID)
	}
	got, err := e.r.Mutation().RetireAppendix(apxCtx(t, "bob"), apxSeeded)
	if err != nil {
		t.Fatal(err)
	}
	if got.RetiredAt == nil || got.Letter != nil {
		t.Fatalf("retired = at %v letter %v, want a time and no letter", got.RetiredAt, got.Letter)
	}
	pairs := []string{}
	for _, a := range e.readerTitles(t, "version-2", "erin") {
		pairs = append(pairs, a.Letter+":"+a.Title)
	}
	if !slices.Equal(pairs, []string{"A:Quote checklist", "B:Supplier terms"}) {
		t.Fatalf("reader sees %v", pairs)
	}
	if n := len(e.list(t, "bob", true)); n != 3 {
		t.Fatalf("editor with includeRetired sees %d, want 3", n)
	}
	if n := len(e.list(t, "bob", false)); n != 2 {
		t.Fatalf("editor without includeRetired sees %d, want 2", n)
	}
	if n := len(e.list(t, "erin", true)); n != 2 {
		t.Fatalf("reader with includeRetired sees %d, want 2", n)
	}
	if _, err := e.r.Query().PolicyAppendix(apxCtx(t, "erin"), apxSeeded); status.Code(err) != codes.NotFound {
		t.Fatalf("a reader asking for a retired appendix: err = %v, want NotFound", err)
	}
}

// mock: "restores it to the end of the list"
func TestRestoreAppendix_GoesLast(t *testing.T) {
	e := newApxEnv(t)
	for _, title := range []string{"Quote checklist", "Supplier terms"} {
		e.publish(t, "bob", e.create(t, "bob", strp(title)).ID)
	}
	m := e.r.Mutation()
	if _, err := m.RetireAppendix(apxCtx(t, "bob"), apxSeeded); err != nil {
		t.Fatal(err)
	}
	got, err := m.RestoreAppendix(apxCtx(t, "bob"), apxSeeded)
	if err != nil {
		t.Fatal(err)
	}
	if got.RetiredAt != nil || deref(got.Letter) != "C" {
		t.Fatalf("restored = retiredAt %v letter %s, want live and C", got.RetiredAt, deref(got.Letter))
	}
}

// mock: "an unchanged appendix makes no draft: ignores a save of the published
// title and content"
func TestSaveAppendixDraft_UnchangedMakesNoDraft(t *testing.T) {
	e := newApxEnv(t)
	row := e.list(t, "bob", false)[0]
	got := e.save(t, "bob", apxSeeded, row.Published.Title, row.Published.ContentJSON)
	if got.Draft != nil || e.list(t, "bob", false)[0].Draft != nil {
		t.Fatal("saving the published title and content must not open a draft")
	}
}

// mock: "makes no draft on a reorder, a retire or a restore" (the reorder is
// a separate row)
func TestRetireAndRestore_MakeNoDraft(t *testing.T) {
	e := newApxEnv(t)
	m := e.r.Mutation()
	if _, err := m.RetireAppendix(apxCtx(t, "bob"), apxSeeded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RestoreAppendix(apxCtx(t, "bob"), apxSeeded); err != nil {
		t.Fatal(err)
	}
	for _, a := range e.list(t, "bob", true) {
		if a.Draft != nil {
			t.Fatalf("%s has a draft", a.ID)
		}
	}
}

// mock (titles): "is Appendix B, then Appendix C, when no title is given",
// "treats a blank title as no title", "keeps a title that was given". Core
// names the appendix; the gateway passes a missing title on as blank.
func TestCreatePolicyAppendix_TitleDefaultsAreCores(t *testing.T) {
	e := newApxEnv(t)
	first := e.create(t, "bob", nil)
	second := e.create(t, "bob", nil)
	blank := e.create(t, "bob", strp("   "))
	named := e.create(t, "bob", strp("Glossary"))
	got := []string{first.Draft.Title, second.Draft.Title, blank.Draft.Title, named.Draft.Title}
	if !slices.Equal(got, []string{"Appendix B", "Appendix C", "Appendix D", "Glossary"}) {
		t.Fatalf("titles = %v", got)
	}
	if e.core.lastTitle != "Glossary" {
		t.Fatalf("core got title %q, want the given one", e.core.lastTitle)
	}
}

// mock (titles): "leaves renaming open"; a blank title on save is refused
// before core is asked.
func TestSaveAppendixDraft_RenameOpenBlankRefused(t *testing.T) {
	e := newApxEnv(t)
	made := e.create(t, "bob", nil)
	if got := e.save(t, "bob", made.ID, "Glossary of terms", apxBody); got.Draft.Title != "Glossary of terms" {
		t.Fatalf("title = %q", got.Draft.Title)
	}
	writes := e.core.writes
	if _, err := e.r.Mutation().SaveAppendixDraft(apxCtx(t, "bob"), made.ID, "  ", apxBody); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("blank title: err = %v, want InvalidArgument", err)
	}
	if e.core.writes != writes {
		t.Fatal("a blank title must not reach core")
	}
}

func (e *apxEnv) contributors(t *testing.T, user, id string) *resolvers.PolicyAppendix {
	t.Helper()
	got, err := e.r.Query().PolicyAppendix(apxCtx(t, user), id)
	if err != nil {
		t.Fatalf("policyAppendix as %s: %v", user, err)
	}
	return got
}

// mock (titles): "lists the seeded appendix's author, with a name"
func TestPolicyAppendix_ListsSeededAuthorWithName(t *testing.T) {
	e := newApxEnv(t)
	got := e.contributors(t, "bob", apxSeeded).Contributors
	if len(got) != 1 || *got[0] != (resolvers.AppendixContributor{UserID: "bob", Name: "Bob Author", Active: true}) {
		t.Fatalf("contributors = %+v", got)
	}
}

// mock (titles): "keeps everyone who saved or published it, in the order they
// first did" and "keeps each version's own contributors"
func TestPolicyAppendix_ContributorsInFirstSaveOrderPerVersion(t *testing.T) {
	e := newApxEnv(t)
	made := e.create(t, "bob", nil)
	e.save(t, "bob", made.ID, "Appendix B", `{"root":{"children":[]}}`)
	e.publish(t, "alice", made.ID) // publishing counts as contributing
	got := e.contributors(t, "alice", made.ID)
	if !slices.Equal(contribIDs(got.Contributors), []string{"bob", "alice"}) {
		t.Fatalf("appendix contributors = %v", contribIDs(got.Contributors))
	}
	if !slices.Equal(contribIDs(got.Versions[0].Contributors), []string{"bob", "alice"}) {
		t.Fatalf("v1 contributors = %v", contribIDs(got.Versions[0].Contributors))
	}

	// a second edition by someone else keeps its own contributors
	e.publish(t, "bob", e.create(t, "bob", strp("Third")).ID)
	other := e.create(t, "bob", strp("Fourth"))
	e.publish(t, "bob", other.ID)
	e.save(t, "alice", other.ID, "Fourth", `{"root":{"children":[1]}}`)
	row := e.contributors(t, "bob", other.ID)
	pairs := [][]string{}
	for _, v := range row.Versions {
		pairs = append(pairs, contribIDs(v.Contributors))
	}
	if len(pairs) != 2 || !slices.Equal(pairs[0], []string{"bob"}) || !slices.Equal(pairs[1], []string{"alice"}) {
		t.Fatalf("per-version contributors = %v, want [bob] then [alice]", pairs)
	}
	if !slices.Equal(contribIDs(row.Contributors), []string{"bob", "alice"}) {
		t.Fatalf("appendix contributors = %v", contribIDs(row.Contributors))
	}
}

// mock (titles): "still lists a person who has since been disabled, marked not
// active"; an unknown or removed user stays listed with the id as the name.
func TestPolicyAppendix_DisabledAndUnknownContributorsStayListed(t *testing.T) {
	e := newApxEnv(t)
	e.users["bob"].Enabled = false
	e.core.find0(apxSeeded).people = []string{"bob", "dave", "carol"}
	e.users["carol"] = &identityv1.User{Id: "carol", Name: "Carol Gone", Enabled: true, DeletedAt: "2026-01-02T03:04:05Z"}
	got := e.contributors(t, "alice", apxSeeded).Contributors
	want := []resolvers.AppendixContributor{
		{UserID: "bob", Name: "Bob Author", Active: false},
		{UserID: "dave", Name: "dave", Active: false},
		{UserID: "carol", Name: "Carol Gone", Active: false},
	}
	if len(got) != 3 {
		t.Fatalf("contributors = %+v", got)
	}
	for i := range want {
		if *got[i] != want[i] {
			t.Errorf("contributor %d = %+v, want %+v", i, *got[i], want[i])
		}
	}
}

// mock (titles): "is shown to an author, a site admin ..., and to nobody else"
// (compliance is not ported: the gateway has no role for it yet)
func TestPolicyAppendix_ContributorsOnlyForEditors(t *testing.T) {
	e := newApxEnv(t)
	for _, user := range []string{"bob", "alice"} {
		if n := len(e.contributors(t, user, apxSeeded).Contributors); n != 1 {
			t.Errorf("%s sees %d contributors, want 1", user, n)
		}
	}
	reader := e.contributors(t, "erin", apxSeeded)
	if len(reader.Contributors) != 0 {
		t.Fatalf("reader contributors = %+v, want none", reader.Contributors)
	}
	for _, v := range reader.Versions {
		if len(v.Contributors) != 0 {
			t.Fatalf("reader version contributors = %+v, want none", v.Contributors)
		}
	}
	if reader.Published == nil || len(reader.Published.Contributors) != 0 {
		t.Fatalf("reader published = %+v", reader.Published)
	}
}

// mock (titles): "lists the published versions newest first, leaving the draft
// out"; the version table stays oldest first with the draft last.
func TestPolicyAppendix_PublishedVersionsNewestFirst(t *testing.T) {
	e := newApxEnv(t)
	for _, text := range []string{"Second.", "Third."} {
		e.save(t, "bob", apxSeeded, "Per-diem rates", text)
		e.publish(t, "bob", apxSeeded)
	}
	e.save(t, "bob", apxSeeded, "Per-diem rates", "Fourth, unpublished.")
	got := e.contributors(t, "bob", apxSeeded)
	if !slices.Equal(versionNos(got.PublishedVersions), []int{3, 2, 1}) {
		t.Fatalf("publishedVersions = %v", versionNos(got.PublishedVersions))
	}
	for _, v := range got.PublishedVersions {
		if v.State != resolvers.AppendixStatePublished {
			t.Fatalf("publishedVersions holds %v", v.State)
		}
	}
	if !slices.Equal(versionNos(got.Versions), []int{1, 2, 3, 4}) || got.Versions[3].State != resolvers.AppendixStateDraft {
		t.Fatalf("versions = %v, want 1 2 3 then the draft 4", versionNos(got.Versions))
	}
	if got.Draft == nil || got.Draft.VersionNo != 4 || got.Published.VersionNo != 3 {
		t.Fatalf("draft/published = %+v / %+v", got.Draft, got.Published)
	}
}

// mock (titles): "shows a reader only the latest published version"
func TestPolicyAppendix_ReaderGetsLatestPublishedOnly(t *testing.T) {
	e := newApxEnv(t)
	e.save(t, "bob", apxSeeded, "Per-diem rates", "Second.")
	e.publish(t, "bob", apxSeeded)
	e.save(t, "bob", apxSeeded, "Per-diem rates", "Third, draft.")
	got := e.contributors(t, "erin", apxSeeded)
	if !slices.Equal(versionNos(got.PublishedVersions), []int{2}) || !slices.Equal(versionNos(got.Versions), []int{2}) {
		t.Fatalf("reader publishedVersions %v versions %v, want only 2", versionNos(got.PublishedVersions), versionNos(got.Versions))
	}
	if got.Draft != nil || got.Published == nil || got.Published.VersionNo != 2 {
		t.Fatalf("reader draft/published = %+v / %+v", got.Draft, got.Published)
	}
}
