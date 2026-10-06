// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package resolvers_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rbacVersionPolicyClient extends the shared fakePolicyClient with a
// version-aware GetPolicyVersion so the obfuscation path (which runs through
// GetPolicyVersion → versionReadDecision → applyVersionReadDecision) can be
// exercised end-to-end. Versions are keyed by id and carry their owning policy.
type rbacVersionPolicyClient struct {
	*fakePolicyClient
	versions map[string]*corev1.PolicyVersion
}

func (f *rbacVersionPolicyClient) GetPolicyVersion(_ context.Context, in *corev1.GetPolicyVersionRequest, _ ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	v, ok := f.versions[in.Id]
	if !ok {
		return nil, status.Error(codes.NotFound, "version not found")
	}
	return &corev1.GetPolicyVersionResponse{Version: v}, nil
}

// auditEvent is a minimal record of an emitted identity audit event, captured by
// the contract-faithful break-glass admin fake.
type auditEvent struct {
	action       string
	policyNumber string
	reason       string
}

// rbacBreakGlassAdmin is a contract-faithful fake of IdentityAdminServiceClient
// at the gateway gRPC seam. It models the identity break-glass grant store: a
// BreakGlassReveal records a time-boxed grant (and emits the high-severity audit
// event the real store emits), and ActiveBreakGlass returns the policy numbers
// whose grants are unexpired RELATIVE TO an injectable clock so the within-window
// vs. after-expiry behaviour can be asserted deterministically.
type rbacBreakGlassAdmin struct {
	identityv1.IdentityAdminServiceClient // embed: unwired methods panic on use

	now      func() time.Time     // injectable clock (defaults to time.Now)
	duration time.Duration        // grant window
	grants   map[string]time.Time // policyNumber -> expiry
	audit    []auditEvent         // emitted audit events, in order
	activeN  int                  // ActiveBreakGlass call count (perf guard)
}

func newRBACBreakGlassAdmin(window time.Duration) *rbacBreakGlassAdmin {
	return &rbacBreakGlassAdmin{
		now:      time.Now,
		duration: window,
		grants:   map[string]time.Time{},
	}
}

func (f *rbacBreakGlassAdmin) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

func (f *rbacBreakGlassAdmin) BreakGlassReveal(_ context.Context, in *identityv1.BreakGlassRevealRequest, _ ...grpc.CallOption) (*identityv1.BreakGlassRevealResponse, error) {
	if in.GetReason() == "" {
		// Mirror the identity handler's InvalidArgument on an empty reason; the
		// gateway also guards this, so this is defence in depth at the seam.
		return nil, status.Error(codes.InvalidArgument, "break-glass requires a non-empty reason")
	}
	exp := f.clock().Add(f.duration)
	f.grants[in.GetPolicyNumber()] = exp
	f.audit = append(f.audit, auditEvent{
		action:       "policy.break_glass_revealed",
		policyNumber: in.GetPolicyNumber(),
		reason:       in.GetReason(),
	})
	return &identityv1.BreakGlassRevealResponse{GrantedUntil: exp.UTC().Format(time.RFC3339)}, nil
}

func (f *rbacBreakGlassAdmin) ActiveBreakGlass(_ context.Context, _ *identityv1.ActiveBreakGlassRequest, _ ...grpc.CallOption) (*identityv1.ActiveBreakGlassResponse, error) {
	f.activeN++
	out := make([]string, 0, len(f.grants))
	nowT := f.clock()
	for num, exp := range f.grants {
		if exp.After(nowT) {
			out = append(out, num)
		}
	}
	return &identityv1.ActiveBreakGlassResponse{PolicyNumbers: out}, nil
}

func (f *rbacBreakGlassAdmin) hasAudit(action string) bool {
	for _, e := range f.audit {
		if e.action == action {
			return true
		}
	}
	return false
}

// secretDoc is a Lexical document whose text must never reach an obfuscated
// viewer. The structure (paragraph node) must survive obfuscation.
const secretDoc = `{"root":{"children":[{"type":"paragraph","children":[{"type":"text","text":"Top secret incident response runbook"}]}],"type":"root","version":1}}`

// TestRBACEnforcement is the consolidated per-authorize()-pathway integration
// suite (plan Task 12). Each subtest drives a real gateway resolver against the
// contract-faithful gRPC fakes (policy + group + identity-admin), exercising the
// authz decision core through the full enforcement wiring.
func TestRBACEnforcement(t *testing.T) {
	t.Run("ExcludedSiteAdmin_ObfuscatedContent", func(t *testing.T) {
		// Exclusion is expressed as a RACI deny-read rule for the site-admin's AD group.
		groups := newRaciReadClient(
			map[string]*corev1.Category{
				"g-it": {Id: "g-it", Name: "IT"},
			},
			map[string][]*corev1.CategoryRule{
				"g-it": {denyGroupRule("SiteAdmins"), allowEveryoneRule()},
			},
		)
		base := &fakePolicyClient{policies: map[string]*corev1.Policy{
			"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec"},
		}}
		pc := &rbacVersionPolicyClient{
			fakePolicyClient: base,
			versions: map[string]*corev1.PolicyVersion{
				"v1": {Id: "v1", PolicyId: "pol-1", VersionNo: 1, ContentJson: secretDoc},
			},
		}
		admin := newRBACBreakGlassAdmin(15 * time.Minute) // no active grant yet
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue:    "sa",
			RolesValue:     []string{"site-admin"},
			IdpGroupsValue: []string{"SiteAdmins"}, // AD group matched by the RACI deny rule
		})

		// viewerCan projection: still visible, but obfuscated.
		p, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, "pol-1")
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if p.ViewerCan == nil || !p.ViewerCan.Read {
			t.Fatalf("RACI-denied site-admin must still see the policy: %+v", p.ViewerCan)
		}
		if !p.ViewerCan.ContentObfuscated {
			t.Fatal("RACI-denied site-admin must get contentObfuscated=true")
		}
		if !p.ViewerCan.CanBreakGlass {
			t.Fatal("obfuscated site-admin must get canBreakGlass=true")
		}

		// Served content is gibberish: the real text never leaks.
		v, err := resolvers.GetPolicyVersion(ctx, pc, groups, admin, "v1")
		if err != nil {
			t.Fatalf("GetPolicyVersion: %v", err)
		}
		if strings.Contains(v.ContentJSON, "secret") || strings.Contains(v.ContentJSON, "runbook") || strings.Contains(v.ContentJSON, "incident") {
			t.Fatalf("real text leaked through obfuscation: %s", v.ContentJSON)
		}
		if !strings.Contains(v.ContentJSON, `"type":"paragraph"`) {
			t.Fatalf("obfuscation destroyed document structure: %s", v.ContentJSON)
		}
	})

	t.Run("BreakGlass_AuditWindowAndExpiry", func(t *testing.T) {
		// Exclusion via RACI deny rule for the site-admin's AD group.
		groups := newRaciReadClient(
			map[string]*corev1.Category{
				"g-it": {Id: "g-it", Name: "IT"},
			},
			map[string][]*corev1.CategoryRule{
				"g-it": {denyGroupRule("SiteAdmins"), allowEveryoneRule()},
			},
		)
		base := &fakePolicyClient{policies: map[string]*corev1.Policy{
			"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "Sec"},
		}}
		pc := &rbacVersionPolicyClient{
			fakePolicyClient: base,
			versions: map[string]*corev1.PolicyVersion{
				"v1": {Id: "v1", PolicyId: "pol-1", VersionNo: 1, ContentJson: secretDoc},
			},
		}
		// Controllable clock so we can step past the grant window deterministically.
		fakeClock := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
		admin := newRBACBreakGlassAdmin(15 * time.Minute)
		admin.now = func() time.Time { return fakeClock }
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue:    "sa",
			RolesValue:     []string{"site-admin"},
			IdpGroupsValue: []string{"SiteAdmins"}, // AD group matched by the RACI deny rule
		})

		// 1. Reveal emits the high-severity audit event and returns grantedUntil.
		res, err := resolvers.BreakGlassRevealResolver(ctx, admin, pc, "pol-1", "investigating incident")
		if err != nil {
			t.Fatalf("BreakGlassRevealResolver: %v", err)
		}
		if res == nil || res.GrantedUntil == "" {
			t.Fatalf("expected grantedUntil; got %+v", res)
		}
		if !admin.hasAudit("policy.break_glass_revealed") {
			t.Fatal("break-glass reveal must emit a policy.break_glass_revealed audit event")
		}

		// 2. Within the window → real content, contentObfuscated=false.
		p, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, "pol-1")
		if err != nil {
			t.Fatalf("GetPolicy (within window): %v", err)
		}
		if p.ViewerCan == nil || p.ViewerCan.ContentObfuscated {
			t.Fatalf("active break-glass must flip contentObfuscated to false: %+v", p.ViewerCan)
		}
		v, err := resolvers.GetPolicyVersion(ctx, pc, groups, admin, "v1")
		if err != nil {
			t.Fatalf("GetPolicyVersion (within window): %v", err)
		}
		if !strings.Contains(v.ContentJSON, "runbook") {
			t.Fatalf("within break-glass window real content must be served; got %s", v.ContentJSON)
		}

		// 3. After expiry → obfuscate again.
		fakeClock = fakeClock.Add(16 * time.Minute)
		p2, err := resolvers.GetPolicy(ctx, pc, groups, admin, nil, "pol-1")
		if err != nil {
			t.Fatalf("GetPolicy (after expiry): %v", err)
		}
		if p2.ViewerCan == nil || !p2.ViewerCan.ContentObfuscated {
			t.Fatalf("after expiry the site-admin must be obfuscated again: %+v", p2.ViewerCan)
		}
		v2, err := resolvers.GetPolicyVersion(ctx, pc, groups, admin, "v1")
		if err != nil {
			t.Fatalf("GetPolicyVersion (after expiry): %v", err)
		}
		if strings.Contains(v2.ContentJSON, "runbook") {
			t.Fatalf("after expiry real content must not leak; got %s", v2.ContentJSON)
		}
	})

	t.Run("ExcludedReader_HiddenFromListAndGet", func(t *testing.T) {
		// Reader is in "Contractors" group, denied read in IT but not HR.
		groups := newRaciReadClient(
			map[string]*corev1.Category{
				"g-it": {Id: "g-it", Name: "IT"},
				"g-hr": {Id: "g-hr", Name: "HR"},
			},
			map[string][]*corev1.CategoryRule{
				"g-it": {denyGroupRule("Contractors"), allowEveryoneRule()},
				"g-hr": {allowEveryoneRule()},
			},
		)
		pc := &fakePolicyClient{
			policies: map[string]*corev1.Policy{
				"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT"},
				"pol-hr": {Id: "pol-hr", HomeCategoryId: "g-hr", Number: "POL-HR-1", Title: "HR"},
			},
			listResult: []string{"pol-it", "pol-hr"},
		}
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue:    "r",
			RolesValue:     []string{"reader"},
			IdpGroupsValue: []string{"Contractors"}, // AD group matched by the RACI deny rule in IT
		})

		// List omits the RACI-denied policy, keeps the visible one.
		out, err := resolvers.ListPolicies(ctx, pc, groups, nil, nil, "g-it", boolPtr(true), nil)
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		for _, p := range out {
			if p.ID == "pol-it" {
				t.Fatal("RACI-denied reader's policy must be filtered from the list")
			}
		}
		seenHR := false
		for _, p := range out {
			if p.ID == "pol-hr" {
				seenHR = true
			}
		}
		if !seenHR {
			t.Fatal("a visible policy must remain in the list")
		}

		// GetPolicy on the hidden policy → NotFound (existence not leaked).
		if _, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it"); status.Code(err) != codes.NotFound {
			t.Fatalf("RACI-denied GetPolicy must be NotFound; got %v", err)
		}
	})

	t.Run("ScopedAuthor_EditOnlyInCategory", func(t *testing.T) {
		groups := newRaciReadClient(
			map[string]*corev1.Category{
				"g-it": {Id: "g-it", Name: "IT"},
				"g-hr": {Id: "g-hr", Name: "HR"},
			},
			map[string][]*corev1.CategoryRule{
				"g-it": {allowEveryoneRule()},
				"g-hr": {allowEveryoneRule()},
			},
		)
		pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
			"pol-it": {Id: "pol-it", HomeCategoryId: "g-it", Number: "POL-IT-1", Title: "IT"},
			"pol-hr": {Id: "pol-hr", HomeCategoryId: "g-hr", Number: "POL-HR-1", Title: "HR"},
		}}
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue:      "auth",
			RolesValue:       []string{"author"},
			ScopedRolesValue: []principal.ScopedRole{{Role: "author", Category: "IT"}},
		})

		itp, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-it")
		if err != nil {
			t.Fatalf("GetPolicy IT: %v", err)
		}
		if itp.ViewerCan == nil || !itp.ViewerCan.Edit {
			t.Fatalf("scoped author in-category must have edit=true: %+v", itp.ViewerCan)
		}
		hrp, err := resolvers.GetPolicy(ctx, pc, groups, nil, nil, "pol-hr")
		if err != nil {
			t.Fatalf("GetPolicy HR: %v", err)
		}
		if hrp.ViewerCan == nil || hrp.ViewerCan.Edit {
			t.Fatalf("scoped author out-of-category must have edit=false: %+v", hrp.ViewerCan)
		}
	})

	t.Run("SensitivePolicy_HiddenWithoutClearance", func(t *testing.T) {
		groups := newRaciReadClient(
			map[string]*corev1.Category{
				"g-it": {Id: "g-it", Name: "IT"},
			},
			map[string][]*corev1.CategoryRule{
				"g-it": {allowEveryoneRule()}, // everyone allowed on merit; sensitivity gate still applies
			},
		)
		pc := &fakePolicyClient{
			policies: map[string]*corev1.Policy{
				"pol-sens": {Id: "pol-sens", HomeCategoryId: "g-it", Number: "POL-IT-9", Title: "Sensitive", Sensitivity: corev1.Sensitivity_SENSITIVITY_SENSITIVE},
			},
			listResult: []string{"pol-sens"},
		}

		// A plain reader (no read_sensitive) → hidden by sensitivity gate: list-filtered + NotFound.
		readerCtx := ctxWithStubClaims(t, principal.Static{
			UserIDValue: "r",
			RolesValue:  []string{"reader"},
		})
		out, err := resolvers.ListPolicies(readerCtx, pc, groups, nil, nil, "g-it", boolPtr(true), nil)
		if err != nil {
			t.Fatalf("ListPolicies (reader): %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("sensitive policy must be hidden from a reader without clearance; got %d", len(out))
		}
		if _, err := resolvers.GetPolicy(readerCtx, pc, groups, nil, nil, "pol-sens"); status.Code(err) != codes.NotFound {
			t.Fatalf("sensitive GetPolicy without clearance must be NotFound; got %v", err)
		}

		// A compliance-admin holds policy.read_sensitive via the role map → visible.
		clearedCtx := ctxWithStubClaims(t, principal.Static{
			UserIDValue: "ca",
			RolesValue:  []string{"compliance-admin"},
		})
		visible, err := resolvers.ListPolicies(clearedCtx, pc, groups, nil, nil, "g-it", boolPtr(true), nil)
		if err != nil {
			t.Fatalf("ListPolicies (compliance-admin): %v", err)
		}
		if len(visible) != 1 || visible[0].ID != "pol-sens" {
			t.Fatalf("read_sensitive holder must see the sensitive policy; got %+v", visible)
		}
		p, err := resolvers.GetPolicy(clearedCtx, pc, groups, nil, nil, "pol-sens")
		if err != nil {
			t.Fatalf("GetPolicy (compliance-admin): %v", err)
		}
		if p.ViewerCan == nil || !p.ViewerCan.Read || p.ViewerCan.ContentObfuscated {
			t.Fatalf("cleared viewer must read sensitive content unobfuscated: %+v", p.ViewerCan)
		}
	})

	t.Run("BreakGlassReveal_EmptyReason_InvalidArgument", func(t *testing.T) {
		pc := &fakePolicyClient{policies: map[string]*corev1.Policy{
			"pol-1": {Id: "pol-1", HomeCategoryId: "g-it", Number: "POL-IT-1"},
		}}
		admin := newRBACBreakGlassAdmin(15 * time.Minute)
		ctx := ctxWithStubClaims(t, principal.Static{
			UserIDValue: "sa",
			RolesValue:  []string{"site-admin"},
		})
		_, err := resolvers.BreakGlassRevealResolver(ctx, admin, pc, "pol-1", "")
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("empty reason must yield InvalidArgument; got %v", err)
		}
		if len(admin.audit) != 0 {
			t.Fatalf("no grant/audit may be emitted for a rejected empty-reason reveal: %+v", admin.audit)
		}
	})
}
