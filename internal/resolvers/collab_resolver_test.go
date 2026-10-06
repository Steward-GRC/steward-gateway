// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	collabv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/collab/v1"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeCollabClient is a minimal stub of collabv1.CollabTokenServiceClient.
// Mirrors the in-package fake style of fakeCategoryClient.
type fakeCollabClient struct {
	collabv1.CollabTokenServiceClient
	lastReq   *collabv1.IssueTokenRequest
	lastActor string
	resp      *collabv1.IssueTokenResponse
	err       error
}

func (f *fakeCollabClient) IssueToken(ctx context.Context, in *collabv1.IssueTokenRequest, _ ...grpc.CallOption) (*collabv1.IssueTokenResponse, error) {
	f.lastReq = in
	if a, ok := grpcactor.FromContext(ctx); ok {
		f.lastActor = a.Subject
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// collabTokenInput is the fixed request shape used by the IssueCollabToken
// tests against the policy "pol" that coAuthMatrixEnv builds. It is the
// TEMPLATED shape; see freeFormCollabTokenInput for the free-form one.
func collabTokenInput() resolvers.IssueCollabTokenInput {
	tv := "tv-1"
	return resolvers.IssueCollabTokenInput{
		PolicyID:          "pol",
		DraftID:           "d-1",
		TemplateVersionID: &tv,
	}
}

// freeFormCollabTokenInput is the same request for a policy with no pinned
// template — the normal case. templateVersionId is nullable in the
// SDL, so a client expresses "no template" by omitting it.
func freeFormCollabTokenInput() resolvers.IssueCollabTokenInput {
	return resolvers.IssueCollabTokenInput{
		PolicyID: "pol",
		DraftID:  "d-1",
	}
}

func TestIssueCollabTokenHappyPath(t *testing.T) {
	expires := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	client := &fakeCollabClient{
		resp: &collabv1.IssueTokenResponse{
			Token:     "jwt-abc",
			WsUrl:     "wss://collab.example.org/ws/d1",
			ExpiresAt: timestamppb.New(expires),
		},
	}

	// Primary author of "pol" — authorized by the effective-author gate.
	pc, gc := coAuthMatrixEnv("u-7", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-7", RolesValue: []string{"reader"}})

	payload, err := resolvers.IssueCollabToken(ctx, client, pc, gc, collabTokenInput())
	if err != nil {
		t.Fatalf("IssueCollabToken: %v", err)
	}
	if payload.Token != "jwt-abc" {
		t.Fatalf("token: got %q want %q", payload.Token, "jwt-abc")
	}
	if payload.WsURL != "wss://collab.example.org/ws/d1" {
		t.Fatalf("ws url: got %q", payload.WsURL)
	}
	if payload.ExpiresAt != "2026-05-31T12:00:00Z" {
		t.Fatalf("expires_at: got %q want RFC3339 UTC", payload.ExpiresAt)
	}

	// The token is minted for the signed-in caller, carried as the
	// go-grpc-actor actor, never for an id from the input. If a future refactor lets the
	// input override it, this assertion catches the security regression.
	if client.lastReq == nil {
		t.Fatal("expected IssueToken to be invoked")
	}
	if client.lastActor != "u-7" {
		t.Fatalf("actor: got %q want %q", client.lastActor, "u-7")
	}
	if client.lastReq.PolicyId != "pol" || client.lastReq.DraftId != "d-1" || client.lastReq.TemplateVersionId != "tv-1" {
		t.Fatalf("request fields not forwarded: %+v", client.lastReq)
	}
}

func TestIssueCollabTokenUnauthenticated(t *testing.T) {
	client := &fakeCollabClient{}
	pc, gc := coAuthMatrixEnv("creator-other", nil, nil)
	_, err := resolvers.IssueCollabToken(context.Background(), client, pc, gc, collabTokenInput())
	if err == nil {
		t.Fatal("expected unauthenticated error when no claims on context")
	}
	if client.lastReq != nil {
		t.Fatalf("IssueToken should not be invoked without claims; got %+v", client.lastReq)
	}
}

func TestIssueCollabTokenPropagatesGRPCError(t *testing.T) {
	rpcErr := errors.New("boom")
	client := &fakeCollabClient{err: rpcErr}
	pc, gc := coAuthMatrixEnv("u-1", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-1", RolesValue: []string{"reader"}})
	_, err := resolvers.IssueCollabToken(ctx, client, pc, gc, collabTokenInput())
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !errors.Is(err, rpcErr) {
		t.Fatalf("expected wrapped rpcErr; got %v", err)
	}
}

// TestIssueCollabToken_EffectiveAuthorGate proves Phase 0 (spec
// §3.5/§7.1): the token mint is gated by the SAME deny-aware effective-author
// model as SaveDraft. A non-effective-author (including one DENIED by RACI) is
// refused with PermissionDenied and the collab service is never called; an
// authorized author gets a token. Mirrors TestCoAuthoring_EditMatrix.
func TestIssueCollabToken_EffectiveAuthorGate(t *testing.T) {
	cases := []struct {
		name      string
		claims    principal.Static
		owners    []string
		primary   string
		rules     []*corev1.CategoryRule
		wantAllow bool
	}{
		{
			name:      "primary author may open a room",
			claims:    principal.Static{UserIDValue: "creator-u", RolesValue: []string{"reader"}},
			primary:   "creator-u",
			wantAllow: true,
		},
		{
			name:      "non-denied category author may open a room",
			claims:    principal.Static{UserIDValue: "coauthor-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("coauthor-u", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: true,
		},
		{
			name:      "site-admin may open a room (deny never applies)",
			claims:    principal.Static{UserIDValue: "admin-u", RolesValue: []string{"site-admin"}},
			rules:     []*corev1.CategoryRule{authorRule("admin-u", corev1.GrantEffect_GRANT_EFFECT_DENY)},
			wantAllow: true,
		},
		{
			name:      "RACI-denied author is refused a room",
			claims:    principal.Static{UserIDValue: "denied-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("denied-u", corev1.GrantEffect_GRANT_EFFECT_DENY)},
			wantAllow: false,
		},
		{
			name:      "non-author is refused a room",
			claims:    principal.Static{UserIDValue: "stranger-u", RolesValue: []string{"reader"}},
			rules:     []*corev1.CategoryRule{authorRule("someone-else", corev1.GrantEffect_GRANT_EFFECT_ALLOW)},
			wantAllow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := tc.primary
			if primary == "" {
				primary = "creator-other"
			}
			pc, gc := coAuthMatrixEnv(primary, tc.owners, tc.rules)
			client := &fakeCollabClient{resp: &collabv1.IssueTokenResponse{
				Token:     "jwt-ok",
				WsUrl:     "wss://collab.example.org/ws/d-1",
				ExpiresAt: timestamppb.New(time.Now()),
			}}
			ctx := ctxWithStubClaims(t, tc.claims)

			_, err := resolvers.IssueCollabToken(ctx, client, pc, gc, collabTokenInput())
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected mint allowed, got %v", err)
				}
				if client.lastReq == nil {
					t.Fatal("expected collab IssueToken to be called")
				}
				if client.lastActor != tc.claims.UserIDValue {
					t.Fatalf("bound uid: got %q want %q", client.lastActor, tc.claims.UserIDValue)
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("expected PermissionDenied, got %v", err)
				}
				if client.lastReq != nil {
					t.Fatal("collab IssueToken must NOT be called when denied")
				}
			}
		})
	}
}

// TestIssueCollabTokenFreeFormPolicy is the gateway half. Before the
// fix templateVersionId was ID! in the SDL, so a client could not even express
// "this policy has no template" — which is most policies. It is now nullable,
// and a null/omitted value must reach collab as the empty sentinel, never as a
// substituted or invented template id.
func TestIssueCollabTokenFreeFormPolicy(t *testing.T) {
	expires := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	client := &fakeCollabClient{
		resp: &collabv1.IssueTokenResponse{
			Token:     "jwt-freeform",
			WsUrl:     "wss://collab.example.org/ws/d1",
			ExpiresAt: timestamppb.New(expires),
		},
	}

	pc, gc := coAuthMatrixEnv("u-7", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-7", RolesValue: []string{"reader"}})

	payload, err := resolvers.IssueCollabToken(ctx, client, pc, gc, freeFormCollabTokenInput())
	if err != nil {
		t.Fatalf("IssueCollabToken for a free-form policy: %v", err)
	}
	if payload.Token != "jwt-freeform" {
		t.Fatalf("token: got %q want %q", payload.Token, "jwt-freeform")
	}
	if client.lastReq == nil {
		t.Fatal("expected IssueToken to be invoked")
	}
	if client.lastReq.TemplateVersionId != "" {
		t.Fatalf("template_version_id: got %q want empty -- a template must never be invented",
			client.lastReq.TemplateVersionId)
	}
	// The rest of the request is unaffected, including the server-bound uid.
	if client.lastActor != "u-7" || client.lastReq.PolicyId != "pol" || client.lastReq.DraftId != "d-1" {
		t.Fatalf("request fields not forwarded: %+v", client.lastReq)
	}
}

// TestIssueCollabTokenFreeFormStillGated confirms making the field nullable did
// not open a hole in the authoring gate: a caller who is not an effective
// author of a FREE-FORM policy is still refused, and collab is never called.
func TestIssueCollabTokenFreeFormStillGated(t *testing.T) {
	client := &fakeCollabClient{}
	pc, gc := coAuthMatrixEnv("someone-else", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-nobody", RolesValue: []string{"reader"}})

	if _, err := resolvers.IssueCollabToken(ctx, client, pc, gc, freeFormCollabTokenInput()); err == nil {
		t.Fatal("expected the effective-author gate to refuse a non-author, got nil")
	}
	if client.lastReq != nil {
		t.Fatalf("collab must not be called when the gate refuses; got %+v", client.lastReq)
	}
}

// TestIssueCollabTokenExplicitEmptyTemplateVersion covers the other way a
// client can say "no template": sending templateVersionId: "" rather than
// omitting it. Both must collapse to the same empty sentinel downstream.
func TestIssueCollabTokenExplicitEmptyTemplateVersion(t *testing.T) {
	client := &fakeCollabClient{
		resp: &collabv1.IssueTokenResponse{Token: "t", WsUrl: "wss://x/ws/d1"},
	}
	pc, gc := coAuthMatrixEnv("u-7", nil, nil)
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "u-7", RolesValue: []string{"reader"}})

	empty := ""
	in := resolvers.IssueCollabTokenInput{PolicyID: "pol", DraftID: "d-1", TemplateVersionID: &empty}
	if _, err := resolvers.IssueCollabToken(ctx, client, pc, gc, in); err != nil {
		t.Fatalf("IssueCollabToken: %v", err)
	}
	if client.lastReq == nil {
		t.Fatal("expected IssueToken to be invoked")
	}
	if client.lastReq.TemplateVersionId != "" {
		t.Fatalf("template_version_id: got %q want empty", client.lastReq.TemplateVersionId)
	}
}
