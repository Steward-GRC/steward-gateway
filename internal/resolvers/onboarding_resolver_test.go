// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCompleteOnboardingResolver_RequiresAuth(t *testing.T) {
	admin := &fakeAdminClient{}
	_, err := resolvers.CompleteOnboardingResolver(context.Background(), admin, true, nil, nil, nil, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without claims, got %v", err)
	}
}

func TestCompleteOnboardingResolver_ForwardsAndMaps(t *testing.T) {
	// A plain authenticated user (no site-admin role) — proves caller-scoping.
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "user-1"})
	// name is the DERIVED display name (first + last); it is returned by identity
	// but never sent by the resolver.
	name := "Alice Example"
	uname := "alice"
	first := "Alice"
	last := "Example"
	email := "alice@example.org"
	admin := &fakeAdminClient{
		completeOnboardingResp: &identityv1.CompleteOnboardingResponse{
			User: &identityv1.User{Id: "user-1", Name: name, FirstName: first, LastName: last, Email: email, Username: uname, NeedsOnboarding: false},
		},
	}
	got, err := resolvers.CompleteOnboardingResolver(ctx, admin, true, &uname, &first, &last, &email)
	if err != nil {
		t.Fatalf("CompleteOnboardingResolver: %v", err)
	}
	// Input forwarded (presence preserved).
	if admin.lastCompleteOnboarding == nil || !admin.lastCompleteOnboarding.GetAcceptTerms() {
		t.Fatal("expected accept_terms=true forwarded")
	}
	// The display name is derived server-side — the resolver must NOT forward it.
	if admin.lastCompleteOnboarding.Name != nil {
		t.Fatalf("name must not be forwarded (derived server-side): %+v", admin.lastCompleteOnboarding)
	}
	if admin.lastCompleteOnboarding.GetUsername() != uname {
		t.Fatalf("username not forwarded: %+v", admin.lastCompleteOnboarding)
	}
	if admin.lastCompleteOnboarding.GetFirstName() != first || admin.lastCompleteOnboarding.GetLastName() != last || admin.lastCompleteOnboarding.GetEmail() != email {
		t.Fatalf("first/last/email not forwarded: %+v", admin.lastCompleteOnboarding)
	}
	// Response mapped onto the GraphQL User.
	if got.NeedsOnboarding {
		t.Fatal("expected needsOnboarding=false")
	}
	if got.Username != uname || got.Name != name {
		t.Fatalf("mapped user mismatch: %+v", got)
	}
	if got.FirstName != first || got.LastName != last {
		t.Fatalf("first/last not mapped onto GraphQL user: %+v", got)
	}
}
