// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// latestVersionFake wraps the visibility fake and answers GetLatestTemplateVersion from a canned
// reply, so each test chooses what core says for the version lookup.
type latestVersionFake struct {
	*labelTemplateFake
	resp  *corev1.GetLatestTemplateVersionResponse
	err   error
	calls int
}

func (f *latestVersionFake) GetLatestTemplateVersion(context.Context, *corev1.GetLatestTemplateVersionRequest, ...grpc.CallOption) (*corev1.GetLatestTemplateVersionResponse, error) {
	f.calls++
	return f.resp, f.err
}

// A template with only a draft has no published version: core answers NotFound and the nullable
// field must come back as null, not as a GraphQL error.
func TestLatestTemplateVersion_NotFoundFromCoreIsNil(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	fake := &latestVersionFake{labelTemplateFake: tc, err: status.Error(codes.NotFound, "template version not found")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	got, err := resolvers.LatestTemplateVersion(ctx, log.Nop(), fake, gc, "TPL-A")
	if err != nil {
		t.Fatalf("NotFound from core must map to a nil result without error; got %v", err)
	}
	if got != nil {
		t.Fatalf("expected a nil version; got %+v", got)
	}
	if fake.calls != 1 {
		t.Fatalf("expected one core lookup; got %d", fake.calls)
	}
}

func TestLatestTemplateVersion_PublishedVersionReturned(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	fake := &latestVersionFake{
		labelTemplateFake: tc,
		resp:              &corev1.GetLatestTemplateVersionResponse{Version: &corev1.TemplateVersion{Id: "TV-A2", TemplateId: "TPL-A", VersionNo: 2}},
	}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	got, err := resolvers.LatestTemplateVersion(ctx, log.Nop(), fake, gc, "TPL-A")
	if err != nil {
		t.Fatalf("LatestTemplateVersion: %v", err)
	}
	if got == nil || got.ID != "TV-A2" {
		t.Fatalf("expected version TV-A2; got %+v", got)
	}
}

// Any other core failure stays an error.
func TestLatestTemplateVersion_OtherCoreErrorStaysError(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	fake := &latestVersionFake{labelTemplateFake: tc, err: status.Error(codes.Internal, "boom")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	got, err := resolvers.LatestTemplateVersion(ctx, log.Nop(), fake, gc, "TPL-A")
	if status.Code(err) != codes.Internal {
		t.Fatalf("Internal from core must stay an error; got %v", err)
	}
	if got != nil {
		t.Fatalf("expected no version on error; got %+v", got)
	}
}

// The read gate runs first: a template the caller may not read, or that does not exist, keeps its
// PermissionDenied and never reaches the version lookup, even if core would answer NotFound.
func TestLatestTemplateVersion_UnreadableTemplateStaysDenied(t *testing.T) {
	tc, gc := templateVisibilityEnv("author-a")
	fake := &latestVersionFake{labelTemplateFake: tc, err: status.Error(codes.NotFound, "template version not found")}
	ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

	for _, id := range []string{"TPL-B", "TPL-MISSING"} {
		got, err := resolvers.LatestTemplateVersion(ctx, log.Nop(), fake, gc, id)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: expected PermissionDenied; got %v", id, err)
		}
		if got != nil {
			t.Fatalf("%s: expected no version; got %+v", id, got)
		}
	}
	if fake.calls != 0 {
		t.Fatalf("the version lookup must not run for an unreadable template; got %d calls", fake.calls)
	}
}
