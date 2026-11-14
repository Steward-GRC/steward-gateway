// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"testing"

	log "github.com/Bugs5382/go-log"
	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-gateway/internal/principal"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TemplateVersion.status is spelled in lower case (draft, published, archived),
// the way the mock server and the admin template page spell it, and never as
// core's enum name.
func TestTemplateVersionStatus_LowerCaseWords(t *testing.T) {
	cases := []struct {
		name string
		in   corev1.TemplateVersionStatus
		want string
	}{
		{"draft", corev1.TemplateVersionStatus_TEMPLATE_VERSION_STATUS_DRAFT, "draft"},
		{"published", corev1.TemplateVersionStatus_TEMPLATE_VERSION_STATUS_PUBLISHED, "published"},
		{"archived", corev1.TemplateVersionStatus_TEMPLATE_VERSION_STATUS_ARCHIVED, "archived"},
		{"unspecified", corev1.TemplateVersionStatus_TEMPLATE_VERSION_STATUS_UNSPECIFIED, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpl, gc := templateVisibilityEnv("author-a")
			fake := &latestVersionFake{
				labelTemplateFake: tpl,
				resp:              &corev1.GetLatestTemplateVersionResponse{Version: &corev1.TemplateVersion{Id: "TV-A1", TemplateId: "TPL-A", Status: tc.in}},
			}
			ctx := ctxWithStubClaims(t, principal.Static{UserIDValue: "author-a", RolesValue: []string{"reader"}})

			got, err := resolvers.LatestTemplateVersion(ctx, log.Nop(), fake, gc, "TPL-A")
			if err != nil {
				t.Fatalf("LatestTemplateVersion: %v", err)
			}
			if got == nil || got.Status != tc.want {
				t.Fatalf("status = %+v, want %q", got, tc.want)
			}
		})
	}
}
