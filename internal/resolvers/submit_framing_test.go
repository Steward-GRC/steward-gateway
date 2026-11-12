// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"encoding/json"
	"strings"
	"testing"

	aiv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/ai/v1"
	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

type framingPayload struct {
	Framing       *string `json:"framing"`
	CustomFraming *string `json:"customFraming"`
}

func framingPtr(f resolvers.DraftFraming) *resolvers.DraftFraming { return &f }
func strPtr(s string) *string                                     { return &s }

type framingCase struct {
	name       string
	framing    *resolvers.DraftFraming
	custom     *string
	wantFrame  string // "" means key absent
	wantCustom string // "" means key absent
	wantErr    string // substring; "" means success
}

func framingCases() []framingCase {
	return []framingCase{
		{name: "omitted", framing: nil},
		{name: "plain", framing: framingPtr(resolvers.DraftFramingPlain), wantFrame: "PLAIN"},
		{name: "professional", framing: framingPtr(resolvers.DraftFramingProfessional), wantFrame: "PROFESSIONAL"},
		{name: "formal", framing: framingPtr(resolvers.DraftFramingFormal), wantFrame: "FORMAL"},
		{name: "custom", framing: framingPtr(resolvers.DraftFramingCustom), custom: strPtr("  Warm and direct, for new hires  "), wantFrame: "CUSTOM", wantCustom: "Warm and direct, for new hires"},
		{name: "custom at limit", framing: framingPtr(resolvers.DraftFramingCustom), custom: strPtr(strings.Repeat("é", 500)), wantFrame: "CUSTOM", wantCustom: strings.Repeat("é", 500)},
		{name: "wording ignored without custom", framing: framingPtr(resolvers.DraftFramingPlain), custom: strPtr("ignore me"), wantFrame: "PLAIN"},
		{name: "wording alone is ignored", framing: nil, custom: strPtr("ignore me")},
		{name: "custom missing wording", framing: framingPtr(resolvers.DraftFramingCustom), wantErr: "custom framing needs wording"},
		{name: "custom blank wording", framing: framingPtr(resolvers.DraftFramingCustom), custom: strPtr("  \n "), wantErr: "custom framing needs wording"},
		{name: "custom too long", framing: framingPtr(resolvers.DraftFramingCustom), custom: strPtr(strings.Repeat("a", 501)), wantErr: "limit is 500"},
		{name: "unknown framing", framing: framingPtr(resolvers.DraftFraming("LOUD")), wantErr: "unknown framing"},
	}
}

func checkFraming(t *testing.T, c framingCase, client *fakeAIClient, err error) {
	t.Helper()
	if c.wantErr != "" {
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("want error containing %q, got %v", c.wantErr, err)
		}
		if client.lastSubmitReq != nil {
			t.Fatal("job submitted despite invalid framing")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var p framingPayload
	if e := json.Unmarshal([]byte(client.lastSubmitReq.InputJson), &p); e != nil {
		t.Fatalf("input_json: %v", e)
	}
	got := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	if got(p.Framing) != c.wantFrame || got(p.CustomFraming) != c.wantCustom {
		t.Fatalf("framing=%q custom=%q, want %q / %q (%s)", got(p.Framing), got(p.CustomFraming), c.wantFrame, c.wantCustom, client.lastSubmitReq.InputJson)
	}
	if c.wantFrame == "" && strings.Contains(client.lastSubmitReq.InputJson, "raming") {
		t.Fatalf("framing keys must be absent: %s", client.lastSubmitReq.InputJson)
	}
}

func TestSubmitDraftGenerationResolver_framing(t *testing.T) {
	for _, c := range framingCases() {
		t.Run(c.name, func(t *testing.T) {
			client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "j"}}
			_, err := resolvers.SubmitDraftGenerationResolver(ctxWithUser(t, "u-1"), client, aiReadableCategory("g-1"), nil,
				resolvers.SubmitDraftGenerationInput{Brief: "b", Framing: c.framing, CustomFraming: c.custom})
			checkFraming(t, c, client, err)
		})
	}
}

func TestSubmitPolicyRevisionResolver_framing(t *testing.T) {
	for _, c := range framingCases() {
		t.Run(c.name, func(t *testing.T) {
			client := &fakeAIClient{submitResp: &aiv1.SubmitAIJobResponse{JobId: "j"}}
			_, err := resolvers.SubmitPolicyRevisionResolver(ctxWithUser(t, "u-1"), client, aiReadableCategory("g-1"), nil,
				resolvers.SubmitPolicyRevisionInput{PolicyID: "p", VersionID: "v", Instruction: "i", Framing: c.framing, CustomFraming: c.custom})
			checkFraming(t, c, client, err)
		})
	}
}
