// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPublicQuery(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"globalSettings", `{"query":"query { globalSettings { maintenance { enabled } } }"}`, true},
		{"typename", `{"query":"{ __typename }"}`, true},
		{"introspection schema now gated", `{"query":"{ __schema { types { name } } }"}`, false},
		{"introspection __type now gated", `{"query":"{ __type(name:\"Query\"){ name } }"}`, false},
		{"named public op", `{"query":"query Boot { globalSettings { announcement { enabled } } }","operationName":"Boot"}`, true},
		{"protected field", `{"query":"{ me { id } }"}`, false},
		{"mixed public+protected", `{"query":"{ globalSettings { maintenance { enabled } } me { id } }"}`, false},
		{"mutation", `{"query":"mutation { updateGlobalSettings(input:{}) { maintenance { enabled } } }"}`, false},
		{"anonymous report", `{"query":"mutation { submitAnonymousReport(input:{}) { caseCode } }"}`, true},
		{"anonymous check", `{"query":"mutation Check { checkReport(input:{}) { status } }","operationName":"Check"}`, true},
		{"anonymous reply", `{"query":"mutation { replyToReport(input:{}) { ok } }"}`, true},
		{"anonymous op mixed with a protected one", `{"query":"mutation { replyToReport(input:{}) { ok } recordAck(policyVersionId:\"v\") { id } }"}`, false},
		{"anonymous op name used as a query", `{"query":"query { checkReport { status } }"}`, false},
		{"public query name used as a mutation", `{"query":"mutation { globalSettings { maintenance { enabled } } }"}`, false},
		{"empty query", `{"query":""}`, false},
		{"batch array", `[{"query":"{ __typename }"}]`, false},
		{"garbage", `not json`, false},
		{"unparseable graphql", `{"query":"query { "}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPublicQuery([]byte(c.body)); got != c.want {
				t.Fatalf("isPublicQuery(%s) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestPublicOpsRouting(t *testing.T) {
	mark := func(tag string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prove the body survives classification and is readable downstream.
			b, _ := readAll(r)
			w.Header().Set("X-Route", tag)
			w.Header().Set("X-Body-Len", itoa(len(b)))
			w.WriteHeader(http.StatusOK)
		})
	}
	h := PublicOps(mark("auth"), mark("public"))

	tests := []struct {
		name, body, wantRoute string
	}{
		{"public op bypasses auth", `{"query":"{ __typename }"}`, "public"},
		{"public banner query", `{"query":"query { globalSettings { maintenance { enabled } } }"}`, "public"},
		{"protected op hits auth", `{"query":"{ me { id } }"}`, "auth"},
		{"anonymous report bypasses auth", `{"query":"mutation { submitAnonymousReport(input:{}) { caseCode } }"}`, "public"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/query", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if got := rec.Header().Get("X-Route"); got != tc.wantRoute {
				t.Fatalf("route = %q, want %q", got, tc.wantRoute)
			}
			if rec.Header().Get("X-Body-Len") == "0" {
				t.Fatal("downstream handler saw an empty body — PublicOps did not reset r.Body")
			}
		})
	}
}

// small helpers to avoid extra imports in the test handler
func readAll(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
