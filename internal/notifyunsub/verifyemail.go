// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package notifyunsub

import (
	"context"
	"net/http"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Steward-GRC/steward-gateway/internal/errcodes"
)

// EmailVerifier is the narrow slice of identityv1.IdentityReadServiceClient the
// verify-email handler needs: persist that (user_id, email) proved control of
// the mailbox. The real gRPC client satisfies it; tests supply a fake.
type EmailVerifier interface {
	MarkEmailVerified(ctx context.Context, in *identityv1.MarkEmailVerifiedRequest, opts ...grpc.CallOption) (*identityv1.MarkEmailVerifiedResponse, error)
}

// VerifyEmailHandlers serves the unauthenticated email-address verification
// endpoint — the counterpart to this
// package's one-click unsubscribe handler. A "verify your email" CTA click
// arrives with the signed token obligations minted at send time; the
// handler verifies it here with the SAME NOTIFY_UNSUB_SECRET (via the shared
// *Verifier) and, on success, calls identity to mark the address verified.
// It renders a small self-contained result page for every outcome — mirroring
// the SSO test-result page pattern — so a mail-client click always lands on a
// friendly page rather than a bare error.
type VerifyEmailHandlers struct {
	verifier *Verifier
	identity EmailVerifier
	log      log.Logger
}

// NewVerifyEmail returns handlers wired to the shared token verifier and the
// identity read client (MarkEmailVerified).
func NewVerifyEmail(verifier *Verifier, identity EmailVerifier) *VerifyEmailHandlers {
	return &VerifyEmailHandlers{verifier: verifier, identity: identity}
}

// WithLogger sets the logger. Returns the receiver for chaining.
func (h *VerifyEmailHandlers) WithLogger(l log.Logger) *VerifyEmailHandlers {
	h.log = l
	return h
}

func (h *VerifyEmailHandlers) logger(ctx context.Context) log.Logger {
	if h.log == nil {
		return log.Nop()
	}
	return h.log.Ctx(ctx)
}

// Handler serves GET /notify/verify-email?token=... — the browser path a
// recipient reaches by clicking the "verify your email" button. It verifies the
// PurposeEmailVerify token, persists the verification via identity, and renders
// the matching result page. It never requires a session: the signed token is
// the credential, exactly like the unsubscribe endpoint.
func (h *VerifyEmailHandlers) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		claims, err := h.verifier.Verify(token, PurposeEmailVerify)
		if err != nil {
			writeVerifyResult(w, http.StatusBadRequest, resultInvalid)
			return
		}

		resp, err := h.identity.MarkEmailVerified(r.Context(), &identityv1.MarkEmailVerifiedRequest{
			UserId: claims.UserID,
			Email:  claims.Email,
		})
		switch status.Code(err) {
		case codes.OK:
			if resp.GetAlreadyVerified() {
				writeVerifyResult(w, http.StatusOK, resultAlready)
				return
			}
			writeVerifyResult(w, http.StatusOK, resultSuccess)
		case codes.FailedPrecondition, codes.NotFound, codes.InvalidArgument:
			writeVerifyResult(w, http.StatusBadRequest, resultInvalid)
		default:
			h.logger(r.Context()).Error(err, "notify/verify-email: persist verified failed", log.F("error_code", errcodes.CodeNotifyVerifyEmailPersistFailed))
			writeVerifyResult(w, http.StatusBadGateway, resultError)
		}
	}
}

// verifyResult enumerates the four rendered outcomes.
type verifyResult int

const (
	resultSuccess verifyResult = iota // freshly verified
	resultAlready                     // already verified (idempotent)
	resultInvalid                     // bad/expired token, or link no longer valid
	resultError                       // transient server-side failure
)

// writeVerifyResult renders the small self-contained result page for outcome
// with the given HTTP status. The pages carry no user-supplied input, so there
// is nothing to escape.
func writeVerifyResult(w http.ResponseWriter, statusCode int, outcome verifyResult) {
	var heading, body string
	switch outcome {
	case resultSuccess:
		heading = "Email verified"
		body = "Thanks — your email address is now verified. You can close this window."
	case resultAlready:
		heading = "Already verified"
		body = "This email address was already verified. You can close this window."
	case resultInvalid:
		heading = "This link is no longer valid"
		body = "This verification link is invalid, has expired, or was already superseded. If you still need to verify your email, request a new link."
	case resultError:
		heading = "Something went wrong"
		body = "We couldn't verify your email just now. Please try the link again in a few minutes."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(verifyResultPage(heading, body)))
}

// verifyResultPage returns a minimal branded result page. heading and body are
// static, handler-controlled strings (never user input).
func verifyResultPage(heading, body string) string {
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>` + heading + `</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #f5f6f8; color: #1f2933; }
  .card { max-width: 28rem; margin: 1rem; padding: 2rem; background: #fff; border-radius: 12px;
          box-shadow: 0 1px 3px rgba(0,0,0,.12), 0 1px 2px rgba(0,0,0,.08); }
  h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
  p  { font-size: .95rem; line-height: 1.5; margin: 0; color: #52606d; }
  @media (prefers-color-scheme: dark) {
    body { background: #1f2933; color: #e4e7eb; }
    .card { background: #323f4b; }
    p { color: #cbd2d9; }
  }
</style></head>
<body><main class="card"><h1>` + heading + `</h1><p>` + body + `</p></main></body></html>`
}
