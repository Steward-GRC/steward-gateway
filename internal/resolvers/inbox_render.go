// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import "fmt"

// noticePolicy is the policy a notice is about, as far as the caller may know
// it: the title and number are left empty when the caller cannot read the
// policy or core could not say.
type noticePolicy struct {
	number string
	title  string
}

// noticeWords is how one kind reads in the bell. It is the wording the mock's
// seed notices show (steward-mock-server src/product/data/notices.ts); the
// kinds the mock does not seed follow the same pattern. line takes the policy's
// title when it has one; plain is the line without it.
type noticeWords struct {
	title string
	line  func(title string) string
	plain string
	// approval is true for a notice that opens the approval, not the policy.
	approval bool
}

func withTitle(format string) func(string) string {
	return func(title string) string { return fmt.Sprintf(format, title) }
}

// noticeCatalog is keyed by the notification-type taxonomy kind.
var noticeCatalog = map[string]noticeWords{
	"ack-required":        {title: "Acknowledgement required", line: withTitle("Please read and acknowledge the %s."), plain: "Please read and acknowledge a policy."},
	"policy-ack-reminder": {title: "Acknowledgement reminder", line: withTitle("The %s is still waiting for your acknowledgement."), plain: "A policy is still waiting for your acknowledgement."},
	"policy-escalation":   {title: "Acknowledgement overdue", line: withTitle("Your acknowledgement of the %s is overdue."), plain: "An acknowledgement of yours is overdue."},
	"review-due":          {title: "Review due", line: withTitle("The %s is due for review."), plain: "A policy is due for review."},

	"policy-published":        {title: "Policy published", line: withTitle("%s is now published."), plain: "A policy was published."},
	"policy-retired":          {title: "Policy retired", line: withTitle("%s has been retired."), plain: "A policy was retired."},
	"access-granted":          {title: "Access granted", line: withTitle("You were given access to %s."), plain: "You were given access to a policy."},
	"raci-permission-granted": {title: "Role granted", line: withTitle("You were given a role on %s."), plain: "You were given a role on a policy."},
	"sso-activated":           {title: "Single sign-on turned on", plain: "Single sign-on is now active."},
	"sso-disabled":            {title: "Single sign-on turned off", plain: "Single sign-on was turned off."},
	"idp-test-failed":         {title: "Sign-in test failed", plain: "The identity provider test did not pass."},

	"workflow-awaiting-approval": {title: "Approval needed", plain: "A policy version is waiting for your approval.", approval: true},
	"workflow-assigned":          {title: "Assigned to you", plain: "A policy version was assigned to you for approval.", approval: true},
	"workflow-denied":            {title: "Approval declined", line: withTitle("%s was not approved."), plain: "A policy version was not approved."},
	"workflow-started":           {title: "Approval started", line: withTitle("An approval started on %s."), plain: "An approval started on a policy."},
	"assigned-as-owner":          {title: "Assigned as owner", line: withTitle("You are now the owner of %s."), plain: "You are now the owner of a policy."},

	"break-glass-alert":      {title: "Emergency access used", plain: "Emergency access was used on your account."},
	"break-glass-read-alert": {title: "Emergency read", plain: "Emergency access was used to read a policy."},
	"mfa-setup":              {title: "Set up two-step sign-in", plain: "Add a second step to protect your account."},
	"sp-cert-rotated":        {title: "Certificate rotated", plain: "A single sign-on certificate was rotated."},
	"welcome-account":        {title: "Welcome to Steward", plain: "Your account is ready."},
	"domain-verified":        {title: "Domain verified", plain: "Your domain is verified."},
}

const (
	unknownNoticeTitle = "Notification"
	unknownNoticeLine  = "You have a new notification."
)

// renderNotice words a notice and picks its link from the kind and the payload.
// versionID is the payload's policy_version_id ("" when it has none). policy is
// called only when the words or the link need the policy, and may return nil.
func renderNotice(kind, versionID string, policy func() *noticePolicy) (title, line string, link *NotificationLink) {
	words, known := noticeCatalog[kind]
	if !known {
		return unknownNoticeTitle, unknownNoticeLine, nil
	}
	if words.approval {
		if versionID != "" {
			link = &NotificationLink{Kind: NotificationLinkKindApproval, Ref: versionID}
		}
		return words.title, words.plain, link
	}
	if words.line == nil {
		return words.title, words.plain, nil
	}
	var p *noticePolicy
	if versionID != "" {
		p = policy()
	}
	if p == nil || p.title == "" {
		return words.title, words.plain, nil
	}
	if p.number != "" {
		link = &NotificationLink{Kind: NotificationLinkKindPolicy, Ref: p.number}
	}
	return words.title, words.line(p.title), link
}
