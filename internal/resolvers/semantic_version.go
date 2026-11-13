// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"fmt"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	workflowv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/workflow/v1"
)

// Semantic versions (steward-gateway#66): core stamps policy and template versions with
// MAJOR.MINOR.FIX and the change type behind it. These helpers turn core's messages into the
// gateway's enum and string, and the author's pick into workflow's enum. An unset value stays
// null; nothing is invented here.

// semanticVersionString renders core's semantic version, "2.1.0". Core sends the text with it;
// the three numbers are the fallback when it does not. Nil when core sent no version.
func semanticVersionString(v *corev1.SemanticVersion) *string {
	if v == nil {
		return nil
	}
	s := v.GetText()
	if s == "" {
		s = fmt.Sprintf("%d.%d.%d", v.GetMajor(), v.GetMinor(), v.GetFix())
	}
	return &s
}

// changeTypeFromCore maps core's change type. Nil for UNSPECIFIED (and anything unknown), so the
// client sees null rather than a value core never decided.
func changeTypeFromCore(c corev1.ChangeType) *ChangeType {
	var out ChangeType
	switch c {
	case corev1.ChangeType_CHANGE_TYPE_MAJOR:
		out = ChangeTypeMajor
	case corev1.ChangeType_CHANGE_TYPE_MINOR:
		out = ChangeTypeMinor
	case corev1.ChangeType_CHANGE_TYPE_FIX:
		out = ChangeTypeFix
	default:
		return nil
	}
	return &out
}

// changeTypeToWorkflow maps the author's pick to workflow's enum (the values match core's, so the
// pick passes through unchanged). Nil or unknown is UNSPECIFIED: core's suggestion stands.
func changeTypeToWorkflow(c *ChangeType) workflowv1.ChangeType {
	if c == nil {
		return workflowv1.ChangeType_CHANGE_TYPE_UNSPECIFIED
	}
	switch *c {
	case ChangeTypeMajor:
		return workflowv1.ChangeType_CHANGE_TYPE_MAJOR
	case ChangeTypeMinor:
		return workflowv1.ChangeType_CHANGE_TYPE_MINOR
	case ChangeTypeFix:
		return workflowv1.ChangeType_CHANGE_TYPE_FIX
	default:
		return workflowv1.ChangeType_CHANGE_TYPE_UNSPECIFIED
	}
}

// changeTypeLabel names a pick for the log; "unset" when the author made none.
func changeTypeLabel(c *ChangeType) string {
	if c == nil {
		return "unset"
	}
	return c.String()
}
