// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// letterFor maps a 0-based order index to its display letter (A=0).
func letterFor(orderIndex int) string {
	switch {
	case orderIndex < 0:
		orderIndex = 0
	case orderIndex > 25:
		orderIndex = 25
	}
	return string(rune('A' + orderIndex)) //nosec G115 -- bounded to 0..25 above
}

func appendixFromProto(a *corev1.Appendix) *Appendix {
	return &Appendix{
		ID:              a.GetId(),
		PolicyVersionID: a.GetPolicyVersionId(),
		Title:           a.GetTitle(),
		ContentJSON:     a.GetContentJson(),
		OrderIndex:      int(a.GetOrderIndex()),
		Letter:          letterFor(int(a.GetOrderIndex())),
	}
}

// AppendicesForVersion lists a version's appendices with derived letters.
func AppendicesForVersion(ctx context.Context, client corev1.AppendixServiceClient, policyVersionID string) ([]*Appendix, error) {
	resp, err := client.ListAppendices(ctx, &corev1.ListAppendicesRequest{PolicyVersionId: policyVersionID})
	if err != nil {
		return nil, fmt.Errorf("list appendices: %w", err)
	}
	out := make([]*Appendix, 0, len(resp.GetAppendices()))
	for _, a := range resp.GetAppendices() {
		out = append(out, appendixFromProto(a))
	}
	return out, nil
}

// AddAppendixResolver adds an appendix to a policy version.
func AddAppendixResolver(ctx context.Context, client corev1.AppendixServiceClient, policyVersionID, title, contentJSON string) (*Appendix, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.AddAppendix(ctx, &corev1.AddAppendixRequest{
		PolicyVersionId: policyVersionID,
		Title:           title,
		ContentJson:     contentJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("add appendix: %w", err)
	}
	return appendixFromProto(resp.GetAppendix()), nil
}

// UpdateAppendixResolver updates an appendix's title and content.
func UpdateAppendixResolver(ctx context.Context, client corev1.AppendixServiceClient, id, title, contentJSON string) (*Appendix, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.UpdateAppendix(ctx, &corev1.UpdateAppendixRequest{
		Id:          id,
		Title:       title,
		ContentJson: contentJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("update appendix: %w", err)
	}
	return appendixFromProto(resp.GetAppendix()), nil
}

// ReorderAppendicesResolver reorders appendices for a policy version.
func ReorderAppendicesResolver(ctx context.Context, client corev1.AppendixServiceClient, policyVersionID string, orderedIDs []string) ([]*Appendix, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ReorderAppendices(ctx, &corev1.ReorderAppendicesRequest{
		PolicyVersionId: policyVersionID,
		OrderedIds:      orderedIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("reorder appendices: %w", err)
	}
	out := make([]*Appendix, 0, len(resp.GetAppendices()))
	for _, a := range resp.GetAppendices() {
		out = append(out, appendixFromProto(a))
	}
	return out, nil
}

// DeleteAppendixResolver deletes an appendix by id.
func DeleteAppendixResolver(ctx context.Context, client corev1.AppendixServiceClient, id string) (bool, error) {
	if _, err := claimsUserID(ctx); err != nil {
		return false, err
	}
	if _, err := client.DeleteAppendix(ctx, &corev1.DeleteAppendixRequest{Id: id}); err != nil {
		return false, fmt.Errorf("delete appendix: %w", err)
	}
	return true, nil
}
