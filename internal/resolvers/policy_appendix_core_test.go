// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

// appendixRow is one row of a fake appendix's version table.
type appendixRow struct {
	state        corev1.AppendixVersionState
	title        string
	content      string
	contributors []string
	publishedBy  string
}

type fakeAppendix struct {
	id, policyID string
	retired      bool
	rows         []*appendixRow // rows[i] is version i+1
	people       []string       // first-save order
}

// appendixCore is an in-memory PolicyAppendixService that behaves as core does:
// it returns the published row and the draft side by side, never filters for a
// reader, keeps contributors in first-save order and ignores an unchanged save.
type appendixCore struct {
	corev1.PolicyAppendixServiceClient
	list   []*fakeAppendix
	writes int // every call that changes or tries to change state
	// lastActor and lastTitle are what the latest create was sent.
	lastActor, lastTitle string
	// lastReorder is the latest reorder request core was sent.
	lastReorder *corev1.ReorderPolicyAppendicesRequest
	// lastDiff is the latest diff request core was sent; diffs counts them.
	lastDiff *corev1.DiffPolicyAppendixRequest
	diffs    int
}

func (c *appendixCore) note(a *fakeAppendix, r *appendixRow, user string) {
	if !slices.Contains(a.people, user) {
		a.people = append(a.people, user)
	}
	if !slices.Contains(r.contributors, user) {
		r.contributors = append(r.contributors, user)
	}
}

func (c *appendixCore) seed(id, policy, title, content, author string) *fakeAppendix {
	a := &fakeAppendix{id: id, policyID: policy}
	r := &appendixRow{state: corev1.AppendixVersionState_APPENDIX_VERSION_STATE_PUBLISHED, title: title, content: content, publishedBy: author}
	c.note(a, r, author)
	a.rows = append(a.rows, r)
	c.list = append(c.list, a)
	return a
}

func (c *appendixCore) live(policy string) []*fakeAppendix {
	var out []*fakeAppendix
	for _, a := range c.list {
		if a.policyID == policy && !a.retired {
			out = append(out, a)
		}
	}
	return out
}

func (c *appendixCore) find(id string) (*fakeAppendix, error) {
	for _, a := range c.list {
		if a.id == id {
			return a, nil
		}
	}
	return nil, status.Error(codes.NotFound, "appendix not found")
}

func (c *appendixCore) ver(a *fakeAppendix, i int) *corev1.AppendixVersion {
	r := a.rows[i]
	at := timestamppb.Now()
	v := &corev1.AppendixVersion{
		Id: fmt.Sprintf("%s-v%d", a.id, i+1), VersionNo: int32(i + 1), State: r.state, Title: r.title, ContentJson: r.content,
		CreatedAt: at, CreatedBy: r.contributors[0], UpdatedAt: at, UpdatedBy: r.contributors[len(r.contributors)-1],
		ContributorIds: slices.Clone(r.contributors),
	}
	if r.state == corev1.AppendixVersionState_APPENDIX_VERSION_STATE_PUBLISHED {
		v.PublishedAt, v.PublishedBy = at, r.publishedBy
	}
	return v
}

func (c *appendixCore) view(a *fakeAppendix) *corev1.PolicyAppendix {
	out := &corev1.PolicyAppendix{Id: a.id, PolicyId: a.policyID, ContributorIds: slices.Clone(a.people)}
	if a.retired {
		out.RetiredAt = timestamppb.Now()
	} else {
		at := slices.Index(c.live(a.policyID), a)
		out.OrderIndex = int32(at)
		out.Letter = string(rune('A' + at))
	}
	for i, r := range a.rows {
		out.Versions = append(out.Versions, &corev1.AppendixVersionInfo{VersionNo: int32(i + 1), State: r.state, ContributorIds: slices.Clone(r.contributors)})
		if r.state == corev1.AppendixVersionState_APPENDIX_VERSION_STATE_DRAFT {
			out.Draft = c.ver(a, i)
			continue
		}
		out.PublishedVersions = append([]*corev1.AppendixVersion{c.ver(a, i)}, out.PublishedVersions...)
	}
	if len(out.PublishedVersions) > 0 {
		out.Published = out.PublishedVersions[0]
	}
	return out
}

func (c *appendixCore) draftOf(a *fakeAppendix) *appendixRow {
	if last := a.rows[len(a.rows)-1]; last.state == corev1.AppendixVersionState_APPENDIX_VERSION_STATE_DRAFT {
		return last
	}
	return nil
}

func (c *appendixCore) ListPolicyAppendices(_ context.Context, in *corev1.ListPolicyAppendicesRequest, _ ...grpc.CallOption) (*corev1.ListPolicyAppendicesResponse, error) {
	out := &corev1.ListPolicyAppendicesResponse{}
	for _, a := range c.live(in.GetPolicyId()) {
		out.Appendices = append(out.Appendices, c.view(a))
	}
	if in.GetIncludeRetired() {
		for _, a := range c.list {
			if a.policyID == in.GetPolicyId() && a.retired {
				out.Appendices = append(out.Appendices, c.view(a))
			}
		}
	}
	return out, nil
}

func (c *appendixCore) GetPolicyAppendix(_ context.Context, in *corev1.GetPolicyAppendixRequest, _ ...grpc.CallOption) (*corev1.GetPolicyAppendixResponse, error) {
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	return &corev1.GetPolicyAppendixResponse{Appendix: c.view(a)}, nil
}

func (c *appendixCore) CreatePolicyAppendix(_ context.Context, in *corev1.CreatePolicyAppendixRequest, _ ...grpc.CallOption) (*corev1.CreatePolicyAppendixResponse, error) {
	c.writes++
	c.lastActor, c.lastTitle = in.GetActorUserId(), in.GetTitle()
	a := &fakeAppendix{id: fmt.Sprintf("app-%d", len(c.list)+1), policyID: in.GetPolicyId()}
	title := strings.TrimSpace(in.GetTitle())
	for n := len(c.live(a.policyID)); title == ""; n++ {
		name := "Appendix " + string(rune('A'+n))
		used := false
		for _, o := range c.list {
			if o.policyID == a.policyID && o.rows[len(o.rows)-1].title == name {
				used = true
			}
		}
		if !used {
			title = name
		}
	}
	r := &appendixRow{state: corev1.AppendixVersionState_APPENDIX_VERSION_STATE_DRAFT, title: title, content: in.GetContentJson()}
	c.note(a, r, in.GetActorUserId())
	a.rows = append(a.rows, r)
	c.list = append(c.list, a)
	return &corev1.CreatePolicyAppendixResponse{Appendix: c.view(a)}, nil
}

func (c *appendixCore) SaveAppendixDraft(_ context.Context, in *corev1.SaveAppendixDraftRequest, _ ...grpc.CallOption) (*corev1.SaveAppendixDraftResponse, error) {
	c.writes++
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	if d := c.draftOf(a); d != nil {
		d.title, d.content = in.GetTitle(), in.GetContentJson()
		c.note(a, d, in.GetActorUserId())
	} else if p := a.rows[len(a.rows)-1]; p.title != in.GetTitle() || p.content != in.GetContentJson() {
		d := &appendixRow{state: corev1.AppendixVersionState_APPENDIX_VERSION_STATE_DRAFT, title: in.GetTitle(), content: in.GetContentJson()}
		c.note(a, d, in.GetActorUserId())
		a.rows = append(a.rows, d)
	}
	return &corev1.SaveAppendixDraftResponse{Appendix: c.view(a)}, nil
}

func (c *appendixCore) PublishAppendix(_ context.Context, in *corev1.PublishAppendixRequest, _ ...grpc.CallOption) (*corev1.PublishAppendixResponse, error) {
	c.writes++
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	d := c.draftOf(a)
	if d == nil {
		return nil, status.Error(codes.FailedPrecondition, "no draft to publish")
	}
	d.state, d.publishedBy = corev1.AppendixVersionState_APPENDIX_VERSION_STATE_PUBLISHED, in.GetActorUserId()
	c.note(a, d, in.GetActorUserId())
	return &corev1.PublishAppendixResponse{Appendix: c.view(a)}, nil
}

func (c *appendixCore) RetireAppendix(_ context.Context, in *corev1.RetireAppendixRequest, _ ...grpc.CallOption) (*corev1.RetireAppendixResponse, error) {
	c.writes++
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	a.retired = true
	return &corev1.RetireAppendixResponse{Appendix: c.view(a)}, nil
}

func (c *appendixCore) RestoreAppendix(_ context.Context, in *corev1.RestoreAppendixRequest, _ ...grpc.CallOption) (*corev1.RestoreAppendixResponse, error) {
	c.writes++
	a, err := c.find(in.GetId())
	if err != nil {
		return nil, err
	}
	a.retired = false
	// restoring puts it last among the live ones
	c.list = append(slices.DeleteFunc(c.list, func(o *fakeAppendix) bool { return o == a }), a)
	return &corev1.RestoreAppendixResponse{Appendix: c.view(a)}, nil
}

// ReorderPolicyAppendices behaves as core does: the list must name every live
// appendix of the policy exactly once, else InvalidArgument and the order is
// left as it was.
func (c *appendixCore) ReorderPolicyAppendices(_ context.Context, in *corev1.ReorderPolicyAppendicesRequest, _ ...grpc.CallOption) (*corev1.ReorderPolicyAppendicesResponse, error) {
	c.writes++
	c.lastReorder = in
	live := c.live(in.GetPolicyId())
	named := map[string]bool{}
	for _, id := range in.GetOrderedIds() {
		a, err := c.find(id)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "unknown appendix in the list")
		}
		if a.policyID != in.GetPolicyId() || a.retired || named[id] {
			return nil, status.Error(codes.InvalidArgument, "name every live appendix of the policy exactly once")
		}
		named[id] = true
	}
	if len(named) != len(live) {
		return nil, status.Error(codes.InvalidArgument, "name every live appendix of the policy exactly once")
	}
	// the live ones take the slots the policy's live ones held, in the new order
	var slots []int
	for i, a := range c.list {
		if a.policyID == in.GetPolicyId() && !a.retired {
			slots = append(slots, i)
		}
	}
	var ordered []*fakeAppendix
	for _, id := range in.GetOrderedIds() {
		ordered = append(ordered, c.find0(id))
	}
	for n, a := range ordered {
		c.list[slots[n]] = a
	}
	out := &corev1.ReorderPolicyAppendicesResponse{}
	for _, a := range c.live(in.GetPolicyId()) {
		out.Appendices = append(out.Appendices, c.view(a))
	}
	return out, nil
}

// find0 is find for a test that knows the appendix exists.
func (c *appendixCore) find0(id string) *fakeAppendix {
	a, _ := c.find(id)
	return a
}
