// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"errors"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
)

var errLabelUnused = errors.New("label fake: method not used")

type labelIdentityFake struct {
	identityv1.IdentityReadServiceClient
	users     map[string]*identityv1.User // user id -> user (missing = NotFound-ish)
	getUserN  int
	getUserMu []string // ids requested, in order
}

func (f *labelIdentityFake) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.getUserN++
	f.getUserMu = append(f.getUserMu, in.GetUserId())
	u, ok := f.users[in.GetUserId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

type labelGroupFake struct {
	corev1.CategoryServiceClient
	groups map[string]string // group id -> name
}

func (f *labelGroupFake) GetCategory(_ context.Context, in *corev1.GetCategoryRequest, _ ...grpc.CallOption) (*corev1.GetCategoryResponse, error) {
	name, ok := f.groups[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetCategoryResponse{Category: &corev1.Category{Id: in.GetId(), Name: name}}, nil
}

type labelPolicyFake struct {
	corev1.PolicyServiceClient
	policies map[string]*corev1.Policy        // policy id -> policy
	versions map[string]*corev1.PolicyVersion // version id -> version
}

func (f *labelPolicyFake) GetPolicy(_ context.Context, in *corev1.GetPolicyRequest, _ ...grpc.CallOption) (*corev1.GetPolicyResponse, error) {
	p, ok := f.policies[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetPolicyResponse{Policy: p}, nil
}
func (f *labelPolicyFake) GetPolicyVersion(_ context.Context, in *corev1.GetPolicyVersionRequest, _ ...grpc.CallOption) (*corev1.GetPolicyVersionResponse, error) {
	v, ok := f.versions[in.GetId()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &corev1.GetPolicyVersionResponse{Version: v}, nil
}

type labelTemplateFake struct {
	corev1.TemplateServiceClient
	templates []*corev1.Template                   // all templates (ListTemplates)
	versions  map[string][]*corev1.TemplateVersion // template id -> versions
}

func (f *labelTemplateFake) ListTemplates(context.Context, *corev1.ListTemplatesRequest, ...grpc.CallOption) (*corev1.ListTemplatesResponse, error) {
	return &corev1.ListTemplatesResponse{Templates: f.templates}, nil
}
func (f *labelTemplateFake) ListTemplateVersions(_ context.Context, in *corev1.ListTemplateVersionsRequest, _ ...grpc.CallOption) (*corev1.ListTemplateVersionsResponse, error) {
	return &corev1.ListTemplateVersionsResponse{Versions: f.versions[in.GetTemplateId()]}, nil
}
