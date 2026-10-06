// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-gateway/internal/resolvers"
)

// TestEveryGraphQLResolverIsImplemented guards against shipping a release in
// which a gqlgen-generated resolver is still an unwritten stub. When gqlgen
// scaffolds a resolver for a new schema field it emits a body of
//
//	panic(fmt.Errorf("not implemented: <GoField> - <field>"))
//
// (see github.com/99designs/gqlgen/plugin/resolvergen/resolver.go). That stub
// compiles and satisfies the generated resolver interface, so nothing at build
// time — and no `var _ MutationResolver = (*mutationResolver)(nil)` assertion —
// catches a field left unimplemented; it only blows up at runtime the first
// time a client selects that field. This is the GraphQL analogue of the
// gRPC codes.Unimplemented trap guarded by TestEveryGRPCRPCIsImplemented in
// policy/core.
//
// The guard reflects over the full resolver-root surface (Mutation, Query,
// Subscription and the PolicyVersion field resolver) and invokes every field
// method on a zero-value *Resolver. A resolver left as the generated stub
// panics with the "not implemented:" marker WITHOUT touching any dependency.
// An implemented resolver, run against a zero-value *Resolver with nil gRPC
// clients, instead reaches real code and either returns cleanly or nil-deref
// panics — neither of which carries the marker. So only the generated stub is
// flagged. New schema fields are covered automatically the moment gqlgen
// regenerates the resolver interface.
func TestEveryGraphQLResolverIsImplemented(t *testing.T) {
	root := &resolvers.Resolver{}

	entries := []struct {
		name   string
		ifaceT reflect.Type
		bound  reflect.Value
	}{
		{
			name:   "Mutation",
			ifaceT: reflect.TypeFor[resolvers.MutationResolver](),
			bound:  reflect.ValueOf(root.Mutation()),
		},
		{
			name:   "Query",
			ifaceT: reflect.TypeFor[resolvers.QueryResolver](),
			bound:  reflect.ValueOf(root.Query()),
		},
		{
			name:   "Subscription",
			ifaceT: reflect.TypeFor[resolvers.SubscriptionResolver](),
			bound:  reflect.ValueOf(root.Subscription()),
		},
		{
			name:   "PolicyVersion",
			ifaceT: reflect.TypeFor[resolvers.PolicyVersionResolver](),
			bound:  reflect.ValueOf(root.PolicyVersion()),
		},
	}

	totalChecked := 0
	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			checked, stubs := scanResolverFields(e.name, e.ifaceT, e.bound)
			totalChecked += checked

			// Sanity: a future refactor that hides an interface's methods (or an
			// entry dropped from the table) must not let this subtest pass
			// vacuously.
			if checked == 0 {
				t.Fatalf("reflected 0 fields on %sResolver — reflection/filter is wrong or the interface is empty", e.name)
			}
			for _, field := range stubs {
				t.Errorf("GraphQL resolver %s is still an unimplemented gqlgen stub "+
					"(panics %q). Implement the resolver before release, or remove the "+
					"field from graphql/schema.graphqls.", field, "not implemented: ...")
			}
		})
	}

	// Sanity: ensure the reflection actually exercised the whole resolver
	// surface. The schema currently exposes ~184 resolver fields; a floor well
	// below that still catches an entire interface (Mutation/Query) silently
	// dropping out of the table while tolerating normal schema churn.
	const minExpectedFields = 150
	if totalChecked < minExpectedFields {
		t.Fatalf("expected to check at least %d resolver fields across all resolver interfaces, only checked %d — a resolver interface is missing from the table or reflection is broken", minExpectedFields, totalChecked)
	}
}

// gqlgenNotImplementedMarker is the substring gqlgen v0.17.x writes into the
// body of an unwritten resolver stub. Kept in one place so the detector and
// its self-test agree.
const gqlgenNotImplementedMarker = "not implemented:"

// scanResolverFields invokes every field method exposed by ifaceT on the bound
// resolver value and returns how many were checked plus the fully-qualified
// names ("<Interface>.<Field>") of any that are still the generated
// not-implemented stub.
func scanResolverFields(ifaceName string, ifaceT reflect.Type, bound reflect.Value) (checked int, stubs []string) {
	for m := range ifaceT.Methods() {
		checked++
		if resolverFieldIsStub(bound, m.Type, m.Name) {
			stubs = append(stubs, ifaceName+"."+m.Name)
		}
	}
	return checked, stubs
}

// resolverFieldIsStub calls a single resolver field method with zero-value
// arguments and reports whether it is the generated gqlgen not-implemented
// stub. The call runs in its own goroutine with a recover so an implemented
// resolver's nil-dependency panic is contained, and with a timeout so a
// resolver that blocks on real code can never hang CI — a stub panics
// instantly and never blocks.
func resolverFieldIsStub(bound reflect.Value, methodType reflect.Type, name string) bool {
	ctxT := reflect.TypeFor[context.Context]()

	args := make([]reflect.Value, methodType.NumIn())
	for i := 0; i < methodType.NumIn(); i++ {
		in := methodType.In(i)
		if in.Implements(ctxT) {
			args[i] = reflect.ValueOf(context.Background())
		} else {
			args[i] = reflect.New(in).Elem()
		}
	}

	done := make(chan bool, 1)
	go func() {
		isStub := false
		defer func() {
			// A recovered panic carrying the marker is the generated stub. Any
			// other panic (e.g. nil gRPC client deref) means real handler code
			// ran, i.e. the field IS implemented.
			isStub = isNotImplementedStubPanic(recover())
			done <- isStub
		}()
		bound.MethodByName(name).Call(args)
		// Clean return against nil deps: implemented.
	}()

	select {
	case isStub := <-done:
		return isStub
	case <-time.After(2 * time.Second):
		// The generated stub panics synchronously and instantly; blocking here
		// means real code ran, so the field is implemented.
		return false
	}
}

// isNotImplementedStubPanic reports whether a recovered panic value is the
// gqlgen "not implemented" stub panic.
func isNotImplementedStubPanic(recovered any) bool {
	if recovered == nil {
		return false
	}
	var msg string
	switch v := recovered.(type) {
	case error:
		msg = v.Error()
	case string:
		msg = v
	case fmt.Stringer:
		msg = v.String()
	default:
		msg = fmt.Sprintf("%v", recovered)
	}
	return strings.Contains(msg, gqlgenNotImplementedMarker)
}

// --- self-test: prove the guard actually catches a forgotten stub ---

// stubGuardProbe models exactly what gqlgen scaffolds vs. what a real resolver
// looks like when run against nil dependencies.
type stubGuardProbe interface {
	// ForgottenField is a verbatim gqlgen not-implemented stub.
	ForgottenField(ctx context.Context, id string) (string, error)
	// ImplementedField represents a real resolver: it reaches real code that
	// nil-derefs against a zero-value probe (like dialing a nil gRPC client),
	// which must NOT be mistaken for an unimplemented stub.
	ImplementedField(ctx context.Context) (string, error)
}

type stubGuardProbeImpl struct{ dep *int }

func (stubGuardProbeImpl) ForgottenField(ctx context.Context, id string) (string, error) {
	panic(fmt.Errorf("not implemented: ForgottenField - forgottenField"))
}

func (p stubGuardProbeImpl) ImplementedField(ctx context.Context) (string, error) {
	return fmt.Sprintf("%d", *p.dep), nil // nil-deref panic on a zero-value probe
}

// TestResolverStubGuardCatchesForgottenStub proves the detection mechanism used
// by TestEveryGraphQLResolverIsImplemented genuinely flags a forgotten stub and
// does not misclassify an implemented (nil-deref) resolver. If this fails the
// main guard cannot be trusted.
func TestResolverStubGuardCatchesForgottenStub(t *testing.T) {
	ifaceT := reflect.TypeFor[stubGuardProbe]()
	bound := reflect.ValueOf(stubGuardProbe(stubGuardProbeImpl{}))

	checked, stubs := scanResolverFields("StubGuardProbe", ifaceT, bound)

	if checked != 2 {
		t.Fatalf("expected to check 2 probe fields, checked %d", checked)
	}
	if len(stubs) != 1 || stubs[0] != "StubGuardProbe.ForgottenField" {
		t.Fatalf("stub guard failed to isolate the forgotten stub: got %v, want [StubGuardProbe.ForgottenField]", stubs)
	}
}
