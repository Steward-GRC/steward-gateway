// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/core/v1"
)

type attachedDefinitionJSON struct {
	Term       string `json:"term"`
	Definition string `json:"definition"`
}

type attachedReferenceJSON struct {
	Label    string `json:"label"`
	Kind     string `json:"kind,omitempty"`
	Citation string `json:"citation,omitempty"`
	URL      string `json:"url,omitempty"`
}

type attachedRelatedPolicyJSON struct {
	PolicyID string `json:"policyId"`
	Title    string `json:"title"`
	Summary  string `json:"summary,omitempty"`
}

type enrichmentContextJSON struct {
	Definitions     []attachedDefinitionJSON    `json:"definitions,omitempty"`
	References      []attachedReferenceJSON     `json:"references,omitempty"`
	RelatedPolicies []attachedRelatedPolicyJSON `json:"relatedPolicies,omitempty"`
}

func (c *enrichmentContextJSON) isEmpty() bool {
	return c == nil || (len(c.Definitions) == 0 && len(c.References) == 0 && len(c.RelatedPolicies) == 0)
}

type enrichmentOptOutJSON struct {
	Definitions bool `json:"definitions,omitempty"`
	Related     bool `json:"related,omitempty"`
	References  bool `json:"references,omitempty"`
}

// optOutJSONFromInput maps the GraphQL opt-out input onto the wire shape.
func optOutJSONFromInput(in *EnrichmentOptOutInput) enrichmentOptOutJSON {
	if in == nil {
		return enrichmentOptOutJSON{}
	}
	return enrichmentOptOutJSON{
		Definitions: derefBool(in.Definitions),
		Related:     derefBool(in.Related),
		References:  derefBool(in.References),
	}
}

type libraryDefinitionJSON struct {
	EntryID string `json:"entryId"`
	Term    string `json:"term"`
}

type libraryReferenceJSON struct {
	ReferenceID string `json:"referenceId"`
	Label       string `json:"label"`
	URL         string `json:"url,omitempty"`
}

type enrichmentLibraryJSON struct {
	Definitions []libraryDefinitionJSON `json:"definitions,omitempty"`
	References  []libraryReferenceJSON  `json:"references,omitempty"`
}

func (l *enrichmentLibraryJSON) isEmpty() bool {
	return l == nil || (len(l.Definitions) == 0 && len(l.References) == 0)
}

// EnrichmentResolver fetches a policy's attached enrichments (ingest grounding) and the dedupe
// library from core, best-effort.
type EnrichmentResolver struct {
	refClient corev1.ReferenceServiceClient
	defClient corev1.DefinitionLibraryServiceClient
	relClient corev1.RelationServiceClient
}

// NewEnrichmentResolver constructs an EnrichmentResolver from the gateway's core clients.
func NewEnrichmentResolver(ref corev1.ReferenceServiceClient, def corev1.DefinitionLibraryServiceClient, rel corev1.RelationServiceClient) *EnrichmentResolver {
	return &EnrichmentResolver{refClient: ref, defClient: def, relClient: rel}
}

// resolve fetches, for policyID, the attached-enrichment ingest context and the dedupe library.
func (er *EnrichmentResolver) resolve(ctx context.Context, policyID string) (*enrichmentContextJSON, *enrichmentLibraryJSON) {
	if er == nil || policyID == "" {
		return nil, nil
	}

	ingest := &enrichmentContextJSON{}
	library := &enrichmentLibraryJSON{}

	if er.defClient != nil {
		if resp, err := er.defClient.ListPolicyDefinitionEntries(ctx, &corev1.ListPolicyDefinitionEntriesRequest{PolicyId: policyID}); err == nil {
			for _, d := range resp.GetDefinitions() {
				ingest.Definitions = append(ingest.Definitions, attachedDefinitionJSON{Term: d.GetTerm(), Definition: d.GetDefinition()})
			}
		}
		if resp, err := er.defClient.ListDefinitionEntries(ctx, &corev1.ListDefinitionEntriesRequest{}); err == nil {
			for _, d := range resp.GetDefinitions() {
				if d.GetArchived() {
					continue
				}
				library.Definitions = append(library.Definitions, libraryDefinitionJSON{EntryID: d.GetId(), Term: d.GetTerm()})
			}
		}
	}

	if er.refClient != nil {
		if resp, err := er.refClient.ListPolicyReferences(ctx, &corev1.ListPolicyReferencesRequest{PolicyId: policyID}); err == nil {
			for _, r := range resp.GetReferences() {
				ingest.References = append(ingest.References, attachedReferenceJSON{
					Label:    r.GetLabel(),
					Kind:     referenceKindWire(r.GetKind()),
					Citation: referenceCitation(r),
					URL:      r.GetUrl(),
				})
			}
		}
		if resp, err := er.refClient.ListReferences(ctx, &corev1.ListReferencesRequest{}); err == nil {
			for _, r := range resp.GetReferences() {
				library.References = append(library.References, libraryReferenceJSON{ReferenceID: r.GetId(), Label: r.GetLabel(), URL: r.GetUrl()})
			}
		}
	}

	if er.relClient != nil {
		if resp, err := er.relClient.ListRelatedPolicies(ctx, &corev1.ListRelatedPoliciesRequest{PolicyId: policyID}); err == nil {
			for _, rp := range resp.GetRelated() {
				ingest.RelatedPolicies = append(ingest.RelatedPolicies, attachedRelatedPolicyJSON{PolicyID: rp.GetPolicyId(), Title: rp.GetTitle()})
			}
		}
	}

	if ingest.isEmpty() {
		ingest = nil
	}
	if library.isEmpty() {
		library = nil
	}
	return ingest, library
}

// referenceKindWire maps the core ReferenceKind enum to the STANDARD/TEXT/LINK wire strings the ai
// service's enrichment shapes use.
func referenceKindWire(k corev1.ReferenceKind) string {
	switch k {
	case corev1.ReferenceKind_REFERENCE_KIND_TEXT:
		return "TEXT"
	case corev1.ReferenceKind_REFERENCE_KIND_LINK:
		return "LINK"
	default:
		return "STANDARD"
	}
}

// referenceCitation picks the human-meaningful citation text for grounding: the clause for a
// STANDARD reference, else the free-text body.
func referenceCitation(r *corev1.Reference) string {
	if c := r.GetClause(); c != "" {
		return c
	}
	return r.GetBody()
}

func (r *Resolver) enrichmentResolver() *EnrichmentResolver {
	return NewEnrichmentResolver(r.ReferenceClient, r.DefinitionLibraryClient, r.RelationClient)
}
