// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	identityv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/identity/v1"
)

// ssoOrgFromProto maps a proto Organization to the GraphQL model.
func ssoOrgFromProto(o *identityv1.Organization) *Organization {
	if o == nil {
		return nil
	}
	return &Organization{
		Domain:          o.GetDomain(),
		OrgName:         o.GetOrgName(),
		Protocol:        o.GetProtocol(),
		DisplayName:     o.GetDisplayName(),
		ConnectionAlias: o.GetConnectionAlias(),
		Verified:        o.GetVerified(),
		TestPassed:      o.GetTestPassed(),
		Enabled:         o.GetEnabled(),
		ConnectionID:    o.GetConnectionId(),
		JitEnabled:      o.GetJitEnabled(),
		AllowLocal:      o.GetAllowLocal(),
	}
}

// spCertFromProto maps a proto SPCertificate to the GraphQL model.
func spCertFromProto(c *identityv1.SPCertificate) *SpCertificate {
	if c == nil {
		return nil
	}
	return &SpCertificate{
		Serial:        c.GetSerial(),
		CertPem:       c.GetCertPem(),
		SpMetadataXML: c.GetSpMetadataXml(),
		NotAfter:      c.GetNotAfter(),
		Active:        c.GetActive(),
	}
}

// groupMappingFromProto maps a proto GroupMapping to the GraphQL model.
func groupMappingFromProto(m *identityv1.GroupMapping) *GroupMapping {
	if m == nil {
		return nil
	}
	return &GroupMapping{
		ID:                 m.GetId(),
		ConnectionID:       m.GetConnectionId(),
		IdpGroupClaimValue: m.GetIdpGroupClaimValue(),
		TargetGroupID:      m.GetTargetGroupId(),
	}
}

// OrganizationsResolver lists all configured organization SSO connections.
func OrganizationsResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient) ([]*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListOrganizations(ctx, &identityv1.ListOrganizationsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*Organization, 0, len(resp.GetOrganizations()))
	for _, o := range resp.GetOrganizations() {
		out = append(out, ssoOrgFromProto(o))
	}
	return out, nil
}

// OrganizationResolver fetches a single organization SSO connection by domain.
func OrganizationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.GetOrganization(ctx, &identityv1.GetOrganizationRequest{Domain: domain})
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// SpCertificateResolver returns the active SP signing certificate.
func SpCertificateResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient) (*SpCertificate, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.GetSPCertificate(ctx, &identityv1.GetSPCertificateRequest{})
	if err != nil {
		return nil, err
	}
	return spCertFromProto(resp.GetCertificate()), nil
}

// SpCertificatesResolver returns all SP signing certificates (history).
func SpCertificatesResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient) ([]*SpCertificate, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListSPCertificates(ctx, &identityv1.ListSPCertificatesRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*SpCertificate, 0, len(resp.GetCertificates()))
	for _, c := range resp.GetCertificates() {
		out = append(out, spCertFromProto(c))
	}
	return out, nil
}

// GroupMappingsResolver lists a connection's IdP-group-claim-to-group mappings.
func GroupMappingsResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, connectionID string) ([]*GroupMapping, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ListGroupMappings(ctx, &identityv1.ListGroupMappingsRequest{ConnectionId: connectionID})
	if err != nil {
		return nil, err
	}
	out := make([]*GroupMapping, 0, len(resp.GetMappings()))
	for _, m := range resp.GetMappings() {
		out = append(out, groupMappingFromProto(m))
	}
	return out, nil
}

// AddOrganizationResolver registers a new organization SSO connection.
func AddOrganizationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, input AddOrganizationInput) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	req := &identityv1.AddOrganizationRequest{
		OrgName:  input.OrgName,
		Domain:   input.Domain,
		Protocol: input.Protocol,
	}
	if input.DisplayName != nil {
		req.DisplayName = *input.DisplayName
	}
	if input.SecretRef != nil {
		req.SecretRef = *input.SecretRef
	}
	if len(input.Config) > 0 {
		req.Config = make(map[string]string, len(input.Config))
		for _, kv := range input.Config {
			if kv == nil {
				continue
			}
			req.Config[kv.Key] = kv.Value
		}
	}
	resp, err := client.AddOrganization(ctx, req)
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// StartDomainVerificationResolver mints a DNS TXT verification challenge.
func StartDomainVerificationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string, rotate *bool) (*DomainVerification, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.StartDomainVerification(ctx, &identityv1.StartDomainVerificationRequest{
		Domain: domain,
		Rotate: rotate != nil && *rotate,
	})
	if err != nil {
		return nil, err
	}
	return &DomainVerification{
		Token:          resp.GetToken(),
		DNSRecordName:  resp.GetDnsRecordName(),
		DNSRecordValue: resp.GetDnsRecordValue(),
		Instructions:   resp.GetInstructions(),
	}, nil
}

// ChangeOrgProtocolResolver switches an organization's IdP protocol (SAML<->OIDC), resetting the
// org to the start.
func ChangeOrgProtocolResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain, protocol string, config []*KeyValueInput, secretRef *string) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	req := &identityv1.ChangeOrgProtocolRequest{
		Domain:   domain,
		Protocol: protocol,
	}
	if secretRef != nil {
		req.SecretRef = *secretRef
	}
	if len(config) > 0 {
		req.Config = make(map[string]string, len(config))
		for _, kv := range config {
			if kv == nil {
				continue
			}
			req.Config[kv.Key] = kv.Value
		}
	}
	resp, err := client.ChangeOrgProtocol(ctx, req)
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// VerifyDomainResolver checks the domain's DNS TXT record against its token and returns the
// (now-updated) organization.
func VerifyDomainResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	if _, err := client.VerifyDomain(ctx, &identityv1.VerifyDomainRequest{Domain: domain}); err != nil {
		return nil, err
	}
	resp, err := client.GetOrganization(ctx, &identityv1.GetOrganizationRequest{Domain: domain})
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// ActivateOrganizationResolver enables an organization's SSO connection.
func ActivateOrganizationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ActivateOrganization(ctx, &identityv1.ActivateOrganizationRequest{Domain: domain})
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// DisableOrganizationResolver disables an organization's SSO connection.
func DisableOrganizationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.DisableOrganization(ctx, &identityv1.DisableOrganizationRequest{Domain: domain})
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// UpdateIdPConnectionResolver flips an organization's per-org login toggles: jitEnabled and
// allowLocal.
func UpdateIdPConnectionResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string, jitEnabled, allowLocal *bool) (*Organization, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.UpdateIdPConnection(ctx, &identityv1.UpdateIdPConnectionRequest{
		Domain:     domain,
		JitEnabled: jitEnabled,
		AllowLocal: allowLocal,
	})
	if err != nil {
		return nil, err
	}
	return ssoOrgFromProto(resp.GetOrganization()), nil
}

// DeleteOrganizationResolver removes an organization SSO connection.
func DeleteOrganizationResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, domain string) (bool, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return false, err
	}
	if _, err := client.DeleteOrganization(ctx, &identityv1.DeleteOrganizationRequest{Domain: domain}); err != nil {
		return false, err
	}
	return true, nil
}

// AddGroupMappingResolver adds an IdP-group-claim-to-platform-group mapping.
func AddGroupMappingResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, connectionID, idpGroupClaimValue, targetGroupID string) (*GroupMapping, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.AddGroupMapping(ctx, &identityv1.AddGroupMappingRequest{
		ConnectionId:       connectionID,
		IdpGroupClaimValue: idpGroupClaimValue,
		TargetGroupId:      targetGroupID,
	})
	if err != nil {
		return nil, err
	}
	return groupMappingFromProto(resp.GetMapping()), nil
}

// DeleteGroupMappingResolver removes a group mapping by id.
func DeleteGroupMappingResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient, mappingID string) (bool, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return false, err
	}
	if _, err := client.DeleteGroupMapping(ctx, &identityv1.DeleteGroupMappingRequest{MappingId: mappingID}); err != nil {
		return false, err
	}
	return true, nil
}

// ForceRotateSpCertificateResolver mints a new SP signing certificate and activates it immediately,
// superseding the previous one.
func ForceRotateSpCertificateResolver(ctx context.Context, client identityv1.IdentitySSOAdminServiceClient) (*SpCertificate, error) {
	if _, err := requireSiteAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := client.ForceRotateSPCertificate(ctx, &identityv1.ForceRotateSPCertificateRequest{})
	if err != nil {
		return nil, err
	}
	return spCertFromProto(resp.GetCertificate()), nil
}
