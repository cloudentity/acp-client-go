// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// WorkspacePermissionsResponse workspace permissions response
//
// swagger:model WorkspacePermissionsResponse
type WorkspacePermissionsResponse struct {

	// create identity pool
	CreateIdentityPool bool `json:"create_identity_pool,omitempty" yaml:"create_identity_pool,omitempty"`

	// delete organization
	DeleteOrganization bool `json:"delete_organization,omitempty" yaml:"delete_organization,omitempty"`

	// delete workspace
	DeleteWorkspace bool `json:"delete_workspace,omitempty" yaml:"delete_workspace,omitempty"`

	// discover workspace
	DiscoverWorkspace bool `json:"discover_workspace,omitempty" yaml:"discover_workspace,omitempty"`

	// get organization
	GetOrganization bool `json:"get_organization,omitempty" yaml:"get_organization,omitempty"`

	// get workspace
	GetWorkspace bool `json:"get_workspace,omitempty" yaml:"get_workspace,omitempty"`

	// list identity pools
	ListIdentityPools bool `json:"list_identity_pools,omitempty" yaml:"list_identity_pools,omitempty"`

	// manage admin role
	ManageAdminRole bool `json:"manage_admin_role,omitempty" yaml:"manage_admin_role,omitempty"`

	// manage apis
	ManageApis bool `json:"manage_apis,omitempty" yaml:"manage_apis,omitempty"`

	// manage auditor role
	ManageAuditorRole bool `json:"manage_auditor_role,omitempty" yaml:"manage_auditor_role,omitempty"`

	// manage authorization details
	ManageAuthorizationDetails bool `json:"manage_authorization_details,omitempty" yaml:"manage_authorization_details,omitempty"`

	// manage claims
	ManageClaims bool `json:"manage_claims,omitempty" yaml:"manage_claims,omitempty"`

	// manage clients
	ManageClients bool `json:"manage_clients,omitempty" yaml:"manage_clients,omitempty"`

	// manage custom apps
	ManageCustomApps bool `json:"manage_custom_apps,omitempty" yaml:"manage_custom_apps,omitempty"`

	// manage gateways
	ManageGateways bool `json:"manage_gateways,omitempty" yaml:"manage_gateways,omitempty"`

	// manage idps
	ManageIdps bool `json:"manage_idps,omitempty" yaml:"manage_idps,omitempty"`

	// manage manager role
	ManageManagerRole bool `json:"manage_manager_role,omitempty" yaml:"manage_manager_role,omitempty"`

	// manage member role
	ManageMemberRole bool `json:"manage_member_role,omitempty" yaml:"manage_member_role,omitempty"`

	// manage policies
	ManagePolicies bool `json:"manage_policies,omitempty" yaml:"manage_policies,omitempty"`

	// manage scripts
	ManageScripts bool `json:"manage_scripts,omitempty" yaml:"manage_scripts,omitempty"`

	// manage secrets
	ManageSecrets bool `json:"manage_secrets,omitempty" yaml:"manage_secrets,omitempty"`

	// manage services
	ManageServices bool `json:"manage_services,omitempty" yaml:"manage_services,omitempty"`

	// manage user manager role
	ManageUserManagerRole bool `json:"manage_user_manager_role,omitempty" yaml:"manage_user_manager_role,omitempty"`

	// manage webhooks
	ManageWebhooks bool `json:"manage_webhooks,omitempty" yaml:"manage_webhooks,omitempty"`

	// read analytics
	ReadAnalytics bool `json:"read_analytics,omitempty" yaml:"read_analytics,omitempty"`

	// read apis
	ReadApis bool `json:"read_apis,omitempty" yaml:"read_apis,omitempty"`

	// read audit events
	ReadAuditEvents bool `json:"read_audit_events,omitempty" yaml:"read_audit_events,omitempty"`

	// read authorization details
	ReadAuthorizationDetails bool `json:"read_authorization_details,omitempty" yaml:"read_authorization_details,omitempty"`

	// read claims
	ReadClaims bool `json:"read_claims,omitempty" yaml:"read_claims,omitempty"`

	// read clients
	ReadClients bool `json:"read_clients,omitempty" yaml:"read_clients,omitempty"`

	// read custom apps
	ReadCustomApps bool `json:"read_custom_apps,omitempty" yaml:"read_custom_apps,omitempty"`

	// read gateways
	ReadGateways bool `json:"read_gateways,omitempty" yaml:"read_gateways,omitempty"`

	// read idps
	ReadIdps bool `json:"read_idps,omitempty" yaml:"read_idps,omitempty"`

	// read policies
	ReadPolicies bool `json:"read_policies,omitempty" yaml:"read_policies,omitempty"`

	// read roles
	ReadRoles bool `json:"read_roles,omitempty" yaml:"read_roles,omitempty"`

	// read scripts
	ReadScripts bool `json:"read_scripts,omitempty" yaml:"read_scripts,omitempty"`

	// read secrets
	ReadSecrets bool `json:"read_secrets,omitempty" yaml:"read_secrets,omitempty"`

	// read services
	ReadServices bool `json:"read_services,omitempty" yaml:"read_services,omitempty"`

	// read webhooks
	ReadWebhooks bool `json:"read_webhooks,omitempty" yaml:"read_webhooks,omitempty"`

	// update organization
	UpdateOrganization bool `json:"update_organization,omitempty" yaml:"update_organization,omitempty"`

	// update workspace
	UpdateWorkspace bool `json:"update_workspace,omitempty" yaml:"update_workspace,omitempty"`

	// update workspace metadata
	UpdateWorkspaceMetadata bool `json:"update_workspace_metadata,omitempty" yaml:"update_workspace_metadata,omitempty"`
}

// Validate validates this workspace permissions response
func (m *WorkspacePermissionsResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this workspace permissions response based on context it is used
func (m *WorkspacePermissionsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *WorkspacePermissionsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WorkspacePermissionsResponse) UnmarshalBinary(b []byte) error {
	var res WorkspacePermissionsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
