// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Features features
//
// swagger:model Features
type Features struct {

	// enable admin workspace access (tenant)
	AdminWorkspaceAccess bool `json:"admin_workspace_access,omitempty"`

	// enable analytics (tenant)
	Analytics bool `json:"analytics,omitempty"`

	// enable analytics v2 (tenant)
	AnalyticsV2 bool `json:"analytics_v2,omitempty"`

	// enable Application Builder UI (tenant)
	ApplicationBuilderUI bool `json:"application_builder_ui,omitempty"`

	// enable ciba (system)
	Ciba bool `json:"ciba,omitempty"`

	// store client secrets as a one way hash (tenant)
	ClientSecretsStoredAsOneWayHash bool `json:"client_secrets_stored_as_one_way_hash,omitempty"`

	// enable demo app endpoints (system)
	DemoApp bool `json:"demo_app,omitempty"`

	// realod templates and adds local redirects urls to frontend apps (system)
	DevMode bool `json:"dev_mode,omitempty"`

	// enable pushing events to elasticsearch (system)
	Elasticsearch bool `json:"elasticsearch,omitempty"`

	// extended audit events retention
	ExtendedAuditEventsRetention bool `json:"extended_audit_events_retention,omitempty"`

	// enable external datastore idp (system)
	ExternalDatastore bool `json:"external_datastore,omitempty"`

	// FDX (tenant)
	Fdx bool `json:"fdx,omitempty"`

	// enable Identity Pools (tenant)
	IdentityPools bool `json:"identity_pools,omitempty"`

	// when enabled and the display_workspace_wizard feature flag is set to true, a demo workspace with a set of preconfigured IDPs is created and no welcome screen is displayed (tenant)
	InitializeDemoWorkspace bool `json:"initialize_demo_workspace,omitempty"`

	// enable global import and export configuration endpoints (system)
	IntegrationEndpoints bool `json:"integration_endpoints,omitempty"`

	// enable login with select_account param (tenant)
	LoginWithSelectAccount bool `json:"login_with_select_account,omitempty"`

	// enable when ACP is running on-prem and Pyron is used as a gateway (tenant)
	PyronOnPrem bool `json:"pyron_on_prem,omitempty"`

	// enable quick access functionality on UI (system)
	QuickAccess bool `json:"quick_access,omitempty"`

	// enable scope transient_otp (tenant)
	ScopeTransientOtp bool `json:"scope_transient_otp,omitempty"`

	// enable the javascript transformer (tenant)
	ScriptTransformer bool `json:"script_transformer,omitempty"`

	// enable custom scripts (tenant)
	Scripts bool `json:"scripts,omitempty"`

	// enable swagger ui (system)
	SwaggerUI bool `json:"swagger_ui,omitempty"`

	// enable system client management APIs (system)
	SystemClientsManagement bool `json:"system_clients_management,omitempty"`

	// enable admin workspace access (tenant)
	SystemWorkspaceAccess bool `json:"system_workspace_access,omitempty"`

	// enable Token Exchange (system)
	TokenExchange bool `json:"token_exchange,omitempty"`

	// enable Token Exchange for authorizers (tenant)
	TokenExchangeForAuthorizers bool `json:"token_exchange_for_authorizers,omitempty"`

	// enable trust anchor integration (system)
	TrustAnchorIntegration bool `json:"trust_anchor_integration,omitempty"`
}

// Validate validates this features
func (m *Features) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this features based on context it is used
func (m *Features) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Features) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Features) UnmarshalBinary(b []byte) error {
	var res Features
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
