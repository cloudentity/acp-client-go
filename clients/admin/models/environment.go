// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Environment environment
//
// swagger:model Environment
type Environment struct {

	// add fake tenantUrl to query params for routing other than default (needed for backward compatibility with CIP for vanity domains)
	AddFakeTenantURLToLoginRequestForNonDefaultRouting bool `json:"add_fake_tenant_url_to_login_request_for_non_default_routing,omitempty" yaml:"add_fake_tenant_url_to_login_request_for_non_default_routing,omitempty"`

	// admin issuer url
	AdminIssuerURL string `json:"admin_issuer_url,omitempty" yaml:"admin_issuer_url,omitempty"`

	// Admin portal face lifting
	//
	// Improve user experience by facelifting the basic components of Cloudentity.
	AdminPortalFaceLifting bool `json:"admin_portal_face_lifting,omitempty" yaml:"admin_portal_face_lifting,omitempty"`

	// admin workspace access
	AdminWorkspaceAccess bool `json:"admin_workspace_access,omitempty" yaml:"admin_workspace_access,omitempty"`

	// analytics duration
	// Format: duration
	AnalyticsDuration strfmt.Duration `json:"analytics_duration,omitempty" yaml:"analytics_duration,omitempty"`

	// audit events duration
	// Format: duration
	AuditEventsDuration strfmt.Duration `json:"audit_events_duration,omitempty" yaml:"audit_events_duration,omitempty"`

	// block access to a tenant's resources from traffic not originating from the tenant's vanity domain
	BlockNonVanityDomainAccess bool `json:"block_non_vanity_domain_access,omitempty" yaml:"block_non_vanity_domain_access,omitempty"`

	// brute force limits
	BruteForceLimits *DefaultBruteForceLimits `json:"brute_force_limits,omitempty" yaml:"brute_force_limits,omitempty"`

	// cache access tokens
	CacheAccessTokens bool `json:"cache_access_tokens,omitempty" yaml:"cache_access_tokens,omitempty"`

	// add previous arrangement to CDR amend audit event
	CdrAmendAuditEventWithPreviousArrangement bool `json:"cdr_amend_audit_event_with_previous_arrangement,omitempty" yaml:"cdr_amend_audit_event_with_previous_arrangement,omitempty"`

	// arrangement cache for CDR
	CdrArrangementCache bool `json:"cdr_arrangement_cache,omitempty" yaml:"cdr_arrangement_cache,omitempty"`

	// disable unique software id for CDR
	CdrDisableUniqueSoftwareID bool `json:"cdr_disable_unique_software_id,omitempty" yaml:"cdr_disable_unique_software_id,omitempty"`

	// stores client secrets as one-way hashes
	ClientSecretsStoredAsOneWayHash bool `json:"client_secrets_stored_as_one_way_hash,omitempty" yaml:"client_secrets_stored_as_one_way_hash,omitempty"`

	// Cloudentity IDP
	CloudentityIdp bool `json:"cloudentity_idp,omitempty" yaml:"cloudentity_idp,omitempty"`

	// commit
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`

	// connectID profile
	ConnectID bool `json:"connect_id,omitempty" yaml:"connect_id,omitempty"`

	// connect ID consent page facelifting
	ConnectIDConsentPageFaceLifting bool `json:"connect_id_consent_page_face_lifting,omitempty" yaml:"connect_id_consent_page_face_lifting,omitempty"`

	// enable additional debug logs
	Debug bool `json:"debug,omitempty" yaml:"debug,omitempty"`

	// allow the usage of dedicated FaaS Rego/JS environments
	DedicatedFaas bool `json:"dedicated_faas,omitempty" yaml:"dedicated_faas,omitempty"`

	// demo app
	DemoApp bool `json:"demo_app,omitempty" yaml:"demo_app,omitempty"`

	// hot reloading of templates
	DevMode bool `json:"dev_mode,omitempty" yaml:"dev_mode,omitempty"`

	// disable audit events
	DisableAuditEvents bool `json:"disable_audit_events,omitempty" yaml:"disable_audit_events,omitempty"`

	// disable embedded sms provider
	DisableEmbeddedSmsProvider bool `json:"disable_embedded_sms_provider,omitempty" yaml:"disable_embedded_sms_provider,omitempty"`

	// display workspace wizard
	DisplayWorkspaceWizard bool `json:"display_workspace_wizard,omitempty" yaml:"display_workspace_wizard,omitempty"`

	// do not validate cert for private key jwt
	DoNotValidateCertForPrivateKeyJwt bool `json:"do_not_validate_cert_for_private_key_jwt,omitempty" yaml:"do_not_validate_cert_for_private_key_jwt,omitempty"`

	// drop tokens on password reset
	DropTokensOnPasswordReset bool `json:"drop_tokens_on_password_reset,omitempty" yaml:"drop_tokens_on_password_reset,omitempty"`

	// grpc url
	GrpcURL string `json:"grpc_url,omitempty" yaml:"grpc_url,omitempty"`

	// has google image search
	HasGoogleImageSearch bool `json:"has_google_image_search,omitempty" yaml:"has_google_image_search,omitempty"`

	// Identifier-based discovery
	//
	// Enable users to provide their identifier first during user authentication and discover their preffered authentication provider.
	IdentifierBasedDiscovery bool `json:"identifier_based_discovery,omitempty" yaml:"identifier_based_discovery,omitempty"`

	// identity assurance
	IdentityAssurance bool `json:"identity_assurance,omitempty" yaml:"identity_assurance,omitempty"`

	// Identity Pool MFA
	//
	// Enable MFA for Identity Pool
	IdentityPoolMfa bool `json:"identity_pool_mfa,omitempty" yaml:"identity_pool_mfa,omitempty"`

	// image proxy url
	ImageProxyURL string `json:"image_proxy_url,omitempty" yaml:"image_proxy_url,omitempty"`

	// when enabled and the display_workspace_wizard feature flag is set to true, a demo workspace with a set of preconfigured IDPs is created and no welcome screen is displayed
	InitializeDemoWorkspace bool `json:"initialize_demo_workspace,omitempty" yaml:"initialize_demo_workspace,omitempty"`

	// disable csrf
	InsecureDisableCsrf bool `json:"insecure_disable_csrf,omitempty" yaml:"insecure_disable_csrf,omitempty"`

	// insecure token exchange public clients
	InsecureTokenExchangePublicClients bool `json:"insecure_token_exchange_public_clients,omitempty" yaml:"insecure_token_exchange_public_clients,omitempty"`

	// Enforce JIT users roles
	JitPermissions bool `json:"jit_permissions,omitempty" yaml:"jit_permissions,omitempty"`

	// mark address as verified on any proof of possession of the address
	MarkAddressAsVerifiedOnAnyProofOfPossession bool `json:"mark_address_as_verified_on_any_proof_of_possession,omitempty" yaml:"mark_address_as_verified_on_any_proof_of_possession,omitempty"`

	// openbanking ksa workspace and security profile
	OpenbankingKsa bool `json:"openbanking_ksa,omitempty" yaml:"openbanking_ksa,omitempty"`

	// Organizations
	//
	// Delineate a structured and hierarchical separation among your business customers' companies or partners. Enable Delegated Admin Portal.
	Organizations bool `json:"organizations,omitempty" yaml:"organizations,omitempty"`

	// Permissions
	//
	// Control access to resources based on user permissions. Create permission systems.
	Permissions bool `json:"permissions,omitempty" yaml:"permissions,omitempty"`

	// rich authorization requests
	Rar bool `json:"rar,omitempty" yaml:"rar,omitempty"`

	// Roles
	//
	// Control access to Cloudentity based on user roles. Invite tenant admins, workspace admins, or business admins.
	Roles bool `json:"roles,omitempty" yaml:"roles,omitempty"`

	// Enable SAML V2
	SamlV2 bool `json:"saml_v2,omitempty" yaml:"saml_v2,omitempty"`

	// scope transient_otp
	ScopeTransientOtp bool `json:"scope_transient_otp,omitempty" yaml:"scope_transient_otp,omitempty"`

	// script runtimes
	ScriptRuntimes []*ScriptRuntime `json:"script_runtimes" yaml:"script_runtimes"`

	// Scripts runtime versions
	//
	// Enable users to manage runtime versions for scripts.
	ScriptsRuntimeVersions bool `json:"scripts_runtime_versions,omitempty" yaml:"scripts_runtime_versions,omitempty"`

	// Self-service
	//
	// Enable users to manage their accounts using the self-service view. Allow users to adjust their profile, see their sign-in methods, authorized applications, and more.
	SelfService bool `json:"self_service,omitempty" yaml:"self_service,omitempty"`

	// simple api integration
	SimpleAPIIntegration bool `json:"simple_api_integration,omitempty" yaml:"simple_api_integration,omitempty"`

	// swagger ui
	SwaggerUI bool `json:"swagger_ui,omitempty" yaml:"swagger_ui,omitempty"`

	// system flags
	SystemFlags []string `json:"system_flags" yaml:"system_flags"`

	// system workspace access
	SystemWorkspaceAccess bool `json:"system_workspace_access,omitempty" yaml:"system_workspace_access,omitempty"`

	// tenant flags
	TenantFlags []string `json:"tenant_flags" yaml:"tenant_flags"`

	// tenant settings
	TenantSettings *TenantSettings `json:"tenant_settings,omitempty" yaml:"tenant_settings,omitempty"`

	// hierarchical dumps tenant APIs
	TreeDumpTenant bool `json:"tree_dump_tenant,omitempty" yaml:"tree_dump_tenant,omitempty"`

	// version
	Version string `json:"version,omitempty" yaml:"version,omitempty"`

	// with analytics
	WithAnalytics bool `json:"with_analytics,omitempty" yaml:"with_analytics,omitempty"`

	// with permissions
	WithPermissions bool `json:"with_permissions,omitempty" yaml:"with_permissions,omitempty"`

	// with roles
	WithRoles bool `json:"with_roles,omitempty" yaml:"with_roles,omitempty"`
}

// Validate validates this environment
func (m *Environment) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAnalyticsDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuditEventsDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBruteForceLimits(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScriptRuntimes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantSettings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Environment) validateAnalyticsDuration(formats strfmt.Registry) error {
	if swag.IsZero(m.AnalyticsDuration) { // not required
		return nil
	}

	if err := validate.FormatOf("analytics_duration", "body", "duration", m.AnalyticsDuration.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Environment) validateAuditEventsDuration(formats strfmt.Registry) error {
	if swag.IsZero(m.AuditEventsDuration) { // not required
		return nil
	}

	if err := validate.FormatOf("audit_events_duration", "body", "duration", m.AuditEventsDuration.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Environment) validateBruteForceLimits(formats strfmt.Registry) error {
	if swag.IsZero(m.BruteForceLimits) { // not required
		return nil
	}

	if m.BruteForceLimits != nil {
		if err := m.BruteForceLimits.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("brute_force_limits")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("brute_force_limits")
			}
			return err
		}
	}

	return nil
}

func (m *Environment) validateScriptRuntimes(formats strfmt.Registry) error {
	if swag.IsZero(m.ScriptRuntimes) { // not required
		return nil
	}

	for i := 0; i < len(m.ScriptRuntimes); i++ {
		if swag.IsZero(m.ScriptRuntimes[i]) { // not required
			continue
		}

		if m.ScriptRuntimes[i] != nil {
			if err := m.ScriptRuntimes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("script_runtimes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("script_runtimes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Environment) validateTenantSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.TenantSettings) { // not required
		return nil
	}

	if m.TenantSettings != nil {
		if err := m.TenantSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tenant_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("tenant_settings")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this environment based on the context it is used
func (m *Environment) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBruteForceLimits(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScriptRuntimes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTenantSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Environment) contextValidateBruteForceLimits(ctx context.Context, formats strfmt.Registry) error {

	if m.BruteForceLimits != nil {

		if swag.IsZero(m.BruteForceLimits) { // not required
			return nil
		}

		if err := m.BruteForceLimits.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("brute_force_limits")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("brute_force_limits")
			}
			return err
		}
	}

	return nil
}

func (m *Environment) contextValidateScriptRuntimes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ScriptRuntimes); i++ {

		if m.ScriptRuntimes[i] != nil {

			if swag.IsZero(m.ScriptRuntimes[i]) { // not required
				return nil
			}

			if err := m.ScriptRuntimes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("script_runtimes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("script_runtimes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Environment) contextValidateTenantSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.TenantSettings != nil {

		if swag.IsZero(m.TenantSettings) { // not required
			return nil
		}

		if err := m.TenantSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tenant_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("tenant_settings")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Environment) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Environment) UnmarshalBinary(b []byte) error {
	var res Environment
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
