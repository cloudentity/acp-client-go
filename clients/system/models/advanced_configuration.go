// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// AdvancedConfiguration advanced configuration
//
// swagger:model AdvancedConfiguration
type AdvancedConfiguration struct {

	// Deprecated ACR values to enforce during auth flow (use new ACR feature instead)
	AcrValues []string `json:"acr_values" yaml:"acr_values"`

	// This option overrides all urls advertised by the well known endpoint with their mtls alias
	AdvertiseOnlyMtlsAliasesInWellKnown bool `json:"advertise_only_mtls_aliases_in_well_known,omitempty" yaml:"advertise_only_mtls_aliases_in_well_known,omitempty"`

	// Block response modes
	BlockResponseModes bool `json:"block_response_modes,omitempty" yaml:"block_response_modes,omitempty"`

	// cookies configuration
	CookiesConfiguration *CookiesConfiguration `json:"cookies_configuration,omitempty" yaml:"cookies_configuration,omitempty"`

	// Disable certificate-bound access tokens for new DCR clients
	//
	// If true, new DCR clients are created with CertificateBoundAccessToken disabled.
	DisableDcrClientCertificateBoundAccessTokens bool `json:"disable_dcr_client_certificate_bound_access_tokens,omitempty" yaml:"disable_dcr_client_certificate_bound_access_tokens,omitempty"`

	// Disable PAR
	DisablePar bool `json:"disable_par,omitempty" yaml:"disable_par,omitempty"`

	// Disable RAR
	DisableRar bool `json:"disable_rar,omitempty" yaml:"disable_rar,omitempty"`

	// Disable refresh token cycling
	//
	// Once disabled, original refresh token can be constantly used to issue new access token.
	DisableRefreshTokenCycling bool `json:"disable_refresh_token_cycling,omitempty" yaml:"disable_refresh_token_cycling,omitempty"`

	// When enabled, the authorization server will not accept access tokens supplied in the request query parameter
	// for protected resources endpoints.
	DisallowAccessTokenInQueryForProtectedResources bool `json:"disallow_access_token_in_query_for_protected_resources,omitempty" yaml:"disallow_access_token_in_query_for_protected_resources,omitempty"`

	// Disallow code response type without JARM
	DisallowCodeResponseTypeWithoutJarm bool `json:"disallow_code_response_type_without_jarm,omitempty" yaml:"disallow_code_response_type_without_jarm,omitempty"`

	// disallowed response modes
	DisallowedResponseModes ResponseModes `json:"disallowed_response_modes,omitempty" yaml:"disallowed_response_modes,omitempty"`

	// Do not issue acr claim in ID Token
	DoNotIssueAcrClaimInIDToken bool `json:"do_not_issue_acr_claim_in_id_token,omitempty" yaml:"do_not_issue_acr_claim_in_id_token,omitempty"`

	// Enforce acr values
	EnforceAcrValues bool `json:"enforce_acr_values,omitempty" yaml:"enforce_acr_values,omitempty"`

	// Ignore unknown scopes for DCR
	//
	// If enabled, an attempt to register or update a client with a scope that does not exist in the server will succeed.
	IgnoreUnknownScopesForDcr bool `json:"ignore_unknown_scopes_for_dcr,omitempty" yaml:"ignore_unknown_scopes_for_dcr,omitempty"`

	// Require request or request uri parameter for authorization flow
	RequireRequestOrRequestURIParameter bool `json:"require_request_or_request_uri_parameter,omitempty" yaml:"require_request_or_request_uri_parameter,omitempty"`

	// Return iss parameter in the authorization response
	ReturnIssParameterInAuthorizationResponse bool `json:"return_iss_parameter_in_authorization_response,omitempty" yaml:"return_iss_parameter_in_authorization_response,omitempty"`

	// Disables SSO as a fallback mechanism for post-logout redirect URI validation
	StrictPostLogoutRedirectEnforcement bool `json:"strict_post_logout_redirect_enforcement,omitempty" yaml:"strict_post_logout_redirect_enforcement,omitempty"`
}

// Validate validates this advanced configuration
func (m *AdvancedConfiguration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCookiesConfiguration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDisallowedResponseModes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AdvancedConfiguration) validateCookiesConfiguration(formats strfmt.Registry) error {
	if swag.IsZero(m.CookiesConfiguration) { // not required
		return nil
	}

	if m.CookiesConfiguration != nil {
		if err := m.CookiesConfiguration.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cookies_configuration")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cookies_configuration")
			}
			return err
		}
	}

	return nil
}

func (m *AdvancedConfiguration) validateDisallowedResponseModes(formats strfmt.Registry) error {
	if swag.IsZero(m.DisallowedResponseModes) { // not required
		return nil
	}

	if err := m.DisallowedResponseModes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("disallowed_response_modes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("disallowed_response_modes")
		}
		return err
	}

	return nil
}

// ContextValidate validate this advanced configuration based on the context it is used
func (m *AdvancedConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCookiesConfiguration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDisallowedResponseModes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AdvancedConfiguration) contextValidateCookiesConfiguration(ctx context.Context, formats strfmt.Registry) error {

	if m.CookiesConfiguration != nil {

		if swag.IsZero(m.CookiesConfiguration) { // not required
			return nil
		}

		if err := m.CookiesConfiguration.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cookies_configuration")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cookies_configuration")
			}
			return err
		}
	}

	return nil
}

func (m *AdvancedConfiguration) contextValidateDisallowedResponseModes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.DisallowedResponseModes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("disallowed_response_modes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("disallowed_response_modes")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AdvancedConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AdvancedConfiguration) UnmarshalBinary(b []byte) error {
	var res AdvancedConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
