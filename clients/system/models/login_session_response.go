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

// LoginSessionResponse login session response
//
// swagger:model LoginSessionResponse
type LoginSessionResponse struct {

	// authentication context class reference
	Acr string `json:"acr,omitempty" yaml:"acr,omitempty"`

	// scopes that passed policy validation
	AllowedScopes map[string]bool `json:"allowed_scopes,omitempty" yaml:"allowed_scopes,omitempty"`

	// authentication methods references
	Amr []string `json:"amr" yaml:"amr"`

	// time when user authenticated
	// Format: date-time
	AuthTime strfmt.DateTime `json:"auth_time,omitempty" yaml:"auth_time,omitempty"`

	// authentication context
	AuthenticationContext AuthenticationContext `json:"authentication_context,omitempty" yaml:"authentication_context,omitempty"`

	// authorization correlation id
	AuthorizationCorrelationID string `json:"authorization_correlation_id,omitempty" yaml:"authorization_correlation_id,omitempty"`

	// authorization details
	AuthorizationDetails []map[string]interface{} `json:"authorization_details" yaml:"authorization_details"`

	// OAuth client identifier
	// Example: default
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// client info
	ClientInfo *ClientInfo `json:"client_info,omitempty" yaml:"client_info,omitempty"`

	// error
	Error *RFC6749Error `json:"error,omitempty" yaml:"error,omitempty"`

	// list of granted audience
	GrantedAudience []string `json:"granted_audience" yaml:"granted_audience"`

	// list of granted scopes
	// Example: ["email","profile","openid"]
	GrantedScopes []string `json:"granted_scopes" yaml:"granted_scopes"`

	// unique id of login session
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// idp identifier
	IdpID string `json:"idp_id,omitempty" yaml:"idp_id,omitempty"`

	// idp subject
	IdpSubject string `json:"idp_subject,omitempty" yaml:"idp_subject,omitempty"`

	// is login approved
	// Example: false
	LoginApproved bool `json:"login_approved,omitempty" yaml:"login_approved,omitempty"`

	// is login rejected
	// Example: false
	LoginRejected bool `json:"login_rejected,omitempty" yaml:"login_rejected,omitempty"`

	// max age for a session to live
	// Format: duration
	MaxAge strfmt.Duration `json:"max_age,omitempty" yaml:"max_age,omitempty"`

	// request query params
	RequestQueryParams Values `json:"request_query_params,omitempty" yaml:"request_query_params,omitempty"`

	// original url requested by oauth client
	RequestURL string `json:"request_url,omitempty" yaml:"request_url,omitempty"`

	// requested acr
	RequestedAcr []string `json:"requested_acr" yaml:"requested_acr"`

	// time when oauth client made a request
	// Format: date-time
	RequestedAt strfmt.DateTime `json:"requested_at,omitempty" yaml:"requested_at,omitempty"`

	// list of requested audiences
	RequestedAudience []string `json:"requested_audience" yaml:"requested_audience"`

	// requested claims
	RequestedClaims *ClaimsRequests `json:"requested_claims,omitempty" yaml:"requested_claims,omitempty"`

	// requested claims to display on consent page
	RequestedClaimsToConsent []string `json:"requested_claims_to_consent" yaml:"requested_claims_to_consent"`

	// requested grant type
	RequestedGrantType string `json:"requested_grant_type,omitempty" yaml:"requested_grant_type,omitempty"`

	// requested max age
	RequestedMaxAge string `json:"requested_max_age,omitempty" yaml:"requested_max_age,omitempty"`

	// requested redirect uri
	RequestedRedirectURI string `json:"requested_redirect_uri,omitempty" yaml:"requested_redirect_uri,omitempty"`

	// list of requested scopes
	RequestedScopes []*RequestedScope `json:"requested_scopes" yaml:"requested_scopes"`

	// requested verified claims
	RequestedVerifiedClaims *VerifiedClaimsRequests `json:"requested_verified_claims,omitempty" yaml:"requested_verified_claims,omitempty"`

	// is scope grant approved
	// Example: true
	ScopeGrantApproved bool `json:"scope_grant_approved,omitempty" yaml:"scope_grant_approved,omitempty"`

	// is scope grant rejected
	// Example: false
	ScopeGrantRejected bool `json:"scope_grant_rejected,omitempty" yaml:"scope_grant_rejected,omitempty"`

	// authorization server identifier
	// Example: default
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// user identifier
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`

	// tenant identifier
	// Example: default
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
}

// Validate validates this login session response
func (m *LoginSessionResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticationContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateError(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMaxAge(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestQueryParams(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedClaims(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedVerifiedClaims(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LoginSessionResponse) validateAuthTime(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthTime) { // not required
		return nil
	}

	if err := validate.FormatOf("auth_time", "body", "date-time", m.AuthTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *LoginSessionResponse) validateAuthenticationContext(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if m.AuthenticationContext != nil {
		if err := m.AuthenticationContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authentication_context")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) validateClientInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.ClientInfo) { // not required
		return nil
	}

	if m.ClientInfo != nil {
		if err := m.ClientInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) validateError(formats strfmt.Registry) error {
	if swag.IsZero(m.Error) { // not required
		return nil
	}

	if m.Error != nil {
		if err := m.Error.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("error")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) validateMaxAge(formats strfmt.Registry) error {
	if swag.IsZero(m.MaxAge) { // not required
		return nil
	}

	if err := validate.FormatOf("max_age", "body", "duration", m.MaxAge.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *LoginSessionResponse) validateRequestQueryParams(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestQueryParams) { // not required
		return nil
	}

	if m.RequestQueryParams != nil {
		if err := m.RequestQueryParams.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("request_query_params")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("request_query_params")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) validateRequestedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("requested_at", "body", "date-time", m.RequestedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *LoginSessionResponse) validateRequestedClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedClaims) { // not required
		return nil
	}

	if m.RequestedClaims != nil {
		if err := m.RequestedClaims.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("requested_claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("requested_claims")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) validateRequestedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedScopes) { // not required
		return nil
	}

	for i := 0; i < len(m.RequestedScopes); i++ {
		if swag.IsZero(m.RequestedScopes[i]) { // not required
			continue
		}

		if m.RequestedScopes[i] != nil {
			if err := m.RequestedScopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *LoginSessionResponse) validateRequestedVerifiedClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedVerifiedClaims) { // not required
		return nil
	}

	if m.RequestedVerifiedClaims != nil {
		if err := m.RequestedVerifiedClaims.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("requested_verified_claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("requested_verified_claims")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this login session response based on the context it is used
func (m *LoginSessionResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClientInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateError(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestQueryParams(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestedClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestedVerifiedClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LoginSessionResponse) contextValidateAuthenticationContext(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if err := m.AuthenticationContext.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_context")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_context")
		}
		return err
	}

	return nil
}

func (m *LoginSessionResponse) contextValidateClientInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.ClientInfo != nil {

		if swag.IsZero(m.ClientInfo) { // not required
			return nil
		}

		if err := m.ClientInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) contextValidateError(ctx context.Context, formats strfmt.Registry) error {

	if m.Error != nil {

		if swag.IsZero(m.Error) { // not required
			return nil
		}

		if err := m.Error.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("error")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) contextValidateRequestQueryParams(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.RequestQueryParams) { // not required
		return nil
	}

	if err := m.RequestQueryParams.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("request_query_params")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("request_query_params")
		}
		return err
	}

	return nil
}

func (m *LoginSessionResponse) contextValidateRequestedClaims(ctx context.Context, formats strfmt.Registry) error {

	if m.RequestedClaims != nil {

		if swag.IsZero(m.RequestedClaims) { // not required
			return nil
		}

		if err := m.RequestedClaims.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("requested_claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("requested_claims")
			}
			return err
		}
	}

	return nil
}

func (m *LoginSessionResponse) contextValidateRequestedScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RequestedScopes); i++ {

		if m.RequestedScopes[i] != nil {

			if swag.IsZero(m.RequestedScopes[i]) { // not required
				return nil
			}

			if err := m.RequestedScopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *LoginSessionResponse) contextValidateRequestedVerifiedClaims(ctx context.Context, formats strfmt.Registry) error {

	if m.RequestedVerifiedClaims != nil {

		if swag.IsZero(m.RequestedVerifiedClaims) { // not required
			return nil
		}

		if err := m.RequestedVerifiedClaims.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("requested_verified_claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("requested_verified_claims")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *LoginSessionResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginSessionResponse) UnmarshalBinary(b []byte) error {
	var res LoginSessionResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
