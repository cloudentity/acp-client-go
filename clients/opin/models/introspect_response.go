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

// IntrospectResponse introspect response
//
// swagger:model IntrospectResponse
type IntrospectResponse struct {

	// Authentication context class reference
	Acr string `json:"acr,omitempty"`

	// Actor claims used in the Token Exchange flow.
	Act map[string]interface{} `json:"act,omitempty"`

	// Active is a boolean indicator of whether or not the presented token
	// is currently active. The specifics of a token's `active` state
	// varies depending on the implementation of an authorization
	// server and the information it keeps about its token. Still, the `true`
	// value returned for the `active` property generally indicates
	// that a given token has been issued by this authorization server,
	// has not been revoked by the resource owner, and is within its
	// given time window of validity (e.g., between its issuance and
	// expiration time).
	Active bool `json:"active,omitempty"`

	// Authentication method references
	Amr []string `json:"amr"`

	// Audience contains the list of the audiences the token is intended for.
	Aud []string `json:"aud"`

	// A client application identifier for the OAuth 2.0 client that
	// requested this token.
	ClientID string `json:"client_id,omitempty"`

	// cnf
	Cnf *Confirmation `json:"cnf,omitempty"`

	// ExpiredAt is the integer timestamp measured in the number of seconds
	// since January 1 1970 UTC (1970-01-01T00:00:00Z). It indicates when this token will expire.
	Exp int64 `json:"exp,omitempty"`

	// Extra is arbitrary data set by the session.
	Ext map[string]interface{} `json:"ext,omitempty"`

	// IssuedAt is the integer timestamp measured in the number of seconds
	// since January 1 1970 UTC. It indicates when this token was
	// originally issued.
	Iat int64 `json:"iat,omitempty"`

	// The identifier of an identity provider that user authenticated with.
	Idp string `json:"idp,omitempty"`

	// IDP subject
	IdpSub string `json:"idp_sub,omitempty"`

	// Issuer URL is a string representing the issuer of this token.
	Iss string `json:"iss,omitempty"`

	// May act claims used in the Token Exchange flow.s
	MayAct map[string]interface{} `json:"may_act,omitempty"`

	// NotBefore is an integer timestamp measured in the number of seconds
	// since January 1 1970 UTC. It indicates this token was not
	// used before the specified time.
	Nbf int64 `json:"nbf,omitempty"`

	// Scope is a JSON string containing a space-separated list of
	// scopes associated with this token.
	Scope string `json:"scope,omitempty"`

	// The OAuth 2.0 authorization server identifier that
	// issued this token.
	ServerID string `json:"server_id,omitempty"`

	// Subject of the token, as defined in JWT [RFC7519].
	// Usually a machine-readable identifier of the resource owner who
	// authorized this token.
	Sub string `json:"sub,omitempty"`

	// TenantID identifies a tenant holding the authorization server that
	// issued this token.
	TenantID string `json:"tenant_id,omitempty"`

	// TokenType is the type of the introspected token. For example, `access_token` or `refresh_token`.
	TokenType string `json:"token_type,omitempty"`

	// Username is a human-readable identifier for the resource owner who
	// authorized this token.
	Username string `json:"username,omitempty"`
}

// Validate validates this introspect response
func (m *IntrospectResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCnf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IntrospectResponse) validateCnf(formats strfmt.Registry) error {
	if swag.IsZero(m.Cnf) { // not required
		return nil
	}

	if m.Cnf != nil {
		if err := m.Cnf.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cnf")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cnf")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this introspect response based on the context it is used
func (m *IntrospectResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCnf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IntrospectResponse) contextValidateCnf(ctx context.Context, formats strfmt.Registry) error {

	if m.Cnf != nil {

		if swag.IsZero(m.Cnf) { // not required
			return nil
		}

		if err := m.Cnf.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cnf")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cnf")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IntrospectResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IntrospectResponse) UnmarshalBinary(b []byte) error {
	var res IntrospectResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
