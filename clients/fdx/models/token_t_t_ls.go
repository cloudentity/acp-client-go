// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TokenTTLs token t t ls
//
// swagger:model TokenTTLs
type TokenTTLs struct {

	// Access token time to live
	//
	// After an access token reaches its time to live, it expires and it cannot be used to
	// authenticate the client application.
	// Example: 1h10m30s
	// Format: duration
	AccessTokenTTL strfmt.Duration `json:"access_token_ttl,omitempty"`

	// Authorization code time to live
	//
	// After an authorization code reaches its time to live, it expires and it cannot be used to
	// authorize the request to the `/token` endpoint.
	// Example: 10m0s
	// Format: duration
	AuthorizationCodeTTL strfmt.Duration `json:"authorization_code_ttl,omitempty"`

	// ID token time to live
	//
	// After an ID token reaches its time to live, it expires and it cannot be used to provide
	// user profile information to a client application.
	// Example: 1h10m30s
	// Format: duration
	IDTokenTTL strfmt.Duration `json:"id_token_ttl,omitempty"`

	// Refresh token time to live
	//
	// After a refresh token reaches its time to live, it expires and it cannot be used to obtain
	// new access tokens for a client application.
	// Example: 720h0m0s
	// Format: duration
	RefreshTokenTTL strfmt.Duration `json:"refresh_token_ttl,omitempty"`
}

// Validate validates this token t t ls
func (m *TokenTTLs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthorizationCodeTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIDTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRefreshTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TokenTTLs) validateAccessTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.AccessTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("access_token_ttl", "body", "duration", m.AccessTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *TokenTTLs) validateAuthorizationCodeTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthorizationCodeTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("authorization_code_ttl", "body", "duration", m.AuthorizationCodeTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *TokenTTLs) validateIDTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.IDTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("id_token_ttl", "body", "duration", m.IDTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *TokenTTLs) validateRefreshTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.RefreshTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("refresh_token_ttl", "body", "duration", m.RefreshTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this token t t ls based on context it is used
func (m *TokenTTLs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TokenTTLs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TokenTTLs) UnmarshalBinary(b []byte) error {
	var res TokenTTLs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}