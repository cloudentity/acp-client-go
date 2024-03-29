// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TokensRevokedPayload tokens revoked payload
//
// swagger:model TokensRevokedPayload
type TokensRevokedPayload struct {

	// consent ID for which the token has been revoked (populated only if type equals consent)
	ConsentID string `json:"consent_id,omitempty" yaml:"consent_id,omitempty"`

	// entity type for which token has been revoked
	// Example: consent
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this tokens revoked payload
func (m *TokensRevokedPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this tokens revoked payload based on context it is used
func (m *TokensRevokedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TokensRevokedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TokensRevokedPayload) UnmarshalBinary(b []byte) error {
	var res TokensRevokedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
