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

// PrivateKeyJWTCredentials PrivateKeyJWT authentication settings
//
// swagger:model PrivateKeyJWTCredentials
type PrivateKeyJWTCredentials struct {

	// Algorithm used to sign the client_assertion (see JWS) - default RS256
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`

	// ExpiresIn defines how long client_assertion is valid for - default 30 seconds
	// Format: duration
	Exp strfmt.Duration `json:"exp,omitempty" yaml:"exp,omitempty"`

	// Key is a PEM formatted private key used to sign client_assertion
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
}

// Validate validates this private key j w t credentials
func (m *PrivateKeyJWTCredentials) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PrivateKeyJWTCredentials) validateExp(formats strfmt.Registry) error {
	if swag.IsZero(m.Exp) { // not required
		return nil
	}

	if err := validate.FormatOf("exp", "body", "duration", m.Exp.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this private key j w t credentials based on context it is used
func (m *PrivateKeyJWTCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PrivateKeyJWTCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PrivateKeyJWTCredentials) UnmarshalBinary(b []byte) error {
	var res PrivateKeyJWTCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
