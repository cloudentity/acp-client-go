// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SAMLV2Credentials s a m l v2 credentials
//
// swagger:model SAMLV2Credentials
type SAMLV2Credentials struct {

	// saml authn request signing cert
	SigningCert string `json:"signing_cert,omitempty" yaml:"signing_cert,omitempty"`

	// saml authn request signing key
	SigningKey string `json:"signing_key,omitempty" yaml:"signing_key,omitempty"`
}

// Validate validates this s a m l v2 credentials
func (m *SAMLV2Credentials) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this s a m l v2 credentials based on context it is used
func (m *SAMLV2Credentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLV2Credentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLV2Credentials) UnmarshalBinary(b []byte) error {
	var res SAMLV2Credentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
