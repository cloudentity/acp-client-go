// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SAMLCredentials s a m l credentials
//
// swagger:model SAMLCredentials
type SAMLCredentials struct {

	// idp certificate, must start with -----BEGIN CERTIFICATE----- and end with -----END CERTIFICATE-----
	IdpCertificate string `json:"idp_certificate,omitempty"`
}

// Validate validates this s a m l credentials
func (m *SAMLCredentials) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLCredentials) UnmarshalBinary(b []byte) error {
	var res SAMLCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
