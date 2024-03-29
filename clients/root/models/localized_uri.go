// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// LocalizedURI LocalizedURI represents the SAML type localizedURIType.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.5
//
// swagger:model LocalizedURI
type LocalizedURI struct {

	// lang
	Lang string `json:"Lang,omitempty" yaml:"Lang,omitempty"`

	// value
	Value string `json:"Value,omitempty" yaml:"Value,omitempty"`
}

// Validate validates this localized URI
func (m *LocalizedURI) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this localized URI based on context it is used
func (m *LocalizedURI) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LocalizedURI) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LocalizedURI) UnmarshalBinary(b []byte) error {
	var res LocalizedURI
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
