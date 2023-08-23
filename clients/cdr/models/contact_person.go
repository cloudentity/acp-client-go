// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ContactPerson ContactPerson represents the SAML element ContactPerson.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.2
//
// swagger:model ContactPerson
type ContactPerson struct {

	// company
	Company string `json:"Company,omitempty"`

	// contact type
	ContactType string `json:"ContactType,omitempty"`

	// email addresses
	EmailAddresses []string `json:"EmailAddresses"`

	// given name
	GivenName string `json:"GivenName,omitempty"`

	// sur name
	SurName string `json:"SurName,omitempty"`

	// telephone numbers
	TelephoneNumbers []string `json:"TelephoneNumbers"`
}

// Validate validates this contact person
func (m *ContactPerson) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this contact person based on context it is used
func (m *ContactPerson) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ContactPerson) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ContactPerson) UnmarshalBinary(b []byte) error {
	var res ContactPerson
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}