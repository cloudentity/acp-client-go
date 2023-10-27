// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OrganizationConfiguration organization configuration
//
// swagger:model OrganizationConfiguration
type OrganizationConfiguration struct {

	// An array of email domains configured for an organization for the purposes of IDP discovery
	Domains []string `json:"domains"`
}

// Validate validates this organization configuration
func (m *OrganizationConfiguration) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this organization configuration based on context it is used
func (m *OrganizationConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OrganizationConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OrganizationConfiguration) UnmarshalBinary(b []byte) error {
	var res OrganizationConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}