// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FDXParty f d x party
//
// swagger:model FDXParty
type FDXParty struct {

	// home uri
	HomeURI string `json:"home_uri,omitempty" yaml:"home_uri,omitempty"`

	// logo uri
	LogoURI string `json:"logo_uri,omitempty" yaml:"logo_uri,omitempty"`

	// name
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// registered entity identifier
	RegisteredEntityIdentifier string `json:"registered_entity_identifier,omitempty" yaml:"registered_entity_identifier,omitempty"`

	// registered entity name
	RegisteredEntityName string `json:"registered_entity_name,omitempty" yaml:"registered_entity_name,omitempty"`

	// registry name
	RegistryName string `json:"registry_name,omitempty" yaml:"registry_name,omitempty"`
}

// Validate validates this f d x party
func (m *FDXParty) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this f d x party based on context it is used
func (m *FDXParty) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FDXParty) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FDXParty) UnmarshalBinary(b []byte) error {
	var res FDXParty
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
