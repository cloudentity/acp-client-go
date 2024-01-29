// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FDXConsentGrantParty Consent Party entity
// Details on the non-end user parties in the Consent Grant. Includes the legal entity operating branded products or services
// in the data sharing chain. Descriptive information is collected during Data Recipient registration at Data Provider,
// and populated during issuance by Data Provider from its registry
//
// swagger:model FDXConsentGrantParty
type FDXConsentGrantParty struct {

	// URL for party, where an end user could learn more about the company or application involved in the data sharing chain
	HomeURI string `json:"homeUri,omitempty" yaml:"homeUri,omitempty"`

	// URL for a logo asset to be displayed to the end user
	LogoURI string `json:"logoUri,omitempty" yaml:"logoUri,omitempty"`

	// Common name for party, as it should be displayed to the end user
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Registered id of party
	RegisteredEntityIdentifier string `json:"registeredEntityIdentifier,omitempty" yaml:"registeredEntityIdentifier,omitempty"`

	// Registered name of party
	RegisteredEntityName string `json:"registeredEntityName,omitempty" yaml:"registeredEntityName,omitempty"`

	// The registry with the party's registered name and id
	RegistryName string `json:"registryName,omitempty" yaml:"registryName,omitempty"`
}

// Validate validates this f d x consent grant party
func (m *FDXConsentGrantParty) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this f d x consent grant party based on context it is used
func (m *FDXConsentGrantParty) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FDXConsentGrantParty) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FDXConsentGrantParty) UnmarshalBinary(b []byte) error {
	var res FDXConsentGrantParty
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
