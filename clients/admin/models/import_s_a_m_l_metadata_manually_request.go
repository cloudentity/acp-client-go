// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ImportSAMLMetadataManuallyRequest import s a m l metadata manually request
//
// swagger:model ImportSAMLMetadataManuallyRequest
type ImportSAMLMetadataManuallyRequest struct {

	// SAML SP ACS URL
	AcsURL string `json:"acs_url,omitempty" yaml:"acs_url,omitempty"`

	// SAML SP signing and encrypotion certificate
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`

	// SAML SP entity ID
	EntityID string `json:"entity_id,omitempty" yaml:"entity_id,omitempty"`

	// SAML SP SSO binding method
	SsoBindingMethod string `json:"sso_binding_method,omitempty" yaml:"sso_binding_method,omitempty"`
}

// Validate validates this import s a m l metadata manually request
func (m *ImportSAMLMetadataManuallyRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this import s a m l metadata manually request based on context it is used
func (m *ImportSAMLMetadataManuallyRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ImportSAMLMetadataManuallyRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ImportSAMLMetadataManuallyRequest) UnmarshalBinary(b []byte) error {
	var res ImportSAMLMetadataManuallyRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
