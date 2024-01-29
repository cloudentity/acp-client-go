// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ExternalSettings External IDP specific settings
//
// swagger:model ExternalSettings
type ExternalSettings struct {

	// URL to your external datastore service
	// Example: https://example.com/
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
}

// Validate validates this external settings
func (m *ExternalSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this external settings based on context it is used
func (m *ExternalSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ExternalSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ExternalSettings) UnmarshalBinary(b []byte) error {
	var res ExternalSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
