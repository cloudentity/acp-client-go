// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CustomSettings custom settings
//
// swagger:model CustomSettings
type CustomSettings struct {

	// URL to custom login page
	// Example: https://example.com/login
	LoginURL string `json:"login_url,omitempty"`

	// type metadata, allowed values: generic, cloudentity. If not provided, it is set to generic
	Type string `json:"type,omitempty"`
}

// Validate validates this custom settings
func (m *CustomSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this custom settings based on context it is used
func (m *CustomSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CustomSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CustomSettings) UnmarshalBinary(b []byte) error {
	var res CustomSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
