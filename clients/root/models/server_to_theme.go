// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ServerToTheme server to theme
//
// swagger:model ServerToTheme
type ServerToTheme struct {

	// authorization server id
	// Example: developer
	ServerID string `json:"server_id,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// theme id
	// Example: acme
	ThemeID string `json:"theme_id,omitempty"`
}

// Validate validates this server to theme
func (m *ServerToTheme) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this server to theme based on context it is used
func (m *ServerToTheme) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ServerToTheme) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServerToTheme) UnmarshalBinary(b []byte) error {
	var res ServerToTheme
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}