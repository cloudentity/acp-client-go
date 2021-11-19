// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CustomAuthentication Custom authentication settings.
//
// Use in case of custom integration.
//
// swagger:model CustomAuthentication
type CustomAuthentication struct {

	// URL to custom login page
	// Example: https://example.com/login
	LoginURL string `json:"login_url,omitempty"`
}

// Validate validates this custom authentication
func (m *CustomAuthentication) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this custom authentication based on context it is used
func (m *CustomAuthentication) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CustomAuthentication) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CustomAuthentication) UnmarshalBinary(b []byte) error {
	var res CustomAuthentication
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}