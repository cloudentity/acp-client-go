// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MetaCredentials Meta IDP specific credentials
//
// swagger:model MetaCredentials
type MetaCredentials struct {

	// OAuth client application secret
	ClientSecret string `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
}

// Validate validates this meta credentials
func (m *MetaCredentials) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this meta credentials based on context it is used
func (m *MetaCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MetaCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MetaCredentials) UnmarshalBinary(b []byte) error {
	var res MetaCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
