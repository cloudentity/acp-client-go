// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// BcryptConfig bcrypt config
//
// swagger:model BcryptConfig
type BcryptConfig struct {

	// cost
	Cost int64 `json:"cost,omitempty" yaml:"cost,omitempty"`
}

// Validate validates this bcrypt config
func (m *BcryptConfig) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this bcrypt config based on context it is used
func (m *BcryptConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *BcryptConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BcryptConfig) UnmarshalBinary(b []byte) error {
	var res BcryptConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
