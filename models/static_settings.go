// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// StaticSettings static settings
//
// swagger:model StaticSettings
type StaticSettings struct {

	// display hint message
	Hint bool `json:"hint,omitempty"`
}

// Validate validates this static settings
func (m *StaticSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this static settings based on context it is used
func (m *StaticSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *StaticSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *StaticSettings) UnmarshalBinary(b []byte) error {
	var res StaticSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
