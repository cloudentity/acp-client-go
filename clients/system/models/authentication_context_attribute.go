// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// AuthenticationContextAttribute Authentication context attribute
//
// swagger:model AuthenticationContextAttribute
type AuthenticationContextAttribute struct {

	// String represented display name of an attribute
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Array of Strings represents attribute labels
	Labels []string `json:"labels" yaml:"labels"`

	// String represented variable name of an attribute
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// The data type of an attribute
	//
	// It stores information what kind of data is used as the value of the attribute.
	//
	// Available types: `number`, `string`, `bool`, `object`, `number_array`, `string_array`, `bool_array`, `object_array` or `any`.
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this authentication context attribute
func (m *AuthenticationContextAttribute) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this authentication context attribute based on context it is used
func (m *AuthenticationContextAttribute) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AuthenticationContextAttribute) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthenticationContextAttribute) UnmarshalBinary(b []byte) error {
	var res AuthenticationContextAttribute
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
