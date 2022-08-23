// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PBKDF2Config p b k d f2 config
//
// swagger:model PBKDF2Config
type PBKDF2Config struct {

	// function
	Function string `json:"function,omitempty"`

	// key length
	KeyLength int64 `json:"key_length,omitempty"`

	// number of iterations
	NumberOfIterations int64 `json:"number_of_iterations,omitempty"`

	// salt
	Salt string `json:"salt,omitempty"`

	// salt length
	SaltLength int64 `json:"salt_length,omitempty"`
}

// Validate validates this p b k d f2 config
func (m *PBKDF2Config) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this p b k d f2 config based on context it is used
func (m *PBKDF2Config) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PBKDF2Config) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PBKDF2Config) UnmarshalBinary(b []byte) error {
	var res PBKDF2Config
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
