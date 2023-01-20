// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// VerifyPassword verify password
//
// swagger:model VerifyPassword
type VerifyPassword struct {

	// id
	ID string `json:"id,omitempty"`

	// identifier
	// Example: sample@email.com/+48123456789
	Identifier string `json:"identifier,omitempty"`

	// password
	// Required: true
	Password string `json:"password"`
}

// Validate validates this verify password
func (m *VerifyPassword) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePassword(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *VerifyPassword) validatePassword(formats strfmt.Registry) error {

	if err := validate.RequiredString("password", "body", m.Password); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this verify password based on context it is used
func (m *VerifyPassword) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *VerifyPassword) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *VerifyPassword) UnmarshalBinary(b []byte) error {
	var res VerifyPassword
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
