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

// SetTotpSecret set totp secret
//
// swagger:model SetTotpSecret
type SetTotpSecret struct {

	// new totp secret
	// Required: true
	NewTotpSecret string `json:"new_totp_secret" yaml:"new_totp_secret"`
}

// Validate validates this set totp secret
func (m *SetTotpSecret) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNewTotpSecret(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SetTotpSecret) validateNewTotpSecret(formats strfmt.Registry) error {

	if err := validate.RequiredString("new_totp_secret", "body", m.NewTotpSecret); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this set totp secret based on context it is used
func (m *SetTotpSecret) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SetTotpSecret) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SetTotpSecret) UnmarshalBinary(b []byte) error {
	var res SetTotpSecret
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
