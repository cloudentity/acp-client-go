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

// CompleteResetPassword complete reset password
//
// swagger:model CompleteResetPassword
type CompleteResetPassword struct {

	// address
	Address string `json:"address,omitempty"`

	// code
	// Required: true
	Code string `json:"code"`

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// new password
	// Required: true
	NewPassword string `json:"new_password"`

	// user ID
	UserID string `json:"userID,omitempty"`
}

// Validate validates this complete reset password
func (m *CompleteResetPassword) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNewPassword(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CompleteResetPassword) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *CompleteResetPassword) validateNewPassword(formats strfmt.Registry) error {

	if err := validate.RequiredString("new_password", "body", m.NewPassword); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this complete reset password based on context it is used
func (m *CompleteResetPassword) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CompleteResetPassword) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CompleteResetPassword) UnmarshalBinary(b []byte) error {
	var res CompleteResetPassword
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
