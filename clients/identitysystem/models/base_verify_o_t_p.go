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

// BaseVerifyOTP base verify o t p
//
// swagger:model BaseVerifyOTP
type BaseVerifyOTP struct {

	// code
	// Required: true
	Code string `json:"code" yaml:"code"`

	// identifier
	// Example: sample@email.com/+48123456789
	Identifier string `json:"identifier,omitempty" yaml:"identifier,omitempty"`

	// user ID
	UserID string `json:"userID,omitempty" yaml:"userID,omitempty"`
}

// Validate validates this base verify o t p
func (m *BaseVerifyOTP) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BaseVerifyOTP) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this base verify o t p based on context it is used
func (m *BaseVerifyOTP) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *BaseVerifyOTP) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BaseVerifyOTP) UnmarshalBinary(b []byte) error {
	var res BaseVerifyOTP
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
