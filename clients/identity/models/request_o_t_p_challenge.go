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

// RequestOTPChallenge request o t p challenge
//
// swagger:model RequestOTPChallenge
type RequestOTPChallenge struct {

	// address
	// Required: true
	Address string `json:"address"`
}

// Validate validates this request o t p challenge
func (m *RequestOTPChallenge) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestOTPChallenge) validateAddress(formats strfmt.Registry) error {

	if err := validate.RequiredString("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this request o t p challenge based on context it is used
func (m *RequestOTPChallenge) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RequestOTPChallenge) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestOTPChallenge) UnmarshalBinary(b []byte) error {
	var res RequestOTPChallenge
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
