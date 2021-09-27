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

// TestMFAMethodRequest test m f a method request
//
// swagger:model TestMFAMethodRequest
type TestMFAMethodRequest struct {

	// address
	// Required: true
	Address string `json:"address"`
}

// Validate validates this test m f a method request
func (m *TestMFAMethodRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TestMFAMethodRequest) validateAddress(formats strfmt.Registry) error {

	if err := validate.RequiredString("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this test m f a method request based on context it is used
func (m *TestMFAMethodRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TestMFAMethodRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestMFAMethodRequest) UnmarshalBinary(b []byte) error {
	var res TestMFAMethodRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
