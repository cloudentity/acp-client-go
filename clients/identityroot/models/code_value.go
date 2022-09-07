// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CodeValue code value
//
// swagger:model CodeValue
type CodeValue struct {

	// hashed code
	HashedCode *Hash `json:"hashed_code,omitempty"`
}

// Validate validates this code value
func (m *CodeValue) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHashedCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CodeValue) validateHashedCode(formats strfmt.Registry) error {
	if swag.IsZero(m.HashedCode) { // not required
		return nil
	}

	if m.HashedCode != nil {
		if err := m.HashedCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("hashed_code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("hashed_code")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this code value based on the context it is used
func (m *CodeValue) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateHashedCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CodeValue) contextValidateHashedCode(ctx context.Context, formats strfmt.Registry) error {

	if m.HashedCode != nil {
		if err := m.HashedCode.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("hashed_code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("hashed_code")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CodeValue) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CodeValue) UnmarshalBinary(b []byte) error {
	var res CodeValue
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
