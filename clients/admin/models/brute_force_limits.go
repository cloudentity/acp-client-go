// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// BruteForceLimits brute force limits
//
// swagger:model BruteForceLimits
type BruteForceLimits struct {

	// brute force limits
	BruteForceLimits []*BruteForceLimit `json:"brute_force_limits" yaml:"brute_force_limits"`
}

// Validate validates this brute force limits
func (m *BruteForceLimits) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBruteForceLimits(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BruteForceLimits) validateBruteForceLimits(formats strfmt.Registry) error {
	if swag.IsZero(m.BruteForceLimits) { // not required
		return nil
	}

	for i := 0; i < len(m.BruteForceLimits); i++ {
		if swag.IsZero(m.BruteForceLimits[i]) { // not required
			continue
		}

		if m.BruteForceLimits[i] != nil {
			if err := m.BruteForceLimits[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("brute_force_limits" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("brute_force_limits" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this brute force limits based on the context it is used
func (m *BruteForceLimits) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBruteForceLimits(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BruteForceLimits) contextValidateBruteForceLimits(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.BruteForceLimits); i++ {

		if m.BruteForceLimits[i] != nil {

			if swag.IsZero(m.BruteForceLimits[i]) { // not required
				return nil
			}

			if err := m.BruteForceLimits[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("brute_force_limits" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("brute_force_limits" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *BruteForceLimits) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BruteForceLimits) UnmarshalBinary(b []byte) error {
	var res BruteForceLimits
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
