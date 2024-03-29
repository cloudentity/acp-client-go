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

// UserPools user pools
//
// swagger:model UserPools
type UserPools struct {

	// cursor
	Cursor Cursor `json:"cursor,omitempty" yaml:"cursor,omitempty"`

	// pools
	Pools []*PoolResponse `json:"pools" yaml:"pools"`
}

// Validate validates this user pools
func (m *UserPools) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCursor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePools(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserPools) validateCursor(formats strfmt.Registry) error {
	if swag.IsZero(m.Cursor) { // not required
		return nil
	}

	if err := m.Cursor.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("cursor")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("cursor")
		}
		return err
	}

	return nil
}

func (m *UserPools) validatePools(formats strfmt.Registry) error {
	if swag.IsZero(m.Pools) { // not required
		return nil
	}

	for i := 0; i < len(m.Pools); i++ {
		if swag.IsZero(m.Pools[i]) { // not required
			continue
		}

		if m.Pools[i] != nil {
			if err := m.Pools[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("pools" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("pools" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this user pools based on the context it is used
func (m *UserPools) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCursor(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePools(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserPools) contextValidateCursor(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Cursor) { // not required
		return nil
	}

	if err := m.Cursor.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("cursor")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("cursor")
		}
		return err
	}

	return nil
}

func (m *UserPools) contextValidatePools(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Pools); i++ {

		if m.Pools[i] != nil {

			if swag.IsZero(m.Pools[i]) { // not required
				return nil
			}

			if err := m.Pools[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("pools" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("pools" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserPools) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserPools) UnmarshalBinary(b []byte) error {
	var res UserPools
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
