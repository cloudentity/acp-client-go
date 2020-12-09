// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Claims claims
//
// swagger:model Claims
type Claims struct {

	// list of claims
	Claims []*Claim `json:"claims"`
}

// Validate validates this claims
func (m *Claims) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClaims(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Claims) validateClaims(formats strfmt.Registry) error {

	if swag.IsZero(m.Claims) { // not required
		return nil
	}

	for i := 0; i < len(m.Claims); i++ {
		if swag.IsZero(m.Claims[i]) { // not required
			continue
		}

		if m.Claims[i] != nil {
			if err := m.Claims[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("claims" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Claims) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Claims) UnmarshalBinary(b []byte) error {
	var res Claims
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
