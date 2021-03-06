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

// IDPsResponse ID ps response
//
// swagger:model IDPsResponse
type IDPsResponse struct {

	// ID ps
	IDPs []*IDPBase `json:"idps"`
}

// Validate validates this ID ps response
func (m *IDPsResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIDPs(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IDPsResponse) validateIDPs(formats strfmt.Registry) error {
	if swag.IsZero(m.IDPs) { // not required
		return nil
	}

	for i := 0; i < len(m.IDPs); i++ {
		if swag.IsZero(m.IDPs[i]) { // not required
			continue
		}

		if m.IDPs[i] != nil {
			if err := m.IDPs[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("idps" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this ID ps response based on the context it is used
func (m *IDPsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateIDPs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IDPsResponse) contextValidateIDPs(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.IDPs); i++ {

		if m.IDPs[i] != nil {
			if err := m.IDPs[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("idps" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *IDPsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IDPsResponse) UnmarshalBinary(b []byte) error {
	var res IDPsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
