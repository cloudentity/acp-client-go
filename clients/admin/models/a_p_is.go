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

// APIs a p is
//
// swagger:model APIs
type APIs struct {

	// apis
	Apis []*API `json:"apis" yaml:"apis"`
}

// Validate validates this a p is
func (m *APIs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApis(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIs) validateApis(formats strfmt.Registry) error {
	if swag.IsZero(m.Apis) { // not required
		return nil
	}

	for i := 0; i < len(m.Apis); i++ {
		if swag.IsZero(m.Apis[i]) { // not required
			continue
		}

		if m.Apis[i] != nil {
			if err := m.Apis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this a p is based on the context it is used
func (m *APIs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIs) contextValidateApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Apis); i++ {

		if m.Apis[i] != nil {

			if swag.IsZero(m.Apis[i]) { // not required
				return nil
			}

			if err := m.Apis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *APIs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIs) UnmarshalBinary(b []byte) error {
	var res APIs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
