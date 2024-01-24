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

// ServersBindingsResponse servers bindings response
//
// swagger:model ServersBindingsResponse
type ServersBindingsResponse struct {

	// bindings
	Bindings []*ServerBindingResponse `json:"bindings" yaml:"bindings"`
}

// Validate validates this servers bindings response
func (m *ServersBindingsResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBindings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServersBindingsResponse) validateBindings(formats strfmt.Registry) error {
	if swag.IsZero(m.Bindings) { // not required
		return nil
	}

	for i := 0; i < len(m.Bindings); i++ {
		if swag.IsZero(m.Bindings[i]) { // not required
			continue
		}

		if m.Bindings[i] != nil {
			if err := m.Bindings[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("bindings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("bindings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this servers bindings response based on the context it is used
func (m *ServersBindingsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBindings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServersBindingsResponse) contextValidateBindings(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Bindings); i++ {

		if m.Bindings[i] != nil {

			if swag.IsZero(m.Bindings[i]) { // not required
				return nil
			}

			if err := m.Bindings[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("bindings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("bindings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ServersBindingsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServersBindingsResponse) UnmarshalBinary(b []byte) error {
	var res ServersBindingsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
