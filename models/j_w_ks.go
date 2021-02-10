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

// JWKs j w ks
//
// swagger:model JWKs
type JWKs struct {

	// swagger keys
	// Example: []
	SwaggerKeys []*JWK `json:"keys"`
}

// Validate validates this j w ks
func (m *JWKs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSwaggerKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JWKs) validateSwaggerKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.SwaggerKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.SwaggerKeys); i++ {
		if swag.IsZero(m.SwaggerKeys[i]) { // not required
			continue
		}

		if m.SwaggerKeys[i] != nil {
			if err := m.SwaggerKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this j w ks based on the context it is used
func (m *JWKs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSwaggerKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JWKs) contextValidateSwaggerKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SwaggerKeys); i++ {

		if m.SwaggerKeys[i] != nil {
			if err := m.SwaggerKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *JWKs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JWKs) UnmarshalBinary(b []byte) error {
	var res JWKs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
