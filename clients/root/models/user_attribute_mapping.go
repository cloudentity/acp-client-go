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

// UserAttributeMapping user attribute mapping
//
// swagger:model UserAttributeMapping
type UserAttributeMapping struct {

	// If enabled, the decoder makes the following "weak" conversions:
	//
	// Bools to string (true = "1", false = "0")
	//
	// numbers to string (base 10)
	//
	// bools to int/uint (true = 1, false = 0)
	//
	// strings to int/uint (base implied by prefix)
	//
	// int to bool (true if value != 0)
	//
	// string to bool (accepts only the following: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False)
	//
	// empty array = empty map and vice versa
	//
	// negative numbers to overflowed uint values (base 10)
	//
	// slice of maps to a merged map
	//
	// single values are converted to slices if required. Each element is weakly decoded.
	// Example: false
	AllowWeakDecoding bool `json:"allow_weak_decoding,omitempty"`

	// mode
	Mode MappingMode `json:"mode,omitempty"`

	// Source attribute.
	//
	// Source path to the attribute(s) which should be copied to the authentication context.
	// Use '.' to copy everything.
	// Required for dynamic mode.
	// Example: access_token
	Source string `json:"source,omitempty"`

	// When static mode is used, this field contains a value that will be populated into a target attribute.
	Static interface{} `json:"static,omitempty"`

	// Target attribute.
	//
	// Target path in the authentication context where source attribute(s) should be pasted.
	// Use '.' to paste to the context top level object.
	// Example: .
	// Required: true
	Target string `json:"target"`

	// Type of the target attribute
	//
	// The `type` parameter accepts the following values:
	// `number`, `string`, `bool`, `number_array`, `string_array`, `bool_array`, `any`.
	// Example: string
	// Required: true
	Type string `json:"type"`

	// update on sign in
	UpdateOnSignIn bool `json:"update_on_sign_in,omitempty"`
}

// Validate validates this user attribute mapping
func (m *UserAttributeMapping) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTarget(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserAttributeMapping) validateMode(formats strfmt.Registry) error {
	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

func (m *UserAttributeMapping) validateTarget(formats strfmt.Registry) error {

	if err := validate.RequiredString("target", "body", m.Target); err != nil {
		return err
	}

	return nil
}

func (m *UserAttributeMapping) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this user attribute mapping based on the context it is used
func (m *UserAttributeMapping) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserAttributeMapping) contextValidateMode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserAttributeMapping) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserAttributeMapping) UnmarshalBinary(b []byte) error {
	var res UserAttributeMapping
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
