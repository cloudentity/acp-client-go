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

// ValidatorConfig validator settings.
//
// swagger:model ValidatorConfig
type ValidatorConfig struct {

	// validator config
	Conf map[string]interface{} `json:"conf,omitempty"`

	// validator name
	// Example: identity-context
	Name string `json:"name,omitempty"`

	// validator recovery config
	Recovery []*RecoveryConfig `json:"recovery"`
}

// Validate validates this validator config
func (m *ValidatorConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRecovery(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ValidatorConfig) validateRecovery(formats strfmt.Registry) error {
	if swag.IsZero(m.Recovery) { // not required
		return nil
	}

	for i := 0; i < len(m.Recovery); i++ {
		if swag.IsZero(m.Recovery[i]) { // not required
			continue
		}

		if m.Recovery[i] != nil {
			if err := m.Recovery[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recovery" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this validator config based on the context it is used
func (m *ValidatorConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRecovery(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ValidatorConfig) contextValidateRecovery(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Recovery); i++ {

		if m.Recovery[i] != nil {
			if err := m.Recovery[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recovery" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ValidatorConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ValidatorConfig) UnmarshalBinary(b []byte) error {
	var res ValidatorConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
