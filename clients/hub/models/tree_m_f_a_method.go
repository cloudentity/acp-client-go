// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TreeMFAMethod tree m f a method
//
// swagger:model TreeMFAMethod
type TreeMFAMethod struct {

	// auth
	Auth *MFAAuth `json:"auth,omitempty" yaml:"auth,omitempty"`

	// enabled
	// Required: true
	Enabled bool `json:"enabled" yaml:"enabled"`

	// mechanism
	// Example: email
	// Required: true
	// Enum: [sms email arculix risk_engine]
	Mechanism string `json:"mechanism" yaml:"mechanism"`

	// settings
	Settings *MFASettings `json:"settings,omitempty" yaml:"settings,omitempty"`
}

// Validate validates this tree m f a method
func (m *TreeMFAMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuth(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMechanism(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSettings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeMFAMethod) validateAuth(formats strfmt.Registry) error {
	if swag.IsZero(m.Auth) { // not required
		return nil
	}

	if m.Auth != nil {
		if err := m.Auth.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("auth")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("auth")
			}
			return err
		}
	}

	return nil
}

func (m *TreeMFAMethod) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", bool(m.Enabled)); err != nil {
		return err
	}

	return nil
}

var treeMFAMethodTypeMechanismPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","email","arculix","risk_engine"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		treeMFAMethodTypeMechanismPropEnum = append(treeMFAMethodTypeMechanismPropEnum, v)
	}
}

const (

	// TreeMFAMethodMechanismSms captures enum value "sms"
	TreeMFAMethodMechanismSms string = "sms"

	// TreeMFAMethodMechanismEmail captures enum value "email"
	TreeMFAMethodMechanismEmail string = "email"

	// TreeMFAMethodMechanismArculix captures enum value "arculix"
	TreeMFAMethodMechanismArculix string = "arculix"

	// TreeMFAMethodMechanismRiskEngine captures enum value "risk_engine"
	TreeMFAMethodMechanismRiskEngine string = "risk_engine"
)

// prop value enum
func (m *TreeMFAMethod) validateMechanismEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, treeMFAMethodTypeMechanismPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *TreeMFAMethod) validateMechanism(formats strfmt.Registry) error {

	if err := validate.RequiredString("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	// value enum
	if err := m.validateMechanismEnum("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	return nil
}

func (m *TreeMFAMethod) validateSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.Settings) { // not required
		return nil
	}

	if m.Settings != nil {
		if err := m.Settings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("settings")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tree m f a method based on the context it is used
func (m *TreeMFAMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuth(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeMFAMethod) contextValidateAuth(ctx context.Context, formats strfmt.Registry) error {

	if m.Auth != nil {

		if swag.IsZero(m.Auth) { // not required
			return nil
		}

		if err := m.Auth.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("auth")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("auth")
			}
			return err
		}
	}

	return nil
}

func (m *TreeMFAMethod) contextValidateSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.Settings != nil {

		if swag.IsZero(m.Settings) { // not required
			return nil
		}

		if err := m.Settings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("settings")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreeMFAMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeMFAMethod) UnmarshalBinary(b []byte) error {
	var res TreeMFAMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
