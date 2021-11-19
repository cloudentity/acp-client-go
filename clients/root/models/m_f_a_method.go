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

// MFAMethod m f a method
//
// swagger:model MFAMethod
type MFAMethod struct {

	// auth
	Auth *MFAAuth `json:"auth,omitempty"`

	// enabled
	// Required: true
	Enabled bool `json:"enabled"`

	// id
	ID string `json:"id,omitempty"`

	// mechanism
	// Example: email
	// Required: true
	// Enum: [sms email]
	Mechanism string `json:"mechanism"`

	// settings
	Settings *MFASettings `json:"settings,omitempty"`

	// tenant id
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id"`
}

// Validate validates this m f a method
func (m *MFAMethod) Validate(formats strfmt.Registry) error {
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

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MFAMethod) validateAuth(formats strfmt.Registry) error {
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

func (m *MFAMethod) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", bool(m.Enabled)); err != nil {
		return err
	}

	return nil
}

var mFAMethodTypeMechanismPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","email"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		mFAMethodTypeMechanismPropEnum = append(mFAMethodTypeMechanismPropEnum, v)
	}
}

const (

	// MFAMethodMechanismSms captures enum value "sms"
	MFAMethodMechanismSms string = "sms"

	// MFAMethodMechanismEmail captures enum value "email"
	MFAMethodMechanismEmail string = "email"
)

// prop value enum
func (m *MFAMethod) validateMechanismEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, mFAMethodTypeMechanismPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *MFAMethod) validateMechanism(formats strfmt.Registry) error {

	if err := validate.RequiredString("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	// value enum
	if err := m.validateMechanismEnum("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	return nil
}

func (m *MFAMethod) validateSettings(formats strfmt.Registry) error {
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

func (m *MFAMethod) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this m f a method based on the context it is used
func (m *MFAMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *MFAMethod) contextValidateAuth(ctx context.Context, formats strfmt.Registry) error {

	if m.Auth != nil {
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

func (m *MFAMethod) contextValidateSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.Settings != nil {
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
func (m *MFAMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MFAMethod) UnmarshalBinary(b []byte) error {
	var res MFAMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
