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

// SMSSettings s m s settings
//
// swagger:model SMSSettings
type SMSSettings struct {

	// Custom message template.
	//
	// If not set, the default is used.
	CustomMessageTemplate string `json:"custom_message_template,omitempty" yaml:"custom_message_template,omitempty"`

	// Custom SMS From phone number.
	//
	// If not set, the default is used.
	CustomSource string `json:"custom_source,omitempty" yaml:"custom_source,omitempty"`

	// otp
	Otp *OTPConfiguration `json:"otp,omitempty" yaml:"otp,omitempty"`

	// SMS provider.
	// Example: embedded
	// Enum: ["twilio","embedded"]
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`
}

// Validate validates this s m s settings
func (m *SMSSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOtp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProvider(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SMSSettings) validateOtp(formats strfmt.Registry) error {
	if swag.IsZero(m.Otp) { // not required
		return nil
	}

	if m.Otp != nil {
		if err := m.Otp.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("otp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("otp")
			}
			return err
		}
	}

	return nil
}

var sMSSettingsTypeProviderPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["twilio","embedded"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		sMSSettingsTypeProviderPropEnum = append(sMSSettingsTypeProviderPropEnum, v)
	}
}

const (

	// SMSSettingsProviderTwilio captures enum value "twilio"
	SMSSettingsProviderTwilio string = "twilio"

	// SMSSettingsProviderEmbedded captures enum value "embedded"
	SMSSettingsProviderEmbedded string = "embedded"
)

// prop value enum
func (m *SMSSettings) validateProviderEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, sMSSettingsTypeProviderPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SMSSettings) validateProvider(formats strfmt.Registry) error {
	if swag.IsZero(m.Provider) { // not required
		return nil
	}

	// value enum
	if err := m.validateProviderEnum("provider", "body", m.Provider); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this s m s settings based on the context it is used
func (m *SMSSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOtp(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SMSSettings) contextValidateOtp(ctx context.Context, formats strfmt.Registry) error {

	if m.Otp != nil {

		if swag.IsZero(m.Otp) { // not required
			return nil
		}

		if err := m.Otp.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("otp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("otp")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SMSSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SMSSettings) UnmarshalBinary(b []byte) error {
	var res SMSSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
