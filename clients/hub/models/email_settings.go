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

// EmailSettings email settings
//
// swagger:model EmailSettings
type EmailSettings struct {

	// Custom email From address.
	//
	// If not set, the default is used.
	// Example: noreply@cloudentity.com
	CustomFrom string `json:"custom_from,omitempty"`

	// Custom email subject.
	//
	// If not set, the default is used.
	CustomMessageSubject string `json:"custom_message_subject,omitempty"`

	// Custom email template.
	//
	// If not set, the default is used.
	CustomMessageTemplate string `json:"custom_message_template,omitempty"`

	// otp
	Otp *OTPConfiguration `json:"otp,omitempty"`

	// Email provider.
	// Example: embedded
	// Enum: [smtp embedded]
	Provider string `json:"provider,omitempty"`
}

// Validate validates this email settings
func (m *EmailSettings) Validate(formats strfmt.Registry) error {
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

func (m *EmailSettings) validateOtp(formats strfmt.Registry) error {
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

var emailSettingsTypeProviderPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["smtp","embedded"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		emailSettingsTypeProviderPropEnum = append(emailSettingsTypeProviderPropEnum, v)
	}
}

const (

	// EmailSettingsProviderSMTP captures enum value "smtp"
	EmailSettingsProviderSMTP string = "smtp"

	// EmailSettingsProviderEmbedded captures enum value "embedded"
	EmailSettingsProviderEmbedded string = "embedded"
)

// prop value enum
func (m *EmailSettings) validateProviderEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, emailSettingsTypeProviderPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *EmailSettings) validateProvider(formats strfmt.Registry) error {
	if swag.IsZero(m.Provider) { // not required
		return nil
	}

	// value enum
	if err := m.validateProviderEnum("provider", "body", m.Provider); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this email settings based on the context it is used
func (m *EmailSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOtp(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailSettings) contextValidateOtp(ctx context.Context, formats strfmt.Registry) error {

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
func (m *EmailSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EmailSettings) UnmarshalBinary(b []byte) error {
	var res EmailSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}