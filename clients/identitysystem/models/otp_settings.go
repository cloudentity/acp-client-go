// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OtpSettings otp settings
//
// swagger:model OtpSettings
type OtpSettings struct {

	// activation
	Activation *OtpConfig `json:"activation,omitempty" yaml:"activation,omitempty"`

	// authentication
	Authentication *OtpConfig `json:"authentication,omitempty" yaml:"authentication,omitempty"`

	// challenge
	Challenge *OtpConfig `json:"challenge,omitempty" yaml:"challenge,omitempty"`

	// reset password
	ResetPassword *OtpConfig `json:"reset_password,omitempty" yaml:"reset_password,omitempty"`

	// verify address
	VerifyAddress *OtpConfig `json:"verify_address,omitempty" yaml:"verify_address,omitempty"`
}

// Validate validates this otp settings
func (m *OtpSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActivation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthentication(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateChallenge(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResetPassword(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerifyAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OtpSettings) validateActivation(formats strfmt.Registry) error {
	if swag.IsZero(m.Activation) { // not required
		return nil
	}

	if m.Activation != nil {
		if err := m.Activation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("activation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("activation")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) validateAuthentication(formats strfmt.Registry) error {
	if swag.IsZero(m.Authentication) { // not required
		return nil
	}

	if m.Authentication != nil {
		if err := m.Authentication.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authentication")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) validateChallenge(formats strfmt.Registry) error {
	if swag.IsZero(m.Challenge) { // not required
		return nil
	}

	if m.Challenge != nil {
		if err := m.Challenge.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("challenge")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("challenge")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) validateResetPassword(formats strfmt.Registry) error {
	if swag.IsZero(m.ResetPassword) { // not required
		return nil
	}

	if m.ResetPassword != nil {
		if err := m.ResetPassword.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reset_password")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reset_password")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) validateVerifyAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.VerifyAddress) { // not required
		return nil
	}

	if m.VerifyAddress != nil {
		if err := m.VerifyAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verify_address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verify_address")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this otp settings based on the context it is used
func (m *OtpSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateActivation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAuthentication(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateChallenge(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateResetPassword(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerifyAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OtpSettings) contextValidateActivation(ctx context.Context, formats strfmt.Registry) error {

	if m.Activation != nil {

		if swag.IsZero(m.Activation) { // not required
			return nil
		}

		if err := m.Activation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("activation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("activation")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) contextValidateAuthentication(ctx context.Context, formats strfmt.Registry) error {

	if m.Authentication != nil {

		if swag.IsZero(m.Authentication) { // not required
			return nil
		}

		if err := m.Authentication.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authentication")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) contextValidateChallenge(ctx context.Context, formats strfmt.Registry) error {

	if m.Challenge != nil {

		if swag.IsZero(m.Challenge) { // not required
			return nil
		}

		if err := m.Challenge.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("challenge")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("challenge")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) contextValidateResetPassword(ctx context.Context, formats strfmt.Registry) error {

	if m.ResetPassword != nil {

		if swag.IsZero(m.ResetPassword) { // not required
			return nil
		}

		if err := m.ResetPassword.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reset_password")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reset_password")
			}
			return err
		}
	}

	return nil
}

func (m *OtpSettings) contextValidateVerifyAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.VerifyAddress != nil {

		if swag.IsZero(m.VerifyAddress) { // not required
			return nil
		}

		if err := m.VerifyAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verify_address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verify_address")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OtpSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OtpSettings) UnmarshalBinary(b []byte) error {
	var res OtpSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
