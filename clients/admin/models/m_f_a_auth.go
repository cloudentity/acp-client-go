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

// MFAAuth m f a auth
//
// swagger:model MFAAuth
type MFAAuth struct {

	// email
	Email *EmailAuth `json:"email,omitempty" yaml:"email,omitempty"`

	// sms
	Sms *SMSAuth `json:"sms,omitempty" yaml:"sms,omitempty"`
}

// Validate validates this m f a auth
func (m *MFAAuth) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSms(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MFAAuth) validateEmail(formats strfmt.Registry) error {
	if swag.IsZero(m.Email) { // not required
		return nil
	}

	if m.Email != nil {
		if err := m.Email.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("email")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("email")
			}
			return err
		}
	}

	return nil
}

func (m *MFAAuth) validateSms(formats strfmt.Registry) error {
	if swag.IsZero(m.Sms) { // not required
		return nil
	}

	if m.Sms != nil {
		if err := m.Sms.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sms")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sms")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this m f a auth based on the context it is used
func (m *MFAAuth) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEmail(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSms(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MFAAuth) contextValidateEmail(ctx context.Context, formats strfmt.Registry) error {

	if m.Email != nil {

		if swag.IsZero(m.Email) { // not required
			return nil
		}

		if err := m.Email.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("email")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("email")
			}
			return err
		}
	}

	return nil
}

func (m *MFAAuth) contextValidateSms(ctx context.Context, formats strfmt.Registry) error {

	if m.Sms != nil {

		if swag.IsZero(m.Sms) { // not required
			return nil
		}

		if err := m.Sms.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sms")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sms")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *MFAAuth) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MFAAuth) UnmarshalBinary(b []byte) error {
	var res MFAAuth
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
