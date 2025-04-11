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
	"github.com/go-openapi/validate"
)

// ActivateSelfRegisteredUser activate self registered user
//
// swagger:model ActivateSelfRegisteredUser
type ActivateSelfRegisteredUser struct {

	// code
	// Required: true
	Code string `json:"code" yaml:"code"`

	// otp address
	OtpAddress string `json:"otp_address,omitempty" yaml:"otp_address,omitempty"`

	// password
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// totp secret
	TotpSecret string `json:"totp_secret,omitempty" yaml:"totp_secret,omitempty"`

	// webauthn
	Webauthn []*Credential `json:"webauthn" yaml:"webauthn"`
}

// Validate validates this activate self registered user
func (m *ActivateSelfRegisteredUser) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWebauthn(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ActivateSelfRegisteredUser) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *ActivateSelfRegisteredUser) validateWebauthn(formats strfmt.Registry) error {
	if swag.IsZero(m.Webauthn) { // not required
		return nil
	}

	for i := 0; i < len(m.Webauthn); i++ {
		if swag.IsZero(m.Webauthn[i]) { // not required
			continue
		}

		if m.Webauthn[i] != nil {
			if err := m.Webauthn[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("webauthn" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("webauthn" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this activate self registered user based on the context it is used
func (m *ActivateSelfRegisteredUser) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateWebauthn(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ActivateSelfRegisteredUser) contextValidateWebauthn(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Webauthn); i++ {

		if m.Webauthn[i] != nil {

			if swag.IsZero(m.Webauthn[i]) { // not required
				return nil
			}

			if err := m.Webauthn[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("webauthn" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("webauthn" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ActivateSelfRegisteredUser) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ActivateSelfRegisteredUser) UnmarshalBinary(b []byte) error {
	var res ActivateSelfRegisteredUser
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
