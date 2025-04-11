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

// SelfRegisterUser self register user
//
// swagger:model SelfRegisterUser
type SelfRegisterUser struct {

	// identifier
	// Required: true
	Identifier string `json:"identifier" yaml:"identifier"`

	// otp address
	OtpAddress string `json:"otp_address,omitempty" yaml:"otp_address,omitempty"`

	// password
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// payload
	Payload map[string]interface{} `json:"payload,omitempty" yaml:"payload,omitempty"`

	// totp secret
	TotpSecret string `json:"totp_secret,omitempty" yaml:"totp_secret,omitempty"`

	// webauthn credentials
	WebauthnCredentials []*Credential `json:"webauthn_credentials" yaml:"webauthn_credentials"`
}

// Validate validates this self register user
func (m *SelfRegisterUser) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWebauthnCredentials(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfRegisterUser) validateIdentifier(formats strfmt.Registry) error {

	if err := validate.RequiredString("identifier", "body", m.Identifier); err != nil {
		return err
	}

	return nil
}

func (m *SelfRegisterUser) validateWebauthnCredentials(formats strfmt.Registry) error {
	if swag.IsZero(m.WebauthnCredentials) { // not required
		return nil
	}

	for i := 0; i < len(m.WebauthnCredentials); i++ {
		if swag.IsZero(m.WebauthnCredentials[i]) { // not required
			continue
		}

		if m.WebauthnCredentials[i] != nil {
			if err := m.WebauthnCredentials[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("webauthn_credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("webauthn_credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this self register user based on the context it is used
func (m *SelfRegisterUser) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateWebauthnCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfRegisterUser) contextValidateWebauthnCredentials(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.WebauthnCredentials); i++ {

		if m.WebauthnCredentials[i] != nil {

			if swag.IsZero(m.WebauthnCredentials[i]) { // not required
				return nil
			}

			if err := m.WebauthnCredentials[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("webauthn_credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("webauthn_credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *SelfRegisterUser) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelfRegisterUser) UnmarshalBinary(b []byte) error {
	var res SelfRegisterUser
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
