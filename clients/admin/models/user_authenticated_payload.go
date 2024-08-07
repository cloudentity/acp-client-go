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

// UserAuthenticatedPayload UserAuthenticatedPayload user authenticated payload
//
// swagger:model UserAuthenticatedPayload
type UserAuthenticatedPayload struct {

	// first factor method
	// Enum: [totp password otp webauthn arculix]
	AuthnMethod string `json:"authn_method,omitempty" yaml:"authn_method,omitempty"`

	// identifier
	Identifier string `json:"identifier,omitempty" yaml:"identifier,omitempty"`

	// second factor method
	// Enum: [totp password otp webauthn arculix]
	Mfa string `json:"mfa,omitempty" yaml:"mfa,omitempty"`

	// m f a skipped
	MfaSkipped bool `json:"mfa_skipped,omitempty" yaml:"mfa_skipped,omitempty"`

	// password mode
	PasswordMode bool `json:"password_mode,omitempty" yaml:"password_mode,omitempty"`

	// success
	// Required: true
	Success bool `json:"success" yaml:"success"`
}

// Validate validates this user authenticated payload
func (m *UserAuthenticatedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthnMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMfa(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuccess(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var userAuthenticatedPayloadTypeAuthnMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","webauthn","arculix"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userAuthenticatedPayloadTypeAuthnMethodPropEnum = append(userAuthenticatedPayloadTypeAuthnMethodPropEnum, v)
	}
}

const (

	// UserAuthenticatedPayloadAuthnMethodTotp captures enum value "totp"
	UserAuthenticatedPayloadAuthnMethodTotp string = "totp"

	// UserAuthenticatedPayloadAuthnMethodPassword captures enum value "password"
	UserAuthenticatedPayloadAuthnMethodPassword string = "password"

	// UserAuthenticatedPayloadAuthnMethodOtp captures enum value "otp"
	UserAuthenticatedPayloadAuthnMethodOtp string = "otp"

	// UserAuthenticatedPayloadAuthnMethodWebauthn captures enum value "webauthn"
	UserAuthenticatedPayloadAuthnMethodWebauthn string = "webauthn"

	// UserAuthenticatedPayloadAuthnMethodArculix captures enum value "arculix"
	UserAuthenticatedPayloadAuthnMethodArculix string = "arculix"
)

// prop value enum
func (m *UserAuthenticatedPayload) validateAuthnMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, userAuthenticatedPayloadTypeAuthnMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UserAuthenticatedPayload) validateAuthnMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthnMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateAuthnMethodEnum("authn_method", "body", m.AuthnMethod); err != nil {
		return err
	}

	return nil
}

var userAuthenticatedPayloadTypeMfaPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","webauthn","arculix"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userAuthenticatedPayloadTypeMfaPropEnum = append(userAuthenticatedPayloadTypeMfaPropEnum, v)
	}
}

const (

	// UserAuthenticatedPayloadMfaTotp captures enum value "totp"
	UserAuthenticatedPayloadMfaTotp string = "totp"

	// UserAuthenticatedPayloadMfaPassword captures enum value "password"
	UserAuthenticatedPayloadMfaPassword string = "password"

	// UserAuthenticatedPayloadMfaOtp captures enum value "otp"
	UserAuthenticatedPayloadMfaOtp string = "otp"

	// UserAuthenticatedPayloadMfaWebauthn captures enum value "webauthn"
	UserAuthenticatedPayloadMfaWebauthn string = "webauthn"

	// UserAuthenticatedPayloadMfaArculix captures enum value "arculix"
	UserAuthenticatedPayloadMfaArculix string = "arculix"
)

// prop value enum
func (m *UserAuthenticatedPayload) validateMfaEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, userAuthenticatedPayloadTypeMfaPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UserAuthenticatedPayload) validateMfa(formats strfmt.Registry) error {
	if swag.IsZero(m.Mfa) { // not required
		return nil
	}

	// value enum
	if err := m.validateMfaEnum("mfa", "body", m.Mfa); err != nil {
		return err
	}

	return nil
}

func (m *UserAuthenticatedPayload) validateSuccess(formats strfmt.Registry) error {

	if err := validate.Required("success", "body", bool(m.Success)); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this user authenticated payload based on context it is used
func (m *UserAuthenticatedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserAuthenticatedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserAuthenticatedPayload) UnmarshalBinary(b []byte) error {
	var res UserAuthenticatedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
