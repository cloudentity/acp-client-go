// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// NewUserCredential new user credential
//
// swagger:model NewUserCredential
type NewUserCredential struct {

	// password
	// Example: secret
	Password string `json:"password,omitempty"`

	// type
	// Example: password
	// Required: true
	// Enum: [password webauthn]
	Type string `json:"type"`

	// webauthn credentials
	// Example: public_key
	WebauthnCredentials []*Credential `json:"webauthn_credentials"`
}

// Validate validates this new user credential
func (m *NewUserCredential) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateType(formats); err != nil {
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

var newUserCredentialTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["password","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		newUserCredentialTypeTypePropEnum = append(newUserCredentialTypeTypePropEnum, v)
	}
}

const (

	// NewUserCredentialTypePassword captures enum value "password"
	NewUserCredentialTypePassword string = "password"

	// NewUserCredentialTypeWebauthn captures enum value "webauthn"
	NewUserCredentialTypeWebauthn string = "webauthn"
)

// prop value enum
func (m *NewUserCredential) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, newUserCredentialTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *NewUserCredential) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *NewUserCredential) validateWebauthnCredentials(formats strfmt.Registry) error {
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

// ContextValidate validate this new user credential based on the context it is used
func (m *NewUserCredential) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateWebauthnCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *NewUserCredential) contextValidateWebauthnCredentials(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.WebauthnCredentials); i++ {

		if m.WebauthnCredentials[i] != nil {
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
func (m *NewUserCredential) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *NewUserCredential) UnmarshalBinary(b []byte) error {
	var res NewUserCredential
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
