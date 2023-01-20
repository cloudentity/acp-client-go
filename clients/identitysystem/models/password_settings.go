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

// PasswordSettings password settings
//
// swagger:model PasswordSettings
type PasswordSettings struct {

	// hashing method
	// Enum: [bcrypt pbkdf2 argon2 sha]
	HashingMethod string `json:"hashing_method,omitempty"`
}

// Validate validates this password settings
func (m *PasswordSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHashingMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var passwordSettingsTypeHashingMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["bcrypt","pbkdf2","argon2","sha"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		passwordSettingsTypeHashingMethodPropEnum = append(passwordSettingsTypeHashingMethodPropEnum, v)
	}
}

const (

	// PasswordSettingsHashingMethodBcrypt captures enum value "bcrypt"
	PasswordSettingsHashingMethodBcrypt string = "bcrypt"

	// PasswordSettingsHashingMethodPbkdf2 captures enum value "pbkdf2"
	PasswordSettingsHashingMethodPbkdf2 string = "pbkdf2"

	// PasswordSettingsHashingMethodArgon2 captures enum value "argon2"
	PasswordSettingsHashingMethodArgon2 string = "argon2"

	// PasswordSettingsHashingMethodSha captures enum value "sha"
	PasswordSettingsHashingMethodSha string = "sha"
)

// prop value enum
func (m *PasswordSettings) validateHashingMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, passwordSettingsTypeHashingMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *PasswordSettings) validateHashingMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.HashingMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateHashingMethodEnum("hashing_method", "body", m.HashingMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this password settings based on context it is used
func (m *PasswordSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PasswordSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PasswordSettings) UnmarshalBinary(b []byte) error {
	var res PasswordSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
