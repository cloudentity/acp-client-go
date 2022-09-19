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

// HashConfig hash config
//
// swagger:model HashConfig
type HashConfig struct {

	// argon2
	Argon2 *Argon2Config `json:"argon2,omitempty"`

	// bcrypt
	Bcrypt *BcryptConfig `json:"bcrypt,omitempty"`

	// method
	// Enum: [bcrypt pbkdf2 argon2 sha]
	Method string `json:"method,omitempty"`

	// pbkdf2
	Pbkdf2 *PBKDF2Config `json:"pbkdf2,omitempty"`

	// sha
	Sha *SHAConfig `json:"sha,omitempty"`
}

// Validate validates this hash config
func (m *HashConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateArgon2(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBcrypt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePbkdf2(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSha(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HashConfig) validateArgon2(formats strfmt.Registry) error {
	if swag.IsZero(m.Argon2) { // not required
		return nil
	}

	if m.Argon2 != nil {
		if err := m.Argon2.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("argon2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("argon2")
			}
			return err
		}
	}

	return nil
}

func (m *HashConfig) validateBcrypt(formats strfmt.Registry) error {
	if swag.IsZero(m.Bcrypt) { // not required
		return nil
	}

	if m.Bcrypt != nil {
		if err := m.Bcrypt.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("bcrypt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("bcrypt")
			}
			return err
		}
	}

	return nil
}

var hashConfigTypeMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["bcrypt","pbkdf2","argon2","sha"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		hashConfigTypeMethodPropEnum = append(hashConfigTypeMethodPropEnum, v)
	}
}

const (

	// HashConfigMethodBcrypt captures enum value "bcrypt"
	HashConfigMethodBcrypt string = "bcrypt"

	// HashConfigMethodPbkdf2 captures enum value "pbkdf2"
	HashConfigMethodPbkdf2 string = "pbkdf2"

	// HashConfigMethodArgon2 captures enum value "argon2"
	HashConfigMethodArgon2 string = "argon2"

	// HashConfigMethodSha captures enum value "sha"
	HashConfigMethodSha string = "sha"
)

// prop value enum
func (m *HashConfig) validateMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, hashConfigTypeMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *HashConfig) validateMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.Method) { // not required
		return nil
	}

	// value enum
	if err := m.validateMethodEnum("method", "body", m.Method); err != nil {
		return err
	}

	return nil
}

func (m *HashConfig) validatePbkdf2(formats strfmt.Registry) error {
	if swag.IsZero(m.Pbkdf2) { // not required
		return nil
	}

	if m.Pbkdf2 != nil {
		if err := m.Pbkdf2.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pbkdf2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pbkdf2")
			}
			return err
		}
	}

	return nil
}

func (m *HashConfig) validateSha(formats strfmt.Registry) error {
	if swag.IsZero(m.Sha) { // not required
		return nil
	}

	if m.Sha != nil {
		if err := m.Sha.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sha")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sha")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this hash config based on the context it is used
func (m *HashConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateArgon2(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBcrypt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePbkdf2(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSha(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HashConfig) contextValidateArgon2(ctx context.Context, formats strfmt.Registry) error {

	if m.Argon2 != nil {
		if err := m.Argon2.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("argon2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("argon2")
			}
			return err
		}
	}

	return nil
}

func (m *HashConfig) contextValidateBcrypt(ctx context.Context, formats strfmt.Registry) error {

	if m.Bcrypt != nil {
		if err := m.Bcrypt.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("bcrypt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("bcrypt")
			}
			return err
		}
	}

	return nil
}

func (m *HashConfig) contextValidatePbkdf2(ctx context.Context, formats strfmt.Registry) error {

	if m.Pbkdf2 != nil {
		if err := m.Pbkdf2.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pbkdf2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pbkdf2")
			}
			return err
		}
	}

	return nil
}

func (m *HashConfig) contextValidateSha(ctx context.Context, formats strfmt.Registry) error {

	if m.Sha != nil {
		if err := m.Sha.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sha")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sha")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HashConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HashConfig) UnmarshalBinary(b []byte) error {
	var res HashConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}