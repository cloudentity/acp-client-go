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

// PasswordPolicy password policy
//
// swagger:model PasswordPolicy
type PasswordPolicy struct {

	// capital letters
	CapitalLetters uint64 `json:"capital_letters,omitempty"`

	// digits
	Digits uint64 `json:"digits,omitempty"`

	// lowercase letters
	LowercaseLetters uint64 `json:"lowercase_letters,omitempty"`

	// min length
	MinLength uint64 `json:"min_length,omitempty"`

	// not used since
	NotUsedSince uint64 `json:"not_used_since,omitempty"`

	// special characters
	SpecialCharacters uint64 `json:"special_characters,omitempty"`

	// strength
	// Enum: [any weak fair strong very_strong]
	Strength string `json:"strength,omitempty"`
}

// Validate validates this password policy
func (m *PasswordPolicy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateStrength(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var passwordPolicyTypeStrengthPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["any","weak","fair","strong","very_strong"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		passwordPolicyTypeStrengthPropEnum = append(passwordPolicyTypeStrengthPropEnum, v)
	}
}

const (

	// PasswordPolicyStrengthAny captures enum value "any"
	PasswordPolicyStrengthAny string = "any"

	// PasswordPolicyStrengthWeak captures enum value "weak"
	PasswordPolicyStrengthWeak string = "weak"

	// PasswordPolicyStrengthFair captures enum value "fair"
	PasswordPolicyStrengthFair string = "fair"

	// PasswordPolicyStrengthStrong captures enum value "strong"
	PasswordPolicyStrengthStrong string = "strong"

	// PasswordPolicyStrengthVeryStrong captures enum value "very_strong"
	PasswordPolicyStrengthVeryStrong string = "very_strong"
)

// prop value enum
func (m *PasswordPolicy) validateStrengthEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, passwordPolicyTypeStrengthPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *PasswordPolicy) validateStrength(formats strfmt.Registry) error {
	if swag.IsZero(m.Strength) { // not required
		return nil
	}

	// value enum
	if err := m.validateStrengthEnum("strength", "body", m.Strength); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this password policy based on context it is used
func (m *PasswordPolicy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PasswordPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PasswordPolicy) UnmarshalBinary(b []byte) error {
	var res PasswordPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
