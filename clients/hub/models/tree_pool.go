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

// TreePool tree pool
//
// swagger:model TreePool
type TreePool struct {

	// authentication mechanisms
	AuthenticationMechanisms AuthenticationMechanisms `json:"authentication_mechanisms,omitempty"`

	// badge color
	BadgeColor string `json:"badge_color,omitempty"`

	// deleted
	Deleted bool `json:"deleted,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// identifier case insensitive
	IdentifierCaseInsensitive bool `json:"identifier_case_insensitive,omitempty"`

	// metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// metadata schema id
	MetadataSchemaID string `json:"metadata_schema_id,omitempty"`

	// name
	// Required: true
	Name string `json:"name"`

	// otp settings
	OtpSettings *OtpSettings `json:"otp_settings,omitempty"`

	// password policy
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`

	// password settings
	PasswordSettings *PasswordSettings `json:"password_settings,omitempty"`

	// payload schema id
	PayloadSchemaID string `json:"payload_schema_id,omitempty"`

	// preferred authentication mechanism
	// Example: password
	// Enum: [password otp webauthn]
	PreferredAuthenticationMechanism string `json:"preferred_authentication_mechanism,omitempty"`

	// public registration allowed
	PublicRegistrationAllowed bool `json:"public_registration_allowed,omitempty"`

	// system
	System bool `json:"system,omitempty"`
}

// Validate validates this tree pool
func (m *TreePool) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOtpSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePasswordPolicy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePasswordSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreferredAuthenticationMechanism(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreePool) validateAuthenticationMechanisms(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationMechanisms) { // not required
		return nil
	}

	if err := m.AuthenticationMechanisms.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_mechanisms")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_mechanisms")
		}
		return err
	}

	return nil
}

func (m *TreePool) validateName(formats strfmt.Registry) error {

	if err := validate.RequiredString("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *TreePool) validateOtpSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.OtpSettings) { // not required
		return nil
	}

	if m.OtpSettings != nil {
		if err := m.OtpSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("otp_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("otp_settings")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) validatePasswordPolicy(formats strfmt.Registry) error {
	if swag.IsZero(m.PasswordPolicy) { // not required
		return nil
	}

	if m.PasswordPolicy != nil {
		if err := m.PasswordPolicy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_policy")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) validatePasswordSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.PasswordSettings) { // not required
		return nil
	}

	if m.PasswordSettings != nil {
		if err := m.PasswordSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_settings")
			}
			return err
		}
	}

	return nil
}

var treePoolTypePreferredAuthenticationMechanismPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["password","otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		treePoolTypePreferredAuthenticationMechanismPropEnum = append(treePoolTypePreferredAuthenticationMechanismPropEnum, v)
	}
}

const (

	// TreePoolPreferredAuthenticationMechanismPassword captures enum value "password"
	TreePoolPreferredAuthenticationMechanismPassword string = "password"

	// TreePoolPreferredAuthenticationMechanismOtp captures enum value "otp"
	TreePoolPreferredAuthenticationMechanismOtp string = "otp"

	// TreePoolPreferredAuthenticationMechanismWebauthn captures enum value "webauthn"
	TreePoolPreferredAuthenticationMechanismWebauthn string = "webauthn"
)

// prop value enum
func (m *TreePool) validatePreferredAuthenticationMechanismEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, treePoolTypePreferredAuthenticationMechanismPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *TreePool) validatePreferredAuthenticationMechanism(formats strfmt.Registry) error {
	if swag.IsZero(m.PreferredAuthenticationMechanism) { // not required
		return nil
	}

	// value enum
	if err := m.validatePreferredAuthenticationMechanismEnum("preferred_authentication_mechanism", "body", m.PreferredAuthenticationMechanism); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this tree pool based on the context it is used
func (m *TreePool) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationMechanisms(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOtpSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePasswordPolicy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePasswordSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreePool) contextValidateAuthenticationMechanisms(ctx context.Context, formats strfmt.Registry) error {

	if err := m.AuthenticationMechanisms.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_mechanisms")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_mechanisms")
		}
		return err
	}

	return nil
}

func (m *TreePool) contextValidateOtpSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.OtpSettings != nil {

		if swag.IsZero(m.OtpSettings) { // not required
			return nil
		}

		if err := m.OtpSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("otp_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("otp_settings")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) contextValidatePasswordPolicy(ctx context.Context, formats strfmt.Registry) error {

	if m.PasswordPolicy != nil {

		if swag.IsZero(m.PasswordPolicy) { // not required
			return nil
		}

		if err := m.PasswordPolicy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_policy")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) contextValidatePasswordSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.PasswordSettings != nil {

		if swag.IsZero(m.PasswordSettings) { // not required
			return nil
		}

		if err := m.PasswordSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_settings")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreePool) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreePool) UnmarshalBinary(b []byte) error {
	var res TreePool
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
