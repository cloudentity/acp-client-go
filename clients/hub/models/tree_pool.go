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
	AuthenticationMechanisms AuthenticationMechanisms `json:"authentication_mechanisms,omitempty" yaml:"authentication_mechanisms,omitempty"`

	// badge color
	BadgeColor string `json:"badge_color,omitempty" yaml:"badge_color,omitempty"`

	// business metadata schema id
	BusinessMetadataSchemaID string `json:"business_metadata_schema_id,omitempty" yaml:"business_metadata_schema_id,omitempty"`

	// deleted
	Deleted bool `json:"deleted,omitempty" yaml:"deleted,omitempty"`

	// description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// identifier case insensitive
	IdentifierCaseInsensitive bool `json:"identifier_case_insensitive,omitempty" yaml:"identifier_case_insensitive,omitempty"`

	// metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// metadata schema id
	MetadataSchemaID string `json:"metadata_schema_id,omitempty" yaml:"metadata_schema_id,omitempty"`

	// mfa session ttl
	// Format: duration
	MfaSessionTTL strfmt.Duration `json:"mfa_session_ttl,omitempty" yaml:"mfa_session_ttl,omitempty"`

	// name
	// Required: true
	Name string `json:"name" yaml:"name"`

	// otp settings
	OtpSettings *OtpSettings `json:"otp_settings,omitempty" yaml:"otp_settings,omitempty"`

	// password policy
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty" yaml:"password_policy,omitempty"`

	// password settings
	PasswordSettings *PasswordSettings `json:"password_settings,omitempty" yaml:"password_settings,omitempty"`

	// payload schema id
	PayloadSchemaID string `json:"payload_schema_id,omitempty" yaml:"payload_schema_id,omitempty"`

	// preferred authentication mechanism
	// Example: password
	// Enum: [totp password otp email_otp sms_otp webauthn]
	PreferredAuthenticationMechanism string `json:"preferred_authentication_mechanism,omitempty" yaml:"preferred_authentication_mechanism,omitempty"`

	// public registration allowed
	PublicRegistrationAllowed bool `json:"public_registration_allowed,omitempty" yaml:"public_registration_allowed,omitempty"`

	// reset credentials settings
	ResetCredentialsSettings *ResetCredentialsSettings `json:"reset_credentials_settings,omitempty" yaml:"reset_credentials_settings,omitempty"`

	// second factor authentication mechanisms
	SecondFactorAuthenticationMechanisms AuthenticationMechanisms `json:"second_factor_authentication_mechanisms,omitempty" yaml:"second_factor_authentication_mechanisms,omitempty"`

	// second factor preferred authentication mechanism
	// Example: password
	// Enum: [totp password otp email_otp sms_otp webauthn]
	SecondFactorPreferredAuthenticationMechanism string `json:"second_factor_preferred_authentication_mechanism,omitempty" yaml:"second_factor_preferred_authentication_mechanism,omitempty"`

	// The minimal risk engine loa score value to skip the 2FA
	SecondFactorThreshold float64 `json:"second_factor_threshold,omitempty" yaml:"second_factor_threshold,omitempty"`

	// system
	System bool `json:"system,omitempty" yaml:"system,omitempty"`
}

// Validate validates this tree pool
func (m *TreePool) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMfaSessionTTL(formats); err != nil {
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

	if err := m.validateResetCredentialsSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSecondFactorAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSecondFactorPreferredAuthenticationMechanism(formats); err != nil {
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

func (m *TreePool) validateMfaSessionTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.MfaSessionTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("mfa_session_ttl", "body", "duration", m.MfaSessionTTL.String(), formats); err != nil {
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
	if err := json.Unmarshal([]byte(`["totp","password","otp","email_otp","sms_otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		treePoolTypePreferredAuthenticationMechanismPropEnum = append(treePoolTypePreferredAuthenticationMechanismPropEnum, v)
	}
}

const (

	// TreePoolPreferredAuthenticationMechanismTotp captures enum value "totp"
	TreePoolPreferredAuthenticationMechanismTotp string = "totp"

	// TreePoolPreferredAuthenticationMechanismPassword captures enum value "password"
	TreePoolPreferredAuthenticationMechanismPassword string = "password"

	// TreePoolPreferredAuthenticationMechanismOtp captures enum value "otp"
	TreePoolPreferredAuthenticationMechanismOtp string = "otp"

	// TreePoolPreferredAuthenticationMechanismEmailOtp captures enum value "email_otp"
	TreePoolPreferredAuthenticationMechanismEmailOtp string = "email_otp"

	// TreePoolPreferredAuthenticationMechanismSmsOtp captures enum value "sms_otp"
	TreePoolPreferredAuthenticationMechanismSmsOtp string = "sms_otp"

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

func (m *TreePool) validateResetCredentialsSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.ResetCredentialsSettings) { // not required
		return nil
	}

	if m.ResetCredentialsSettings != nil {
		if err := m.ResetCredentialsSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reset_credentials_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reset_credentials_settings")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) validateSecondFactorAuthenticationMechanisms(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondFactorAuthenticationMechanisms) { // not required
		return nil
	}

	if err := m.SecondFactorAuthenticationMechanisms.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("second_factor_authentication_mechanisms")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("second_factor_authentication_mechanisms")
		}
		return err
	}

	return nil
}

var treePoolTypeSecondFactorPreferredAuthenticationMechanismPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","email_otp","sms_otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		treePoolTypeSecondFactorPreferredAuthenticationMechanismPropEnum = append(treePoolTypeSecondFactorPreferredAuthenticationMechanismPropEnum, v)
	}
}

const (

	// TreePoolSecondFactorPreferredAuthenticationMechanismTotp captures enum value "totp"
	TreePoolSecondFactorPreferredAuthenticationMechanismTotp string = "totp"

	// TreePoolSecondFactorPreferredAuthenticationMechanismPassword captures enum value "password"
	TreePoolSecondFactorPreferredAuthenticationMechanismPassword string = "password"

	// TreePoolSecondFactorPreferredAuthenticationMechanismOtp captures enum value "otp"
	TreePoolSecondFactorPreferredAuthenticationMechanismOtp string = "otp"

	// TreePoolSecondFactorPreferredAuthenticationMechanismEmailOtp captures enum value "email_otp"
	TreePoolSecondFactorPreferredAuthenticationMechanismEmailOtp string = "email_otp"

	// TreePoolSecondFactorPreferredAuthenticationMechanismSmsOtp captures enum value "sms_otp"
	TreePoolSecondFactorPreferredAuthenticationMechanismSmsOtp string = "sms_otp"

	// TreePoolSecondFactorPreferredAuthenticationMechanismWebauthn captures enum value "webauthn"
	TreePoolSecondFactorPreferredAuthenticationMechanismWebauthn string = "webauthn"
)

// prop value enum
func (m *TreePool) validateSecondFactorPreferredAuthenticationMechanismEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, treePoolTypeSecondFactorPreferredAuthenticationMechanismPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *TreePool) validateSecondFactorPreferredAuthenticationMechanism(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondFactorPreferredAuthenticationMechanism) { // not required
		return nil
	}

	// value enum
	if err := m.validateSecondFactorPreferredAuthenticationMechanismEnum("second_factor_preferred_authentication_mechanism", "body", m.SecondFactorPreferredAuthenticationMechanism); err != nil {
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

	if err := m.contextValidateResetCredentialsSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSecondFactorAuthenticationMechanisms(ctx, formats); err != nil {
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

func (m *TreePool) contextValidateResetCredentialsSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.ResetCredentialsSettings != nil {

		if swag.IsZero(m.ResetCredentialsSettings) { // not required
			return nil
		}

		if err := m.ResetCredentialsSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reset_credentials_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reset_credentials_settings")
			}
			return err
		}
	}

	return nil
}

func (m *TreePool) contextValidateSecondFactorAuthenticationMechanisms(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SecondFactorAuthenticationMechanisms.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("second_factor_authentication_mechanisms")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("second_factor_authentication_mechanisms")
		}
		return err
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
