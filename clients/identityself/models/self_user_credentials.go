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

// SelfUserCredentials self user credentials
//
// swagger:model SelfUserCredentials
type SelfUserCredentials struct {

	// expires after
	// Format: duration
	ExpiresAfter strfmt.Duration `json:"expires_after,omitempty" yaml:"expires_after,omitempty"`

	// expires at
	// Format: date-time
	ExpiresAt strfmt.DateTime `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// state
	// Enum: [valid must_be_reset must_be_changed]
	State string `json:"state,omitempty" yaml:"state,omitempty"`

	// type
	// Example: password
	// Required: true
	// Enum: [password webauthn]
	Type string `json:"type" yaml:"type"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at" yaml:"updated_at"`
}

// Validate validates this self user credentials
func (m *SelfUserCredentials) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExpiresAfter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfUserCredentials) validateExpiresAfter(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpiresAfter) { // not required
		return nil
	}

	if err := validate.FormatOf("expires_after", "body", "duration", m.ExpiresAfter.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserCredentials) validateExpiresAt(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpiresAt) { // not required
		return nil
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

var selfUserCredentialsTypeStatePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["valid","must_be_reset","must_be_changed"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserCredentialsTypeStatePropEnum = append(selfUserCredentialsTypeStatePropEnum, v)
	}
}

const (

	// SelfUserCredentialsStateValid captures enum value "valid"
	SelfUserCredentialsStateValid string = "valid"

	// SelfUserCredentialsStateMustBeReset captures enum value "must_be_reset"
	SelfUserCredentialsStateMustBeReset string = "must_be_reset"

	// SelfUserCredentialsStateMustBeChanged captures enum value "must_be_changed"
	SelfUserCredentialsStateMustBeChanged string = "must_be_changed"
)

// prop value enum
func (m *SelfUserCredentials) validateStateEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserCredentialsTypeStatePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserCredentials) validateState(formats strfmt.Registry) error {
	if swag.IsZero(m.State) { // not required
		return nil
	}

	// value enum
	if err := m.validateStateEnum("state", "body", m.State); err != nil {
		return err
	}

	return nil
}

var selfUserCredentialsTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["password","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserCredentialsTypeTypePropEnum = append(selfUserCredentialsTypeTypePropEnum, v)
	}
}

const (

	// SelfUserCredentialsTypePassword captures enum value "password"
	SelfUserCredentialsTypePassword string = "password"

	// SelfUserCredentialsTypeWebauthn captures enum value "webauthn"
	SelfUserCredentialsTypeWebauthn string = "webauthn"
)

// prop value enum
func (m *SelfUserCredentials) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserCredentialsTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserCredentials) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserCredentials) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updated_at", "body", strfmt.DateTime(m.UpdatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this self user credentials based on context it is used
func (m *SelfUserCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SelfUserCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelfUserCredentials) UnmarshalBinary(b []byte) error {
	var res SelfUserCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
