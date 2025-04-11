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

// UserCredential user credential
//
// swagger:model UserCredential
type UserCredential struct {

	// created at
	// Required: true
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at" yaml:"created_at"`

	// expires at
	// Format: date-time
	ExpiresAt strfmt.DateTime `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// id
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// payload
	// Example: {"hashed_password":"###"}
	// Required: true
	Payload interface{} `json:"payload" yaml:"payload"`

	// state
	// Enum: [valid must_be_reset must_be_changed]
	State string `json:"state,omitempty" yaml:"state,omitempty"`

	// tenant id
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// type
	// Example: password
	// Required: true
	// Enum: [password webauthn totp]
	Type string `json:"type" yaml:"type"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at" yaml:"updated_at"`

	// user id
	// Required: true
	UserID string `json:"user_id" yaml:"user_id"`

	// user pool id
	// Example: default
	// Required: true
	UserPoolID string `json:"user_pool_id" yaml:"user_pool_id"`
}

// Validate validates this user credential
func (m *UserCredential) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayload(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserPoolID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserCredential) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", strfmt.DateTime(m.CreatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validateExpiresAt(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpiresAt) { // not required
		return nil
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validatePayload(formats strfmt.Registry) error {

	if m.Payload == nil {
		return errors.Required("payload", "body", nil)
	}

	return nil
}

var userCredentialTypeStatePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["valid","must_be_reset","must_be_changed"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userCredentialTypeStatePropEnum = append(userCredentialTypeStatePropEnum, v)
	}
}

const (

	// UserCredentialStateValid captures enum value "valid"
	UserCredentialStateValid string = "valid"

	// UserCredentialStateMustBeReset captures enum value "must_be_reset"
	UserCredentialStateMustBeReset string = "must_be_reset"

	// UserCredentialStateMustBeChanged captures enum value "must_be_changed"
	UserCredentialStateMustBeChanged string = "must_be_changed"
)

// prop value enum
func (m *UserCredential) validateStateEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, userCredentialTypeStatePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UserCredential) validateState(formats strfmt.Registry) error {
	if swag.IsZero(m.State) { // not required
		return nil
	}

	// value enum
	if err := m.validateStateEnum("state", "body", m.State); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

var userCredentialTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["password","webauthn","totp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userCredentialTypeTypePropEnum = append(userCredentialTypeTypePropEnum, v)
	}
}

const (

	// UserCredentialTypePassword captures enum value "password"
	UserCredentialTypePassword string = "password"

	// UserCredentialTypeWebauthn captures enum value "webauthn"
	UserCredentialTypeWebauthn string = "webauthn"

	// UserCredentialTypeTotp captures enum value "totp"
	UserCredentialTypeTotp string = "totp"
)

// prop value enum
func (m *UserCredential) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, userCredentialTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UserCredential) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updated_at", "body", strfmt.DateTime(m.UpdatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validateUserID(formats strfmt.Registry) error {

	if err := validate.RequiredString("user_id", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

func (m *UserCredential) validateUserPoolID(formats strfmt.Registry) error {

	if err := validate.RequiredString("user_pool_id", "body", m.UserPoolID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this user credential based on context it is used
func (m *UserCredential) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserCredential) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserCredential) UnmarshalBinary(b []byte) error {
	var res UserCredential
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
