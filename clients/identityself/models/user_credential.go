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
	CreatedAt strfmt.DateTime `json:"created_at"`

	// id
	ID string `json:"id,omitempty"`

	// payload
	// Example: {"hashed_password":"###"}
	// Required: true
	Payload interface{} `json:"payload"`

	// tenant id
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id"`

	// type
	// Example: password
	// Required: true
	// Enum: [password]
	Type string `json:"type"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at"`

	// user id
	// Required: true
	UserID string `json:"user_id"`

	// user pool id
	// Example: default
	// Required: true
	UserPoolID string `json:"user_pool_id"`
}

// Validate validates this user credential
func (m *UserCredential) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayload(formats); err != nil {
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

func (m *UserCredential) validatePayload(formats strfmt.Registry) error {

	if m.Payload == nil {
		return errors.Required("payload", "body", nil)
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
	if err := json.Unmarshal([]byte(`["password"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userCredentialTypeTypePropEnum = append(userCredentialTypeTypePropEnum, v)
	}
}

const (

	// UserCredentialTypePassword captures enum value "password"
	UserCredentialTypePassword string = "password"
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
