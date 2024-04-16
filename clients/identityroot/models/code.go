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

// Code code
//
// swagger:model Code
type Code struct {

	// code
	// Required: true
	Code *CodeValue `json:"code" yaml:"code"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty" yaml:"created_at,omitempty"`

	// expires at
	// Format: date-time
	ExpiresAt strfmt.DateTime `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// id
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// issued at
	// Format: date-time
	IssuedAt strfmt.DateTime `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`

	// general purpose metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// tenant id
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// type
	// Example: active
	// Required: true
	// Enum: [activation reset_password challenge verify_address authentication]
	Type string `json:"type" yaml:"type"`

	// user id
	// Required: true
	UserID string `json:"user_id" yaml:"user_id"`

	// user pool id
	// Example: default
	// Required: true
	UserPoolID string `json:"user_pool_id" yaml:"user_pool_id"`

	// verifiable address id
	VerifiableAddressID string `json:"verifiable_address_id,omitempty" yaml:"verifiable_address_id,omitempty"`
}

// Validate validates this code
func (m *Code) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
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

func (m *Code) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	if m.Code != nil {
		if err := m.Code.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

func (m *Code) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Code) validateExpiresAt(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpiresAt) { // not required
		return nil
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Code) validateIssuedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.IssuedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("issued_at", "body", "date-time", m.IssuedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Code) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

var codeTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["activation","reset_password","challenge","verify_address","authentication"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		codeTypeTypePropEnum = append(codeTypeTypePropEnum, v)
	}
}

const (

	// CodeTypeActivation captures enum value "activation"
	CodeTypeActivation string = "activation"

	// CodeTypeResetPassword captures enum value "reset_password"
	CodeTypeResetPassword string = "reset_password"

	// CodeTypeChallenge captures enum value "challenge"
	CodeTypeChallenge string = "challenge"

	// CodeTypeVerifyAddress captures enum value "verify_address"
	CodeTypeVerifyAddress string = "verify_address"

	// CodeTypeAuthentication captures enum value "authentication"
	CodeTypeAuthentication string = "authentication"
)

// prop value enum
func (m *Code) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, codeTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Code) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *Code) validateUserID(formats strfmt.Registry) error {

	if err := validate.RequiredString("user_id", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

func (m *Code) validateUserPoolID(formats strfmt.Registry) error {

	if err := validate.RequiredString("user_pool_id", "body", m.UserPoolID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this code based on the context it is used
func (m *Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Code) contextValidateCode(ctx context.Context, formats strfmt.Registry) error {

	if m.Code != nil {

		if err := m.Code.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Code) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Code) UnmarshalBinary(b []byte) error {
	var res Code
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
