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

// RequestCodeForUser request code for user
//
// swagger:model RequestCodeForUser
type RequestCodeForUser struct {

	// address
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// identifier
	Identifier string `json:"identifier,omitempty" yaml:"identifier,omitempty"`

	// code metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// type
	// Required: true
	// Enum: [activation reset_password challenge verify_address authentication]
	Type string `json:"type" yaml:"type"`

	// user ID
	UserID string `json:"userID,omitempty" yaml:"userID,omitempty"`
}

// Validate validates this request code for user
func (m *RequestCodeForUser) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var requestCodeForUserTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["activation","reset_password","challenge","verify_address","authentication"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		requestCodeForUserTypeTypePropEnum = append(requestCodeForUserTypeTypePropEnum, v)
	}
}

const (

	// RequestCodeForUserTypeActivation captures enum value "activation"
	RequestCodeForUserTypeActivation string = "activation"

	// RequestCodeForUserTypeResetPassword captures enum value "reset_password"
	RequestCodeForUserTypeResetPassword string = "reset_password"

	// RequestCodeForUserTypeChallenge captures enum value "challenge"
	RequestCodeForUserTypeChallenge string = "challenge"

	// RequestCodeForUserTypeVerifyAddress captures enum value "verify_address"
	RequestCodeForUserTypeVerifyAddress string = "verify_address"

	// RequestCodeForUserTypeAuthentication captures enum value "authentication"
	RequestCodeForUserTypeAuthentication string = "authentication"
)

// prop value enum
func (m *RequestCodeForUser) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, requestCodeForUserTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *RequestCodeForUser) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this request code for user based on context it is used
func (m *RequestCodeForUser) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RequestCodeForUser) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestCodeForUser) UnmarshalBinary(b []byte) error {
	var res RequestCodeForUser
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
