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

// SelfUserIdentifier self user identifier
//
// swagger:model SelfUserIdentifier
type SelfUserIdentifier struct {

	// created at
	// Required: true
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at" yaml:"created_at"`

	// identifier
	// Required: true
	Identifier string `json:"identifier" yaml:"identifier"`

	// type
	// Example: email
	// Required: true
	// Enum: ["email","mobile","uid","external","federated"]
	Type string `json:"type" yaml:"type"`
}

// Validate validates this self user identifier
func (m *SelfUserIdentifier) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfUserIdentifier) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", strfmt.DateTime(m.CreatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserIdentifier) validateIdentifier(formats strfmt.Registry) error {

	if err := validate.RequiredString("identifier", "body", m.Identifier); err != nil {
		return err
	}

	return nil
}

var selfUserIdentifierTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["email","mobile","uid","external","federated"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserIdentifierTypeTypePropEnum = append(selfUserIdentifierTypeTypePropEnum, v)
	}
}

const (

	// SelfUserIdentifierTypeEmail captures enum value "email"
	SelfUserIdentifierTypeEmail string = "email"

	// SelfUserIdentifierTypeMobile captures enum value "mobile"
	SelfUserIdentifierTypeMobile string = "mobile"

	// SelfUserIdentifierTypeUID captures enum value "uid"
	SelfUserIdentifierTypeUID string = "uid"

	// SelfUserIdentifierTypeExternal captures enum value "external"
	SelfUserIdentifierTypeExternal string = "external"

	// SelfUserIdentifierTypeFederated captures enum value "federated"
	SelfUserIdentifierTypeFederated string = "federated"
)

// prop value enum
func (m *SelfUserIdentifier) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserIdentifierTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserIdentifier) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this self user identifier based on context it is used
func (m *SelfUserIdentifier) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SelfUserIdentifier) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelfUserIdentifier) UnmarshalBinary(b []byte) error {
	var res SelfUserIdentifier
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
