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

// OTPPayload o t p payload
//
// swagger:model OTPPayload
type OTPPayload struct {

	// address
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// purpose
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty"`

	// type
	// Enum: [sms email arculix risk_engine]
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this o t p payload
func (m *OTPPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oTPPayloadTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","email","arculix","risk_engine"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oTPPayloadTypeTypePropEnum = append(oTPPayloadTypeTypePropEnum, v)
	}
}

const (

	// OTPPayloadTypeSms captures enum value "sms"
	OTPPayloadTypeSms string = "sms"

	// OTPPayloadTypeEmail captures enum value "email"
	OTPPayloadTypeEmail string = "email"

	// OTPPayloadTypeArculix captures enum value "arculix"
	OTPPayloadTypeArculix string = "arculix"

	// OTPPayloadTypeRiskEngine captures enum value "risk_engine"
	OTPPayloadTypeRiskEngine string = "risk_engine"
)

// prop value enum
func (m *OTPPayload) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oTPPayloadTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OTPPayload) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o t p payload based on context it is used
func (m *OTPPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OTPPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OTPPayload) UnmarshalBinary(b []byte) error {
	var res OTPPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
