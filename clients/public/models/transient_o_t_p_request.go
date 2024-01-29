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

// TransientOTPRequest transient o t p request
//
// swagger:model TransientOTPRequest
type TransientOTPRequest struct {

	// address
	// Example: 1235555609
	// Required: true
	Address string `json:"address" yaml:"address"`

	// mechanism
	// Example: email
	// Required: true
	// Enum: [sms email]
	Mechanism string `json:"mechanism" yaml:"mechanism"`

	// one-time password
	// Example: 111111
	Otp string `json:"otp,omitempty" yaml:"otp,omitempty"`

	// Optional XSRF state
	// Example: c44sqtco4g2legl15m2g
	State string `json:"state,omitempty" yaml:"state,omitempty"`
}

// Validate validates this transient o t p request
func (m *TransientOTPRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMechanism(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransientOTPRequest) validateAddress(formats strfmt.Registry) error {

	if err := validate.RequiredString("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

var transientOTPRequestTypeMechanismPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","email"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		transientOTPRequestTypeMechanismPropEnum = append(transientOTPRequestTypeMechanismPropEnum, v)
	}
}

const (

	// TransientOTPRequestMechanismSms captures enum value "sms"
	TransientOTPRequestMechanismSms string = "sms"

	// TransientOTPRequestMechanismEmail captures enum value "email"
	TransientOTPRequestMechanismEmail string = "email"
)

// prop value enum
func (m *TransientOTPRequest) validateMechanismEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, transientOTPRequestTypeMechanismPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *TransientOTPRequest) validateMechanism(formats strfmt.Registry) error {

	if err := validate.RequiredString("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	// value enum
	if err := m.validateMechanismEnum("mechanism", "body", m.Mechanism); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this transient o t p request based on context it is used
func (m *TransientOTPRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TransientOTPRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransientOTPRequest) UnmarshalBinary(b []byte) error {
	var res TransientOTPRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
