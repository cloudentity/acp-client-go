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

// PayloadSettings payload settings
//
// swagger:model PayloadSettings
type PayloadSettings struct {

	// payload format
	// Enum: [json jws]
	Format string `json:"format,omitempty"`

	// jws payload
	JwsPayload *JWSPayloadSettings `json:"jws_payload,omitempty"`
}

// Validate validates this payload settings
func (m *PayloadSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJwsPayload(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var payloadSettingsTypeFormatPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["json","jws"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		payloadSettingsTypeFormatPropEnum = append(payloadSettingsTypeFormatPropEnum, v)
	}
}

const (

	// PayloadSettingsFormatJSON captures enum value "json"
	PayloadSettingsFormatJSON string = "json"

	// PayloadSettingsFormatJws captures enum value "jws"
	PayloadSettingsFormatJws string = "jws"
)

// prop value enum
func (m *PayloadSettings) validateFormatEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, payloadSettingsTypeFormatPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *PayloadSettings) validateFormat(formats strfmt.Registry) error {
	if swag.IsZero(m.Format) { // not required
		return nil
	}

	// value enum
	if err := m.validateFormatEnum("format", "body", m.Format); err != nil {
		return err
	}

	return nil
}

func (m *PayloadSettings) validateJwsPayload(formats strfmt.Registry) error {
	if swag.IsZero(m.JwsPayload) { // not required
		return nil
	}

	if m.JwsPayload != nil {
		if err := m.JwsPayload.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jws_payload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jws_payload")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this payload settings based on the context it is used
func (m *PayloadSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateJwsPayload(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PayloadSettings) contextValidateJwsPayload(ctx context.Context, formats strfmt.Registry) error {

	if m.JwsPayload != nil {

		if swag.IsZero(m.JwsPayload) { // not required
			return nil
		}

		if err := m.JwsPayload.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jws_payload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jws_payload")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PayloadSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PayloadSettings) UnmarshalBinary(b []byte) error {
	var res PayloadSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
