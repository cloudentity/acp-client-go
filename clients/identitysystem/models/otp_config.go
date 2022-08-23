// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OtpConfig otp config
//
// swagger:model OtpConfig
type OtpConfig struct {

	// length
	Length int64 `json:"length,omitempty"`

	// ttl
	// Format: duration
	TTL strfmt.Duration `json:"ttl,omitempty"`
}

// Validate validates this otp config
func (m *OtpConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTTL(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OtpConfig) validateTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.TTL) { // not required
		return nil
	}

	if err := validate.FormatOf("ttl", "body", "duration", m.TTL.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this otp config based on context it is used
func (m *OtpConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OtpConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OtpConfig) UnmarshalBinary(b []byte) error {
	var res OtpConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
