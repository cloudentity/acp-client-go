// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ValidateResponseValidatorFailure validate response validator failure
//
// swagger:model ValidateResponse_ValidatorFailure
type ValidateResponseValidatorFailure struct {

	// details
	Details string `json:"details,omitempty" yaml:"details,omitempty"`

	// message
	Message string `json:"message,omitempty" yaml:"message,omitempty"`

	// validator
	Validator string `json:"validator,omitempty" yaml:"validator,omitempty"`
}

// Validate validates this validate response validator failure
func (m *ValidateResponseValidatorFailure) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this validate response validator failure based on context it is used
func (m *ValidateResponseValidatorFailure) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ValidateResponseValidatorFailure) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ValidateResponseValidatorFailure) UnmarshalBinary(b []byte) error {
	var res ValidateResponseValidatorFailure
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
