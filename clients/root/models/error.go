// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Error HTTP error response
//
// swagger:model Error
type Error struct {

	// details
	Details interface{} `json:"details,omitempty" yaml:"details,omitempty"`

	// error
	Error string `json:"error,omitempty" yaml:"error,omitempty"`

	// error code
	ErrorCode string `json:"error_code,omitempty" yaml:"error_code,omitempty"`

	// status code
	StatusCode int64 `json:"status_code,omitempty" yaml:"status_code,omitempty"`
}

// Validate validates this error
func (m *Error) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this error based on context it is used
func (m *Error) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Error) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Error) UnmarshalBinary(b []byte) error {
	var res Error
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
