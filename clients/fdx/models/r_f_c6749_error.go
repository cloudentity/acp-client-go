// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RFC6749Error r f c6749 error
//
// swagger:model RFC6749Error
type RFC6749Error struct {

	// cause
	Cause string `json:"cause,omitempty"`

	// error
	Error string `json:"error,omitempty"`

	// error description
	ErrorDescription string `json:"error_description,omitempty"`

	// error hint
	ErrorHint string `json:"error_hint,omitempty"`

	// status code
	StatusCode int64 `json:"status_code,omitempty"`
}

// Validate validates this r f c6749 error
func (m *RFC6749Error) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this r f c6749 error based on context it is used
func (m *RFC6749Error) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RFC6749Error) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RFC6749Error) UnmarshalBinary(b []byte) error {
	var res RFC6749Error
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
