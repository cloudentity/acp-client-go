// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RequestOTPCode request o t p code
//
// swagger:model RequestOTPCode
type RequestOTPCode struct {

	// address
	Address string `json:"address,omitempty"`

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// user ID
	UserID string `json:"userID,omitempty"`
}

// Validate validates this request o t p code
func (m *RequestOTPCode) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this request o t p code based on context it is used
func (m *RequestOTPCode) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RequestOTPCode) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestOTPCode) UnmarshalBinary(b []byte) error {
	var res RequestOTPCode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}