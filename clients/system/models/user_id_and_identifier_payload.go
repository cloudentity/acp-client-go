// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UserIDAndIdentifierPayload UserIDAndIdentifierPayload user ID and identifier payload
//
// swagger:model UserIDAndIdentifierPayload
type UserIDAndIdentifierPayload struct {

	// code id
	CodeID string `json:"code_id,omitempty" yaml:"code_id,omitempty"`

	// failure reason
	FailureReason string `json:"failure_reason,omitempty" yaml:"failure_reason,omitempty"`

	// identifier
	Identifier string `json:"identifier,omitempty" yaml:"identifier,omitempty"`

	// operation type
	OperationType string `json:"operation_type,omitempty" yaml:"operation_type,omitempty"`

	// user id
	UserID string `json:"user_id,omitempty" yaml:"user_id,omitempty"`
}

// Validate validates this user ID and identifier payload
func (m *UserIDAndIdentifierPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this user ID and identifier payload based on context it is used
func (m *UserIDAndIdentifierPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserIDAndIdentifierPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserIDAndIdentifierPayload) UnmarshalBinary(b []byte) error {
	var res UserIDAndIdentifierPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
