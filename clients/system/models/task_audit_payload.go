// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TaskAuditPayload task audit payload
//
// swagger:model TaskAuditPayload
type TaskAuditPayload struct {

	// attributes
	Attributes interface{} `json:"attributes,omitempty" yaml:"attributes,omitempty"`

	// error
	Error string `json:"error,omitempty" yaml:"error,omitempty"`

	// name
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// Validate validates this task audit payload
func (m *TaskAuditPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this task audit payload based on context it is used
func (m *TaskAuditPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TaskAuditPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TaskAuditPayload) UnmarshalBinary(b []byte) error {
	var res TaskAuditPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
