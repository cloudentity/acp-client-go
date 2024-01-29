// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TreeScriptExecutionPoint tree script execution point
//
// swagger:model TreeScriptExecutionPoint
type TreeScriptExecutionPoint struct {

	// Optional script ID
	// Example: 1
	ScriptID string `json:"script_id,omitempty" yaml:"script_id,omitempty"`
}

// Validate validates this tree script execution point
func (m *TreeScriptExecutionPoint) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this tree script execution point based on context it is used
func (m *TreeScriptExecutionPoint) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TreeScriptExecutionPoint) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeScriptExecutionPoint) UnmarshalBinary(b []byte) error {
	var res TreeScriptExecutionPoint
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
