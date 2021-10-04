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

// ScriptExecutionResult script execution result
//
// swagger:model ScriptExecutionResult
type ScriptExecutionResult struct {

	// name of the error
	CaughtErr string `json:"CaughtErr,omitempty"`

	// script execution time
	// Format: duration
	Duration strfmt.Duration `json:"Duration,omitempty"`

	// script id
	ID string `json:"ID,omitempty"`

	// script input
	Input map[string]interface{} `json:"Input,omitempty"`

	// script output
	Output map[string]interface{} `json:"Output,omitempty"`

	// script standard error, e.g. console.error()
	StdErr string `json:"StdErr,omitempty"`

	// script standard output, e.g. console.log()
	StdOut string `json:"StdOut,omitempty"`
}

// Validate validates this script execution result
func (m *ScriptExecutionResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDuration(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScriptExecutionResult) validateDuration(formats strfmt.Registry) error {
	if swag.IsZero(m.Duration) { // not required
		return nil
	}

	if err := validate.FormatOf("Duration", "body", "duration", m.Duration.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this script execution result based on context it is used
func (m *ScriptExecutionResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ScriptExecutionResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScriptExecutionResult) UnmarshalBinary(b []byte) error {
	var res ScriptExecutionResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
