// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// TreeScriptExecutionPointType tree script execution point type
//
// swagger:model TreeScriptExecutionPointType
type TreeScriptExecutionPointType map[string]TreeScriptExecutionPoint

// Validate validates this tree script execution point type
func (m TreeScriptExecutionPointType) Validate(formats strfmt.Registry) error {
	var res []error

	for k := range m {

		if err := validate.Required(k, "body", m[k]); err != nil {
			return err
		}
		if val, ok := m[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName(k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName(k)
				}
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validate this tree script execution point type based on the context it is used
func (m TreeScriptExecutionPointType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	for k := range m {

		if val, ok := m[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
