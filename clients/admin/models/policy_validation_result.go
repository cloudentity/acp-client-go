// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PolicyValidationResult Provides information on the results of a policy validation
//
// swagger:model PolicyValidationResult
type PolicyValidationResult struct {

	// An array of failures that took place during the policy validation process
	Failure []*PolicyValidationFailure `json:"failure"`

	// An array of recovery methods that take place when a policy validation fails
	Recovery []*PolicyValidationRecovery `json:"recovery"`

	// String representation of the policy validation result
	Result string `json:"result,omitempty"`
}

// Validate validates this policy validation result
func (m *PolicyValidationResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFailure(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecovery(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PolicyValidationResult) validateFailure(formats strfmt.Registry) error {
	if swag.IsZero(m.Failure) { // not required
		return nil
	}

	for i := 0; i < len(m.Failure); i++ {
		if swag.IsZero(m.Failure[i]) { // not required
			continue
		}

		if m.Failure[i] != nil {
			if err := m.Failure[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("failure" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("failure" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PolicyValidationResult) validateRecovery(formats strfmt.Registry) error {
	if swag.IsZero(m.Recovery) { // not required
		return nil
	}

	for i := 0; i < len(m.Recovery); i++ {
		if swag.IsZero(m.Recovery[i]) { // not required
			continue
		}

		if m.Recovery[i] != nil {
			if err := m.Recovery[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recovery" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("recovery" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this policy validation result based on the context it is used
func (m *PolicyValidationResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFailure(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRecovery(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PolicyValidationResult) contextValidateFailure(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Failure); i++ {

		if m.Failure[i] != nil {
			if err := m.Failure[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("failure" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("failure" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PolicyValidationResult) contextValidateRecovery(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Recovery); i++ {

		if m.Recovery[i] != nil {
			if err := m.Recovery[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recovery" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("recovery" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *PolicyValidationResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PolicyValidationResult) UnmarshalBinary(b []byte) error {
	var res PolicyValidationResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
