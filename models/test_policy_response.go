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

// TestPolicyResponse test policy response
//
// swagger:model TestPolicyResponse
type TestPolicyResponse struct {

	// failures
	Failures []*ValidateResponseValidatorFailure `json:"failures"`

	// recovery
	Recovery []*ValidateResponseRecovery `json:"recovery"`

	// result
	Result string `json:"result,omitempty"`

	// status
	Status bool `json:"status,omitempty"`
}

// Validate validates this test policy response
func (m *TestPolicyResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFailures(formats); err != nil {
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

func (m *TestPolicyResponse) validateFailures(formats strfmt.Registry) error {
	if swag.IsZero(m.Failures) { // not required
		return nil
	}

	for i := 0; i < len(m.Failures); i++ {
		if swag.IsZero(m.Failures[i]) { // not required
			continue
		}

		if m.Failures[i] != nil {
			if err := m.Failures[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("failures" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TestPolicyResponse) validateRecovery(formats strfmt.Registry) error {
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
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this test policy response based on the context it is used
func (m *TestPolicyResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFailures(ctx, formats); err != nil {
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

func (m *TestPolicyResponse) contextValidateFailures(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Failures); i++ {

		if m.Failures[i] != nil {
			if err := m.Failures[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("failures" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TestPolicyResponse) contextValidateRecovery(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Recovery); i++ {

		if m.Recovery[i] != nil {
			if err := m.Recovery[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recovery" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TestPolicyResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestPolicyResponse) UnmarshalBinary(b []byte) error {
	var res TestPolicyResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
