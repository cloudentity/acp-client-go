// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ClaimsVerification claims verification
//
// swagger:model ClaimsVerification
type ClaimsVerification struct {

	// trust framework
	TrustFramework *ClaimRequest `json:"trust_framework,omitempty" yaml:"trust_framework,omitempty"`
}

// Validate validates this claims verification
func (m *ClaimsVerification) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTrustFramework(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClaimsVerification) validateTrustFramework(formats strfmt.Registry) error {
	if swag.IsZero(m.TrustFramework) { // not required
		return nil
	}

	if m.TrustFramework != nil {
		if err := m.TrustFramework.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("trust_framework")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("trust_framework")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this claims verification based on the context it is used
func (m *ClaimsVerification) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTrustFramework(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClaimsVerification) contextValidateTrustFramework(ctx context.Context, formats strfmt.Registry) error {

	if m.TrustFramework != nil {

		if swag.IsZero(m.TrustFramework) { // not required
			return nil
		}

		if err := m.TrustFramework.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("trust_framework")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("trust_framework")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ClaimsVerification) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClaimsVerification) UnmarshalBinary(b []byte) error {
	var res ClaimsVerification
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
