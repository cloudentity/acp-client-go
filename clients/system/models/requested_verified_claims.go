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

// RequestedVerifiedClaims requested verified claims
//
// swagger:model RequestedVerifiedClaims
type RequestedVerifiedClaims struct {

	// claims
	Claims map[string]ClaimRequest `json:"claims,omitempty" yaml:"claims,omitempty"`

	// verification
	Verification *ClaimsVerification `json:"verification,omitempty" yaml:"verification,omitempty"`
}

// Validate validates this requested verified claims
func (m *RequestedVerifiedClaims) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClaims(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerification(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestedVerifiedClaims) validateClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.Claims) { // not required
		return nil
	}

	for k := range m.Claims {

		if err := validate.Required("claims"+"."+k, "body", m.Claims[k]); err != nil {
			return err
		}
		if val, ok := m.Claims[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("claims" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("claims" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *RequestedVerifiedClaims) validateVerification(formats strfmt.Registry) error {
	if swag.IsZero(m.Verification) { // not required
		return nil
	}

	if m.Verification != nil {
		if err := m.Verification.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this requested verified claims based on the context it is used
func (m *RequestedVerifiedClaims) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerification(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestedVerifiedClaims) contextValidateClaims(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.Claims {

		if val, ok := m.Claims[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *RequestedVerifiedClaims) contextValidateVerification(ctx context.Context, formats strfmt.Registry) error {

	if m.Verification != nil {

		if swag.IsZero(m.Verification) { // not required
			return nil
		}

		if err := m.Verification.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestedVerifiedClaims) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestedVerifiedClaims) UnmarshalBinary(b []byte) error {
	var res RequestedVerifiedClaims
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}