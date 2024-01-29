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

// AcceptScopeGrant accept scope grant
//
// swagger:model AcceptScopeGrant
type AcceptScopeGrant struct {

	// optional consent identifier
	ConsentID string `json:"consent_id,omitempty" yaml:"consent_id,omitempty"`

	// granted claims
	GrantedClaims GrantedClaims `json:"granted_claims,omitempty" yaml:"granted_claims,omitempty"`

	// granted scopes
	GrantedScopes GrantedScopes `json:"granted_scopes,omitempty" yaml:"granted_scopes,omitempty"`

	// login identifier
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// login state
	LoginState string `json:"login_state,omitempty" yaml:"login_state,omitempty"`
}

// Validate validates this accept scope grant
func (m *AcceptScopeGrant) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGrantedClaims(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGrantedScopes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptScopeGrant) validateGrantedClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantedClaims) { // not required
		return nil
	}

	if err := m.GrantedClaims.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_claims")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_claims")
		}
		return err
	}

	return nil
}

func (m *AcceptScopeGrant) validateGrantedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantedScopes) { // not required
		return nil
	}

	if err := m.GrantedScopes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_scopes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_scopes")
		}
		return err
	}

	return nil
}

// ContextValidate validate this accept scope grant based on the context it is used
func (m *AcceptScopeGrant) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGrantedClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGrantedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptScopeGrant) contextValidateGrantedClaims(ctx context.Context, formats strfmt.Registry) error {

	if err := m.GrantedClaims.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_claims")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_claims")
		}
		return err
	}

	return nil
}

func (m *AcceptScopeGrant) contextValidateGrantedScopes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.GrantedScopes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_scopes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_scopes")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AcceptScopeGrant) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AcceptScopeGrant) UnmarshalBinary(b []byte) error {
	var res AcceptScopeGrant
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
