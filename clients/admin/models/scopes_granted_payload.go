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

// ScopesGrantedPayload scopes granted payload
//
// swagger:model ScopesGrantedPayload
type ScopesGrantedPayload struct {

	// List of scopes to grant.
	NewScopeGrants []*ScopeGrant `json:"new_scope_grants" yaml:"new_scope_grants"`
}

// Validate validates this scopes granted payload
func (m *ScopesGrantedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNewScopeGrants(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScopesGrantedPayload) validateNewScopeGrants(formats strfmt.Registry) error {
	if swag.IsZero(m.NewScopeGrants) { // not required
		return nil
	}

	for i := 0; i < len(m.NewScopeGrants); i++ {
		if swag.IsZero(m.NewScopeGrants[i]) { // not required
			continue
		}

		if m.NewScopeGrants[i] != nil {
			if err := m.NewScopeGrants[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("new_scope_grants" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("new_scope_grants" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this scopes granted payload based on the context it is used
func (m *ScopesGrantedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateNewScopeGrants(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScopesGrantedPayload) contextValidateNewScopeGrants(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NewScopeGrants); i++ {

		if m.NewScopeGrants[i] != nil {

			if swag.IsZero(m.NewScopeGrants[i]) { // not required
				return nil
			}

			if err := m.NewScopeGrants[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("new_scope_grants" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("new_scope_grants" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ScopesGrantedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScopesGrantedPayload) UnmarshalBinary(b []byte) error {
	var res ScopesGrantedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
