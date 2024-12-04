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

// JITCreatedPayload j i t created payload
//
// swagger:model JITCreatedPayload
type JITCreatedPayload struct {

	// admin role type
	AdminRoleType string `json:"admin_role_type,omitempty" yaml:"admin_role_type,omitempty"`

	// idp
	Idp *IDPPayload `json:"idp,omitempty" yaml:"idp,omitempty"`

	// pool id
	PoolID string `json:"pool_id,omitempty" yaml:"pool_id,omitempty"`

	// user id
	UserID string `json:"user_id,omitempty" yaml:"user_id,omitempty"`
}

// Validate validates this j i t created payload
func (m *JITCreatedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JITCreatedPayload) validateIdp(formats strfmt.Registry) error {
	if swag.IsZero(m.Idp) { // not required
		return nil
	}

	if m.Idp != nil {
		if err := m.Idp.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("idp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("idp")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this j i t created payload based on the context it is used
func (m *JITCreatedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateIdp(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JITCreatedPayload) contextValidateIdp(ctx context.Context, formats strfmt.Registry) error {

	if m.Idp != nil {

		if swag.IsZero(m.Idp) { // not required
			return nil
		}

		if err := m.Idp.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("idp")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("idp")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *JITCreatedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JITCreatedPayload) UnmarshalBinary(b []byte) error {
	var res JITCreatedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
