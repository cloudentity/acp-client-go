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

// JITDeniedPayload j i t denied payload
//
// swagger:model JITDeniedPayload
type JITDeniedPayload struct {

	// authentication flow control
	AuthenticationFlowControl PreProvisioningAuthenticationFlowControl `json:"authentication_flow_control,omitempty" yaml:"authentication_flow_control,omitempty"`

	// idp
	Idp *IDPPayload `json:"idp,omitempty" yaml:"idp,omitempty"`

	// mode
	Mode ProvisioningMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// pool id
	PoolID string `json:"pool_id,omitempty" yaml:"pool_id,omitempty"`
}

// Validate validates this j i t denied payload
func (m *JITDeniedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationFlowControl(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JITDeniedPayload) validateAuthenticationFlowControl(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationFlowControl) { // not required
		return nil
	}

	if err := m.AuthenticationFlowControl.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_flow_control")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_flow_control")
		}
		return err
	}

	return nil
}

func (m *JITDeniedPayload) validateIdp(formats strfmt.Registry) error {
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

func (m *JITDeniedPayload) validateMode(formats strfmt.Registry) error {
	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

// ContextValidate validate this j i t denied payload based on the context it is used
func (m *JITDeniedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationFlowControl(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIdp(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JITDeniedPayload) contextValidateAuthenticationFlowControl(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.AuthenticationFlowControl) { // not required
		return nil
	}

	if err := m.AuthenticationFlowControl.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_flow_control")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_flow_control")
		}
		return err
	}

	return nil
}

func (m *JITDeniedPayload) contextValidateIdp(ctx context.Context, formats strfmt.Registry) error {

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

func (m *JITDeniedPayload) contextValidateMode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *JITDeniedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JITDeniedPayload) UnmarshalBinary(b []byte) error {
	var res JITDeniedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
