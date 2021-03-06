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

// AcceptLogin accept login
//
// swagger:model AcceptLogin
type AcceptLogin struct {

	// authentication context class reference
	Acr string `json:"acr,omitempty"`

	// authentication methods references
	Amr []string `json:"amr"`

	// time when user authenticated
	// Format: date-time
	AuthTime strfmt.DateTime `json:"auth_time,omitempty"`

	// login identifier
	ID string `json:"id,omitempty"`

	// login state
	LoginState string `json:"login_state,omitempty"`

	// user identifier
	// Example: user
	Subject string `json:"subject,omitempty"`

	// authentication context
	AuthenticationContext AuthenticationContext `json:"authentication_context,omitempty"`
}

// Validate validates this accept login
func (m *AcceptLogin) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticationContext(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptLogin) validateAuthTime(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthTime) { // not required
		return nil
	}

	if err := validate.FormatOf("auth_time", "body", "date-time", m.AuthTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AcceptLogin) validateAuthenticationContext(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if m.AuthenticationContext != nil {
		if err := m.AuthenticationContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this accept login based on the context it is used
func (m *AcceptLogin) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptLogin) contextValidateAuthenticationContext(ctx context.Context, formats strfmt.Registry) error {

	if err := m.AuthenticationContext.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_context")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AcceptLogin) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AcceptLogin) UnmarshalBinary(b []byte) error {
	var res AcceptLogin
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
