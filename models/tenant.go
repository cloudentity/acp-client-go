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

// Tenant tenant
//
// swagger:model Tenant
type Tenant struct {

	// authentication context settings
	AuthenticationContextSettings *AuthenticationContextSettings `json:"authentication_context_settings,omitempty"`

	// tenant unique identifier
	// exampe: default
	ID string `json:"id,omitempty"`

	// jwks
	Jwks *ServerJWKs `json:"jwks,omitempty"`

	// tenant name
	// Example: Default
	Name string `json:"name,omitempty"`

	// styling
	Styling *Styling `json:"styling,omitempty"`

	// optional custom tenant url. If not provided the server url is used instead
	// Example: https://example.com/default
	URL string `json:"url,omitempty"`
}

// Validate validates this tenant
func (m *Tenant) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationContextSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStyling(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Tenant) validateAuthenticationContextSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationContextSettings) { // not required
		return nil
	}

	if m.AuthenticationContextSettings != nil {
		if err := m.AuthenticationContextSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context_settings")
			}
			return err
		}
	}

	return nil
}

func (m *Tenant) validateJwks(formats strfmt.Registry) error {
	if swag.IsZero(m.Jwks) { // not required
		return nil
	}

	if m.Jwks != nil {
		if err := m.Jwks.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *Tenant) validateStyling(formats strfmt.Registry) error {
	if swag.IsZero(m.Styling) { // not required
		return nil
	}

	if m.Styling != nil {
		if err := m.Styling.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("styling")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tenant based on the context it is used
func (m *Tenant) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContextSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStyling(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Tenant) contextValidateAuthenticationContextSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.AuthenticationContextSettings != nil {
		if err := m.AuthenticationContextSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context_settings")
			}
			return err
		}
	}

	return nil
}

func (m *Tenant) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

	if m.Jwks != nil {
		if err := m.Jwks.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *Tenant) contextValidateStyling(ctx context.Context, formats strfmt.Registry) error {

	if m.Styling != nil {
		if err := m.Styling.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("styling")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Tenant) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Tenant) UnmarshalBinary(b []byte) error {
	var res Tenant
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
