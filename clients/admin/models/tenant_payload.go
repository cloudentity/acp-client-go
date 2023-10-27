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

// TenantPayload tenant payload
//
// swagger:model TenantPayload
type TenantPayload struct {

	// tenant unique identifier
	// exampe: default
	ID string `json:"id,omitempty"`

	// jwks
	Jwks *ServerJWKs `json:"jwks,omitempty"`

	// metadata
	Metadata TenantMetadata `json:"metadata,omitempty"`

	// tenant name
	// Example: Default
	Name string `json:"name,omitempty"`

	// settings
	Settings *TenantSettings `json:"settings,omitempty"`

	// styling
	Styling *Styling `json:"styling,omitempty"`

	// optional custom tenant url. If not provided the server url is used instead
	// Example: https://example.com/default
	URL string `json:"url,omitempty"`
}

// Validate validates this tenant payload
func (m *TenantPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSettings(formats); err != nil {
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

func (m *TenantPayload) validateJwks(formats strfmt.Registry) error {
	if swag.IsZero(m.Jwks) { // not required
		return nil
	}

	if m.Jwks != nil {
		if err := m.Jwks.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *TenantPayload) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

func (m *TenantPayload) validateSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.Settings) { // not required
		return nil
	}

	if m.Settings != nil {
		if err := m.Settings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("settings")
			}
			return err
		}
	}

	return nil
}

func (m *TenantPayload) validateStyling(formats strfmt.Registry) error {
	if swag.IsZero(m.Styling) { // not required
		return nil
	}

	if m.Styling != nil {
		if err := m.Styling.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("styling")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("styling")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tenant payload based on the context it is used
func (m *TenantPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSettings(ctx, formats); err != nil {
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

func (m *TenantPayload) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

	if m.Jwks != nil {

		if swag.IsZero(m.Jwks) { // not required
			return nil
		}

		if err := m.Jwks.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *TenantPayload) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("metadata")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("metadata")
		}
		return err
	}

	return nil
}

func (m *TenantPayload) contextValidateSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.Settings != nil {

		if swag.IsZero(m.Settings) { // not required
			return nil
		}

		if err := m.Settings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("settings")
			}
			return err
		}
	}

	return nil
}

func (m *TenantPayload) contextValidateStyling(ctx context.Context, formats strfmt.Registry) error {

	if m.Styling != nil {

		if swag.IsZero(m.Styling) { // not required
			return nil
		}

		if err := m.Styling.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("styling")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("styling")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TenantPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TenantPayload) UnmarshalBinary(b []byte) error {
	var res TenantPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}