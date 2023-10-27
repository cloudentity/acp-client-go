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

// TreeTheme tree theme
//
// swagger:model TreeTheme
type TreeTheme struct {

	// theme logo url
	LogoURL string `json:"logo_url,omitempty"`

	// Display name of the theme
	// Example: acme
	Name string `json:"name,omitempty"`

	// templates
	Templates TreeTemplates `json:"templates,omitempty"`
}

// Validate validates this tree theme
func (m *TreeTheme) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTemplates(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeTheme) validateTemplates(formats strfmt.Registry) error {
	if swag.IsZero(m.Templates) { // not required
		return nil
	}

	if m.Templates != nil {
		if err := m.Templates.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("templates")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("templates")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tree theme based on the context it is used
func (m *TreeTheme) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTemplates(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeTheme) contextValidateTemplates(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Templates) { // not required
		return nil
	}

	if err := m.Templates.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("templates")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("templates")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreeTheme) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeTheme) UnmarshalBinary(b []byte) error {
	var res TreeTheme
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}