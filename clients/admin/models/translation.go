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

// Translation Translation
//
// swagger:model Translation
type Translation struct {

	// built-in exists
	BuiltInExists bool `json:"built_in_exists,omitempty" yaml:"built_in_exists,omitempty"`

	// content of the translation
	Content map[string]interface{} `json:"content,omitempty" yaml:"content,omitempty"`

	// timestamp when the translation was created
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty" yaml:"created_at,omitempty"`

	// enabled
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// Is built-in translation
	IsBuiltIn bool `json:"is_built_in,omitempty" yaml:"is_built_in,omitempty"`

	// translation locale
	// Required: true
	Locale string `json:"locale" yaml:"locale"`

	// ID of the tenant
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// timestamp when the translation was last updated
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// Validate validates this translation
func (m *Translation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocale(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Translation) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Translation) validateLocale(formats strfmt.Registry) error {

	if err := validate.RequiredString("locale", "body", m.Locale); err != nil {
		return err
	}

	return nil
}

func (m *Translation) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

func (m *Translation) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this translation based on context it is used
func (m *Translation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Translation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Translation) UnmarshalBinary(b []byte) error {
	var res Translation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
