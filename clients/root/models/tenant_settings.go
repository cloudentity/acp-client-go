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

// TenantSettings tenant settings
//
// swagger:model TenantSettings
type TenantSettings struct {

	// default template id
	DefaultTemplateID string `json:"default_template_id,omitempty" yaml:"default_template_id,omitempty"`

	// default workspace id
	DefaultWorkspaceID string `json:"default_workspace_id,omitempty" yaml:"default_workspace_id,omitempty"`

	// security
	Security *SecureOptions `json:"security,omitempty" yaml:"security,omitempty"`

	// translations
	Translations *TenantTranslationsSettings `json:"translations,omitempty" yaml:"translations,omitempty"`

	// well known
	WellKnown map[string]interface{} `json:"well_known,omitempty" yaml:"well_known,omitempty"`

	// workforce
	Workforce *WorkforceSettings `json:"workforce,omitempty" yaml:"workforce,omitempty"`
}

// Validate validates this tenant settings
func (m *TenantSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSecurity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTranslations(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWorkforce(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TenantSettings) validateSecurity(formats strfmt.Registry) error {
	if swag.IsZero(m.Security) { // not required
		return nil
	}

	if m.Security != nil {
		if err := m.Security.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("security")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("security")
			}
			return err
		}
	}

	return nil
}

func (m *TenantSettings) validateTranslations(formats strfmt.Registry) error {
	if swag.IsZero(m.Translations) { // not required
		return nil
	}

	if m.Translations != nil {
		if err := m.Translations.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("translations")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("translations")
			}
			return err
		}
	}

	return nil
}

func (m *TenantSettings) validateWorkforce(formats strfmt.Registry) error {
	if swag.IsZero(m.Workforce) { // not required
		return nil
	}

	if m.Workforce != nil {
		if err := m.Workforce.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("workforce")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("workforce")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tenant settings based on the context it is used
func (m *TenantSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSecurity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTranslations(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWorkforce(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TenantSettings) contextValidateSecurity(ctx context.Context, formats strfmt.Registry) error {

	if m.Security != nil {

		if swag.IsZero(m.Security) { // not required
			return nil
		}

		if err := m.Security.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("security")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("security")
			}
			return err
		}
	}

	return nil
}

func (m *TenantSettings) contextValidateTranslations(ctx context.Context, formats strfmt.Registry) error {

	if m.Translations != nil {

		if swag.IsZero(m.Translations) { // not required
			return nil
		}

		if err := m.Translations.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("translations")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("translations")
			}
			return err
		}
	}

	return nil
}

func (m *TenantSettings) contextValidateWorkforce(ctx context.Context, formats strfmt.Registry) error {

	if m.Workforce != nil {

		if swag.IsZero(m.Workforce) { // not required
			return nil
		}

		if err := m.Workforce.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("workforce")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("workforce")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TenantSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TenantSettings) UnmarshalBinary(b []byte) error {
	var res TenantSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
