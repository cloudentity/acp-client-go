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

// TreeTenant tree tenant
//
// swagger:model TreeTenant
type TreeTenant struct {

	// features
	Features TreeFeatures `json:"features,omitempty" yaml:"features,omitempty"`

	// jwks
	Jwks *ServerJWKs `json:"jwks,omitempty" yaml:"jwks,omitempty"`

	// metadata
	Metadata TenantMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// mfa methods
	MfaMethods TreeMFAMethods `json:"mfa_methods,omitempty" yaml:"mfa_methods,omitempty"`

	// tenant name
	// Example: Default
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// pools
	Pools TreePools `json:"pools,omitempty" yaml:"pools,omitempty"`

	// schemas
	Schemas TreeSchemas `json:"schemas,omitempty" yaml:"schemas,omitempty"`

	// servers
	Servers TreeServers `json:"servers,omitempty" yaml:"servers,omitempty"`

	// settings
	Settings *TenantSettings `json:"settings,omitempty" yaml:"settings,omitempty"`

	// styling
	Styling *Styling `json:"styling,omitempty" yaml:"styling,omitempty"`

	// themes
	Themes TreeThemes `json:"themes,omitempty" yaml:"themes,omitempty"`

	// translations
	Translations TreeTranslations `json:"translations,omitempty" yaml:"translations,omitempty"`

	// optional custom tenant url. If not provided the server url is used instead
	// Example: https://example.com/default
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
}

// Validate validates this tree tenant
func (m *TreeTenant) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFeatures(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMfaMethods(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePools(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchemas(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStyling(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThemes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTranslations(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeTenant) validateFeatures(formats strfmt.Registry) error {
	if swag.IsZero(m.Features) { // not required
		return nil
	}

	if m.Features != nil {
		if err := m.Features.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("features")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("features")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validateJwks(formats strfmt.Registry) error {
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

func (m *TreeTenant) validateMetadata(formats strfmt.Registry) error {
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

func (m *TreeTenant) validateMfaMethods(formats strfmt.Registry) error {
	if swag.IsZero(m.MfaMethods) { // not required
		return nil
	}

	if m.MfaMethods != nil {
		if err := m.MfaMethods.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mfa_methods")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("mfa_methods")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validatePools(formats strfmt.Registry) error {
	if swag.IsZero(m.Pools) { // not required
		return nil
	}

	if m.Pools != nil {
		if err := m.Pools.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pools")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pools")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validateSchemas(formats strfmt.Registry) error {
	if swag.IsZero(m.Schemas) { // not required
		return nil
	}

	if m.Schemas != nil {
		if err := m.Schemas.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("schemas")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("schemas")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validateServers(formats strfmt.Registry) error {
	if swag.IsZero(m.Servers) { // not required
		return nil
	}

	if m.Servers != nil {
		if err := m.Servers.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("servers")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("servers")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validateSettings(formats strfmt.Registry) error {
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

func (m *TreeTenant) validateStyling(formats strfmt.Registry) error {
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

func (m *TreeTenant) validateThemes(formats strfmt.Registry) error {
	if swag.IsZero(m.Themes) { // not required
		return nil
	}

	if m.Themes != nil {
		if err := m.Themes.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("themes")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("themes")
			}
			return err
		}
	}

	return nil
}

func (m *TreeTenant) validateTranslations(formats strfmt.Registry) error {
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

// ContextValidate validate this tree tenant based on the context it is used
func (m *TreeTenant) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFeatures(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMfaMethods(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePools(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSchemas(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStyling(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThemes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTranslations(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeTenant) contextValidateFeatures(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Features) { // not required
		return nil
	}

	if err := m.Features.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("features")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("features")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

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

func (m *TreeTenant) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

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

func (m *TreeTenant) contextValidateMfaMethods(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.MfaMethods) { // not required
		return nil
	}

	if err := m.MfaMethods.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mfa_methods")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mfa_methods")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidatePools(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Pools) { // not required
		return nil
	}

	if err := m.Pools.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("pools")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("pools")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidateSchemas(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Schemas) { // not required
		return nil
	}

	if err := m.Schemas.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("schemas")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("schemas")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidateServers(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Servers) { // not required
		return nil
	}

	if err := m.Servers.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("servers")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("servers")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidateSettings(ctx context.Context, formats strfmt.Registry) error {

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

func (m *TreeTenant) contextValidateStyling(ctx context.Context, formats strfmt.Registry) error {

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

func (m *TreeTenant) contextValidateThemes(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Themes) { // not required
		return nil
	}

	if err := m.Themes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("themes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("themes")
		}
		return err
	}

	return nil
}

func (m *TreeTenant) contextValidateTranslations(ctx context.Context, formats strfmt.Registry) error {

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

	return nil
}

// MarshalBinary interface implementation
func (m *TreeTenant) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeTenant) UnmarshalBinary(b []byte) error {
	var res TreeTenant
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
