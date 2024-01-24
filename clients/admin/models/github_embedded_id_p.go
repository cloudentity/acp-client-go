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

// GithubEmbeddedIDP github embedded ID p
//
// swagger:model GithubEmbeddedIDP
type GithubEmbeddedIDP struct {

	// attributes
	Attributes Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"`

	// ID of the authorization server (workspace) to which the IDP is connected
	AuthorizationServerID string `json:"authorization_server_id,omitempty" yaml:"authorization_server_id,omitempty"`

	// Client application ID
	//
	// It serves as a reference to a client application that is created in the System authorization
	// server (workspace), when a custom login page is created.
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// config
	Config *IDPConfiguration `json:"config,omitempty" yaml:"config,omitempty"`

	// If set to `true`, the IDP is disabled
	//
	// When an IDP is disabled, it is not available for the users to be used. It is also not
	// displayed on the login page.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// discovery settings
	DiscoverySettings *IDPDiscoverySettings `json:"discovery_settings,omitempty" yaml:"discovery_settings,omitempty"`

	// Can be used to e.g. modify the order in which the Identity Providers are presented on the login page.
	// Example: 1
	DisplayOrder int64 `json:"display_order,omitempty" yaml:"display_order,omitempty"`

	// If set to `true`, the IDP is not displayed on the login page.
	//
	// When an IDP is hidden, it will not be displayed on the login page. It can still be used
	// and script extensions can enabled it.
	Hidden bool `json:"hidden,omitempty" yaml:"hidden,omitempty"`

	// Unique ID of your identity provider
	//
	// If not provided, a random ID is generated.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// ID of the Identity Pool to which the IDP is connected
	IdentityPoolID string `json:"identity_pool_id,omitempty" yaml:"identity_pool_id,omitempty"`

	// jit
	Jit *JITSettings `json:"jit,omitempty" yaml:"jit,omitempty"`

	// Logo URI
	LogoURI string `json:"logo_uri,omitempty" yaml:"logo_uri,omitempty"`

	// mappings
	Mappings Mappings `json:"mappings,omitempty" yaml:"mappings,omitempty"`

	// Defines the type of an IDP
	//
	// Cloudentity is designed to make it possible for you to bring any of your own IDPs and integrate it
	// with Cloudentity as it delivers enterprise connectors for major Cloud IDPs and a possibility for
	// custom integration DKS for home-built solutions. You can also use built-in Sandbox IDP, which
	// is a static IDP, to create an IDP for testing purposes.
	Method string `json:"method,omitempty" yaml:"method,omitempty"`

	// Display name of your IDP
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Points to the ID of the custom app, null if not set
	PostAuthnAppID string `json:"post_authn_app_id,omitempty" yaml:"post_authn_app_id,omitempty"`

	// sso settings
	SsoSettings *IDPSSOSettings `json:"sso_settings,omitempty" yaml:"sso_settings,omitempty"`

	// Authentication method reference
	//
	// An array of case sensitive strings for authentication methods that are used in the user
	// authentication.
	//
	// For example, an IDP may require the user to provide a biometric authentication using facial
	// recognition. For that, the value of the authentication method reference is `face`.
	StaticAmr []string `json:"static_amr" yaml:"static_amr"`

	// ID of the tenant where an IDP is connected
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// token exchange settings
	TokenExchangeSettings *IDPTokenExchangeSettings `json:"token_exchange_settings,omitempty" yaml:"token_exchange_settings,omitempty"`

	// IDP version to track internal changes
	// version that is currently supported: 3
	Version int64 `json:"version,omitempty" yaml:"version,omitempty"`

	// ID of the Workspace to which the IDP is connected
	WorkspaceID string `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`
}

// Validate validates this github embedded ID p
func (m *GithubEmbeddedIDP) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConfig(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDiscoverySettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMappings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSsoSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenExchangeSettings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GithubEmbeddedIDP) validateAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.Attributes) { // not required
		return nil
	}

	if err := m.Attributes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attributes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("attributes")
		}
		return err
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateConfig(formats strfmt.Registry) error {
	if swag.IsZero(m.Config) { // not required
		return nil
	}

	if m.Config != nil {
		if err := m.Config.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("config")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateDiscoverySettings(formats strfmt.Registry) error {
	if swag.IsZero(m.DiscoverySettings) { // not required
		return nil
	}

	if m.DiscoverySettings != nil {
		if err := m.DiscoverySettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("discovery_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("discovery_settings")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateJit(formats strfmt.Registry) error {
	if swag.IsZero(m.Jit) { // not required
		return nil
	}

	if m.Jit != nil {
		if err := m.Jit.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jit")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateMappings(formats strfmt.Registry) error {
	if swag.IsZero(m.Mappings) { // not required
		return nil
	}

	if err := m.Mappings.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateSsoSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.SsoSettings) { // not required
		return nil
	}

	if m.SsoSettings != nil {
		if err := m.SsoSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sso_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sso_settings")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) validateTokenExchangeSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenExchangeSettings) { // not required
		return nil
	}

	if m.TokenExchangeSettings != nil {
		if err := m.TokenExchangeSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("token_exchange_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("token_exchange_settings")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this github embedded ID p based on the context it is used
func (m *GithubEmbeddedIDP) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateConfig(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDiscoverySettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMappings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSsoSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTokenExchangeSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GithubEmbeddedIDP) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Attributes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attributes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("attributes")
		}
		return err
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateConfig(ctx context.Context, formats strfmt.Registry) error {

	if m.Config != nil {

		if swag.IsZero(m.Config) { // not required
			return nil
		}

		if err := m.Config.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("config")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("config")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateDiscoverySettings(ctx context.Context, formats strfmt.Registry) error {

	if m.DiscoverySettings != nil {

		if swag.IsZero(m.DiscoverySettings) { // not required
			return nil
		}

		if err := m.DiscoverySettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("discovery_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("discovery_settings")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateJit(ctx context.Context, formats strfmt.Registry) error {

	if m.Jit != nil {

		if swag.IsZero(m.Jit) { // not required
			return nil
		}

		if err := m.Jit.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("jit")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateMappings(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Mappings.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateSsoSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.SsoSettings != nil {

		if swag.IsZero(m.SsoSettings) { // not required
			return nil
		}

		if err := m.SsoSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sso_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sso_settings")
			}
			return err
		}
	}

	return nil
}

func (m *GithubEmbeddedIDP) contextValidateTokenExchangeSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.TokenExchangeSettings != nil {

		if swag.IsZero(m.TokenExchangeSettings) { // not required
			return nil
		}

		if err := m.TokenExchangeSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("token_exchange_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("token_exchange_settings")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GithubEmbeddedIDP) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GithubEmbeddedIDP) UnmarshalBinary(b []byte) error {
	var res GithubEmbeddedIDP
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
