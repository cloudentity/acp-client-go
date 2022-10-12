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

// CognitoIDP cognito ID p
//
// swagger:model CognitoIDP
type CognitoIDP struct {

	// attributes
	Attributes Attributes `json:"attributes,omitempty"`

	// ID of the authorization server (workspace) to which the IDP is connected
	AuthorizationServerID string `json:"authorization_server_id,omitempty"`

	// Client application ID
	//
	// It serves as a reference to a client application that is created in the System authorization
	// server (workspace), when a custom login page is created.
	ClientID string `json:"client_id,omitempty"`

	// config
	Config *IDPConfiguration `json:"config,omitempty"`

	// credentials
	Credentials *CognitoCredentials `json:"credentials,omitempty"`

	// If set to `true`, the IDP is disabled
	//
	// When an IDP is disabled, it is not available for the users to be used. It is also not
	// displayed on the login page.
	Disabled bool `json:"disabled,omitempty"`

	// discovery settings
	DiscoverySettings *IDPDiscoverySettings `json:"discovery_settings,omitempty"`

	// If set to `true`, the IDP is not displayed on the login page.
	//
	// When an IDP is hidden, it will not be displayed on the login page. It can still be used
	// and script extensions can enabled it.
	Hidden bool `json:"hidden,omitempty"`

	// Unique ID of your identity provider
	//
	// If not provided, a random ID is generated.
	ID string `json:"id,omitempty"`

	// ID of the Identity Pool to which the IDP is connected
	IdentityPoolID string `json:"identity_pool_id,omitempty"`

	// mappings
	Mappings Mappings `json:"mappings,omitempty"`

	// Defines the type of an IDP
	//
	// ACP is designed to make it possible for you to bring any of your own IDPs and integrate it
	// with ACP as it delivers enterprise connectors for major Cloud IDPs and a possibility for
	// custom integration DKS for home-built solutions. You can also use built-in Sandbox IDP, which
	// is a static IDP, to create an IDP for testing purposes.
	Method string `json:"method,omitempty"`

	// Display name of your IDP
	Name string `json:"name,omitempty"`

	// settings
	Settings *CognitoSettings `json:"settings,omitempty"`

	// Authentication method reference
	//
	// An array of case sensitive strings for authentication methods that are used in the user
	// authentication.
	//
	// For example, an IDP may require the user to provide a biometric authentication using facial
	// recognition. For that, the value of the authentication method reference is `face`.
	StaticAmr []string `json:"static_amr"`

	// ID of the tenant where an IDP is connected
	TenantID string `json:"tenant_id,omitempty"`

	// token exchange settings
	TokenExchangeSettings *IDPTokenExchangeSettings `json:"token_exchange_settings,omitempty"`

	// transformer
	Transformer *ScriptTransformer `json:"transformer,omitempty"`
}

// Validate validates this cognito ID p
func (m *CognitoIDP) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConfig(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCredentials(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDiscoverySettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMappings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenExchangeSettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransformer(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CognitoIDP) validateAttributes(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateConfig(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateCredentials(formats strfmt.Registry) error {
	if swag.IsZero(m.Credentials) { // not required
		return nil
	}

	if m.Credentials != nil {
		if err := m.Credentials.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("credentials")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("credentials")
			}
			return err
		}
	}

	return nil
}

func (m *CognitoIDP) validateDiscoverySettings(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateMappings(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateSettings(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateTokenExchangeSettings(formats strfmt.Registry) error {
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

func (m *CognitoIDP) validateTransformer(formats strfmt.Registry) error {
	if swag.IsZero(m.Transformer) { // not required
		return nil
	}

	if m.Transformer != nil {
		if err := m.Transformer.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transformer")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transformer")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cognito ID p based on the context it is used
func (m *CognitoIDP) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateConfig(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDiscoverySettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMappings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTokenExchangeSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTransformer(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CognitoIDP) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

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

func (m *CognitoIDP) contextValidateConfig(ctx context.Context, formats strfmt.Registry) error {

	if m.Config != nil {
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

func (m *CognitoIDP) contextValidateCredentials(ctx context.Context, formats strfmt.Registry) error {

	if m.Credentials != nil {
		if err := m.Credentials.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("credentials")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("credentials")
			}
			return err
		}
	}

	return nil
}

func (m *CognitoIDP) contextValidateDiscoverySettings(ctx context.Context, formats strfmt.Registry) error {

	if m.DiscoverySettings != nil {
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

func (m *CognitoIDP) contextValidateMappings(ctx context.Context, formats strfmt.Registry) error {

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

func (m *CognitoIDP) contextValidateSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.Settings != nil {
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

func (m *CognitoIDP) contextValidateTokenExchangeSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.TokenExchangeSettings != nil {
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

func (m *CognitoIDP) contextValidateTransformer(ctx context.Context, formats strfmt.Registry) error {

	if m.Transformer != nil {
		if err := m.Transformer.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transformer")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transformer")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CognitoIDP) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CognitoIDP) UnmarshalBinary(b []byte) error {
	var res CognitoIDP
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
