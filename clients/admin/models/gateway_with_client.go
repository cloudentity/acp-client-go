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

// GatewayWithClient gateway with client
//
// swagger:model GatewayWithClient
type GatewayWithClient struct {

	// authorization server id
	// Example: default
	AuthorizationServerID string `json:"authorization_server_id,omitempty" yaml:"authorization_server_id,omitempty"`

	// client
	Client *Client `json:"client,omitempty" yaml:"client,omitempty"`

	// id of a client created for this gateway for authentication
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// if true services are created automatically for each new discovered api group
	CreateAndBindServicesAutomatically bool `json:"create_and_bind_services_automatically,omitempty" yaml:"create_and_bind_services_automatically,omitempty"`

	// description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// unique gateway id
	// Example: 1
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// issuer url
	IssuerURL string `json:"issuer_url,omitempty" yaml:"issuer_url,omitempty"`

	// last time a client fetched configuration
	// Format: date-time
	LastActive strfmt.DateTime `json:"last_active,omitempty" yaml:"last_active,omitempty"`

	// gateway name
	// Example: Cloudentity Pyron
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// server url
	ServerURL string `json:"server_url,omitempty" yaml:"server_url,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// token exchange
	TokenExchange *GatewayTokenExchangeSettings `json:"token_exchange,omitempty" yaml:"token_exchange,omitempty"`

	// Token exchange client id
	TokenExchangeClientID string `json:"token_exchange_client_id,omitempty" yaml:"token_exchange_client_id,omitempty"`

	// gateway type, one of: pyron, aws
	// Example: pyron
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this gateway with client
func (m *GatewayWithClient) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClient(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastActive(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenExchange(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GatewayWithClient) validateClient(formats strfmt.Registry) error {
	if swag.IsZero(m.Client) { // not required
		return nil
	}

	if m.Client != nil {
		if err := m.Client.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client")
			}
			return err
		}
	}

	return nil
}

func (m *GatewayWithClient) validateLastActive(formats strfmt.Registry) error {
	if swag.IsZero(m.LastActive) { // not required
		return nil
	}

	if err := validate.FormatOf("last_active", "body", "date-time", m.LastActive.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *GatewayWithClient) validateTokenExchange(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenExchange) { // not required
		return nil
	}

	if m.TokenExchange != nil {
		if err := m.TokenExchange.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("token_exchange")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("token_exchange")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this gateway with client based on the context it is used
func (m *GatewayWithClient) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClient(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTokenExchange(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GatewayWithClient) contextValidateClient(ctx context.Context, formats strfmt.Registry) error {

	if m.Client != nil {

		if swag.IsZero(m.Client) { // not required
			return nil
		}

		if err := m.Client.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client")
			}
			return err
		}
	}

	return nil
}

func (m *GatewayWithClient) contextValidateTokenExchange(ctx context.Context, formats strfmt.Registry) error {

	if m.TokenExchange != nil {

		if swag.IsZero(m.TokenExchange) { // not required
			return nil
		}

		if err := m.TokenExchange.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("token_exchange")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("token_exchange")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GatewayWithClient) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GatewayWithClient) UnmarshalBinary(b []byte) error {
	var res GatewayWithClient
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
