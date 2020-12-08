// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// GatewayWithClient gateway with client
//
// swagger:model GatewayWithClient
type GatewayWithClient struct {

	// id of a client created for this gateway for authentication
	ClientID string `json:"client_id,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// unique gateway id
	ID string `json:"id,omitempty"`

	// issuer URL
	IssuerURL string `json:"issuer_url,omitempty"`

	// last time a client fetched configuration
	// Format: date-time
	LastActive strfmt.DateTime `json:"last_active,omitempty"`

	// gateway name
	Name string `json:"name,omitempty"`

	// authorization server id
	ServerID string `json:"authorization_server_id,omitempty"`

	// server URL
	ServerURL string `json:"server_url,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// gateway type, one of: pyron, aws
	Type string `json:"type,omitempty"`

	// client
	Client *Client `json:"client,omitempty"`
}

// Validate validates this gateway with client
func (m *GatewayWithClient) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLastActive(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClient(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
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

func (m *GatewayWithClient) validateClient(formats strfmt.Registry) error {

	if swag.IsZero(m.Client) { // not required
		return nil
	}

	if m.Client != nil {
		if err := m.Client.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client")
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
