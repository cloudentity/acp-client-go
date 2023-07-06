// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Auth0Settings Auth0 IDP specific settings
//
// swagger:model Auth0Settings
type Auth0Settings struct {

	// OAuth client application identifier
	// Example: client
	ClientID string `json:"client_id,omitempty"`

	// String represented domain of the Auth0 for your organization
	// Example: dev-318ay013.us.auth0.com
	Domain string `json:"domain,omitempty"`

	// If enabled, users' data is collected by calling the `userinfo` endpoint.
	GetUserInfo bool `json:"get_user_info,omitempty"`

	// An array of additional scopes your client requests
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes"`

	// Whether to send the identifier as a `login_hint` parameter to the IDP
	SendLoginHint bool `json:"send_login_hint,omitempty"`
}

// Validate validates this auth0 settings
func (m *Auth0Settings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this auth0 settings based on context it is used
func (m *Auth0Settings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Auth0Settings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Auth0Settings) UnmarshalBinary(b []byte) error {
	var res Auth0Settings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
