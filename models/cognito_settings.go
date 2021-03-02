// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CognitoSettings cognito settings
//
// swagger:model CognitoSettings
type CognitoSettings struct {

	// OAuth client identifier
	// Example: client
	ClientID string `json:"client_id,omitempty"`

	// flag to fetch additional user data from userinfo endpoint
	GetUserInfo bool `json:"get_user_info,omitempty"`

	// Cognito pool ID
	// Example: us-east-1_Q8WSOH11B
	PoolID string `json:"pool_id,omitempty"`

	// OAuth redirect URL
	// Example: https://example.com/callback
	RedirectURL string `json:"redirect_url,omitempty"`

	// AWS Region
	// Example: us-east-1
	Region string `json:"region,omitempty"`

	// OAuth scopes which client will be requesting
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes"`
}

// Validate validates this cognito settings
func (m *CognitoSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this cognito settings based on context it is used
func (m *CognitoSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CognitoSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CognitoSettings) UnmarshalBinary(b []byte) error {
	var res CognitoSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
