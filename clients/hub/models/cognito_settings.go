// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CognitoSettings Cognito IDP specific settings
//
// swagger:model CognitoSettings
type CognitoSettings struct {

	// Cognito app client ID from your application settings
	// Example: client
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// If enabled, additional user data is collected from the `userinfo` Cognito API
	GetUserInfo bool `json:"get_user_info,omitempty" yaml:"get_user_info,omitempty"`

	// Cognito pool ID
	//
	// A user pool is a user directory in Amazon Cognito. It enables your users to sign in to your
	// application through Amazon Cognito. You can find your pool ID in your User Pools > Federated
	// Identities settings.
	PoolID string `json:"pool_id,omitempty" yaml:"pool_id,omitempty"`

	// AWS Region where the user pool is hosted
	// Example: us-east-1
	Region string `json:"region,omitempty" yaml:"region,omitempty"`

	// An array of allowed OAuth scopes which the client requests
	//
	// The following scopes can be allowed for a Cognito application:
	// `phone`, `email`, `openid`, `aws.cognito.signin.user.admin`, `profile`.
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes" yaml:"scopes"`

	// Whether to send the identifier as a `login_hint` parameter to the IDP
	SendLoginHint bool `json:"send_login_hint,omitempty" yaml:"send_login_hint,omitempty"`
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
