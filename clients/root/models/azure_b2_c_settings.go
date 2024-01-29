// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// AzureB2CSettings Azure AD B2C authentication settings
//
// swagger:model AzureB2CSettings
type AzureB2CSettings struct {

	// Application ID from your Microsoft Azure B2C application settings
	// Example: client
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// Custom domain from your Microsoft Azure application settings when using a custom
	// domain such as with Azure Front Door. This is optional.
	// Example: my.customdomain.com
	CustomDomain string `json:"custom_domain,omitempty" yaml:"custom_domain,omitempty"`

	// If enabled, the groups a user belongs to are collected
	//
	// Groups are collections of users and other principals who share access to resources in
	// Microsoft services or in your app. Microsoft Graph provides APIs that you can use to create
	// and manage different types of groups and group functionality according to your scenario.
	//
	// You can only get groups data if you are entitled to call the Microsoft Graph API.
	// Example: true
	FetchGroups bool `json:"fetch_groups,omitempty" yaml:"fetch_groups,omitempty"`

	// If enabled, users' data is collected from the Microsoft Graph API
	//
	// You can only get user's data if you are entitled to call the Microsoft Graph API.
	GetUser bool `json:"get_user,omitempty" yaml:"get_user,omitempty"`

	// An array of user attributes fetched from the Microsoft Graph API
	GraphUserAttributes []string `json:"graph_user_attributes" yaml:"graph_user_attributes"`

	// String represented group name format used for fetching groups
	//
	// It's value can be either `id` or `name`.
	// Example: id
	GroupNameFormat string `json:"group_name_format,omitempty" yaml:"group_name_format,omitempty"`

	// If enabled, only security groups a user belongs to are collected.
	// Example: true
	OnlySecurityGroups bool `json:"only_security_groups,omitempty" yaml:"only_security_groups,omitempty"`

	// The user flow to be run.
	// Specify the name of a user flow you've created in your Azure AD B2C tenant.
	// Example: b2c_1_sign_in
	Policy string `json:"policy,omitempty" yaml:"policy,omitempty"`

	// An array of additional scopes your client is going to request
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes" yaml:"scopes"`

	// Whether to send the identifier as a `login_hint` parameter to the IDP
	SendLoginHint bool `json:"send_login_hint,omitempty" yaml:"send_login_hint,omitempty"`

	// Directory ID from your Microsoft Azure B2C application settings
	// Example: 123-312-123
	Tenant string `json:"tenant,omitempty" yaml:"tenant,omitempty"`
}

// Validate validates this azure b2 c settings
func (m *AzureB2CSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this azure b2 c settings based on context it is used
func (m *AzureB2CSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AzureB2CSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AzureB2CSettings) UnmarshalBinary(b []byte) error {
	var res AzureB2CSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
