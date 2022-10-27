// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MTLSEndpointAliases m TLS endpoint aliases
//
// swagger:model MTLSEndpointAliases
type MTLSEndpointAliases struct {

	// backchannel authentication endpoint
	BackchannelAuthenticationEndpoint string `json:"backchannel_authentication_endpoint,omitempty"`

	// introspection endpoint
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// pushed authorization request endpoint
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	// registration endpoint
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// revocation endpoint
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// token endpoint
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// userinfo endpoint
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
}

// Validate validates this m TLS endpoint aliases
func (m *MTLSEndpointAliases) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this m TLS endpoint aliases based on context it is used
func (m *MTLSEndpointAliases) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MTLSEndpointAliases) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MTLSEndpointAliases) UnmarshalBinary(b []byte) error {
	var res MTLSEndpointAliases
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
