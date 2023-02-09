// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OIDCSettings OIDC IDP specific settings
//
// swagger:model OIDCSettings
type OIDCSettings struct {

	// Client authentication method
	// Enum: [client_secret private_key_jwt]
	AuthenticationMethod string `json:"authentication_method,omitempty"`

	// OAuth client application identifier
	// Example: client
	ClientID string `json:"client_id,omitempty"`

	// If enabled, users' data is collected by calling the `userinfo` endpoint.
	GetUserInfo bool `json:"get_user_info,omitempty"`

	// URL used to define the {baseURL} for any OpenID Connect endpoint when authorizing against ACP.
	IssuerURL string `json:"issuer_url,omitempty"`

	// An array of additional scopes your client requests
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes"`
}

// Validate validates this o ID c settings
func (m *OIDCSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oIdCSettingsTypeAuthenticationMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret","private_key_jwt"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oIdCSettingsTypeAuthenticationMethodPropEnum = append(oIdCSettingsTypeAuthenticationMethodPropEnum, v)
	}
}

const (

	// OIDCSettingsAuthenticationMethodClientSecret captures enum value "client_secret"
	OIDCSettingsAuthenticationMethodClientSecret string = "client_secret"

	// OIDCSettingsAuthenticationMethodPrivateKeyJwt captures enum value "private_key_jwt"
	OIDCSettingsAuthenticationMethodPrivateKeyJwt string = "private_key_jwt"
)

// prop value enum
func (m *OIDCSettings) validateAuthenticationMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oIdCSettingsTypeAuthenticationMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OIDCSettings) validateAuthenticationMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateAuthenticationMethodEnum("authentication_method", "body", m.AuthenticationMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o ID c settings based on context it is used
func (m *OIDCSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OIDCSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OIDCSettings) UnmarshalBinary(b []byte) error {
	var res OIDCSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
