// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OIDCSettings o ID c settings
//
// swagger:model OIDCSettings
type OIDCSettings struct {

	// OAuth client identifier
	// Example: client
	ClientID string `json:"client_id,omitempty"`

	// flag to fetch additional user attributes from userinfo endpoint
	GetUserInfo bool `json:"get_user_info,omitempty"`

	// Authorization server issuer URL
	IssuerURL string `json:"issuer_url,omitempty"`

	// OAuth scopes which client will be requesting
	// Example: ["email","profile","openid"]
	Scopes []string `json:"scopes"`
}

// Validate validates this o ID c settings
func (m *OIDCSettings) Validate(formats strfmt.Registry) error {
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
