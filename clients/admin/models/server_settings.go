// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ServerSettings server settings
//
// swagger:model ServerSettings
type ServerSettings struct {

	// default client id
	DefaultClientID string `json:"default_client_id,omitempty" yaml:"default_client_id,omitempty"`

	// default post authn ctx script id
	DefaultPostAuthnCtxScriptID string `json:"default_post_authn_ctx_script_id,omitempty" yaml:"default_post_authn_ctx_script_id,omitempty"`
}

// Validate validates this server settings
func (m *ServerSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this server settings based on context it is used
func (m *ServerSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ServerSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServerSettings) UnmarshalBinary(b []byte) error {
	var res ServerSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
