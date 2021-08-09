// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OpenbankingClient openbanking client
//
// swagger:model OpenbankingClient
type OpenbankingClient struct {

	// url to a client website
	// Example: https://example.com
	ClientURI string `json:"client_uri,omitempty"`

	// client id
	// Example: default
	ID string `json:"id,omitempty"`

	// url to a page where client logo is served
	// Example: https://example.com/logo.png
	LogoURI string `json:"logo_uri,omitempty"`

	// client name
	// Example: My app
	Name string `json:"name,omitempty"`
}

// Validate validates this openbanking client
func (m *OpenbankingClient) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking client based on context it is used
func (m *OpenbankingClient) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingClient) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingClient) UnmarshalBinary(b []byte) error {
	var res OpenbankingClient
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}