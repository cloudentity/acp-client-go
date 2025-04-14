// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// IDPConfiguration ID p configuration
//
// swagger:model IDPConfiguration
type IDPConfiguration struct {

	// If set to `true`, the claims are reloaded while issuing an access token.
	//
	// Currently it is only available for Identity Pool IDP.
	ReloadClaimsAtRefreshToken bool `json:"reload_claims_at_refresh_token,omitempty" yaml:"reload_claims_at_refresh_token,omitempty"`

	// Indicates whether the embedded configuration, which functions out of the box, should be used
	//
	// This may only apply to specific IDPs, such as LinkedIn.
	UseEmbedded bool `json:"use_embedded,omitempty" yaml:"use_embedded,omitempty"`
}

// Validate validates this ID p configuration
func (m *IDPConfiguration) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this ID p configuration based on context it is used
func (m *IDPConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IDPConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IDPConfiguration) UnmarshalBinary(b []byte) error {
	var res IDPConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
