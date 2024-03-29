// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ClientTokenExchangeConfiguration client token exchange configuration
//
// swagger:model ClientTokenExchangeConfiguration
type ClientTokenExchangeConfiguration struct {

	// Additional actor token claims
	//
	// Claims from the actor token that will be injected into the exchanged token under the `act` claim.
	//
	// Applies for the token exchange delegation flow only.
	ActorClaims []string `json:"actor_claims" yaml:"actor_claims"`
}

// Validate validates this client token exchange configuration
func (m *ClientTokenExchangeConfiguration) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this client token exchange configuration based on context it is used
func (m *ClientTokenExchangeConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ClientTokenExchangeConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClientTokenExchangeConfiguration) UnmarshalBinary(b []byte) error {
	var res ClientTokenExchangeConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
