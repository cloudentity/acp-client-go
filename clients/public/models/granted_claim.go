// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GrantedClaim granted claim
//
// swagger:model GrantedClaim
type GrantedClaim struct {

	// claim name
	ClaimName string `json:"claim_name,omitempty" yaml:"claim_name,omitempty"`

	// id
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
}

// Validate validates this granted claim
func (m *GrantedClaim) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this granted claim based on context it is used
func (m *GrantedClaim) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GrantedClaim) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GrantedClaim) UnmarshalBinary(b []byte) error {
	var res GrantedClaim
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
