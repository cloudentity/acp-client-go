// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// IdentityPoolRoles identity pool roles
//
// swagger:model IdentityPoolRoles
type IdentityPoolRoles struct {

	// user manager
	UserManager bool `json:"user_manager,omitempty" yaml:"user_manager,omitempty"`
}

// Validate validates this identity pool roles
func (m *IdentityPoolRoles) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this identity pool roles based on context it is used
func (m *IdentityPoolRoles) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IdentityPoolRoles) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityPoolRoles) UnmarshalBinary(b []byte) error {
	var res IdentityPoolRoles
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
