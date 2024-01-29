// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ScopeGrantRejected scope grant rejected
//
// swagger:model ScopeGrantRejected
type ScopeGrantRejected struct {

	// A URL to redirect the user.
	// It applies for the redirect flow only, i.e the consent page.
	// Example: https://authorization.cloudentity.com:8443/tenant/server/oauth2/authorize?client_id=bugkgm23g9kregtu051g\u0026consent_verified=true\u0026login_id=cavai7d8s9nelp7k792g\u0026login_state=cauq8fonbud6q8806bf0
	RedirectTo string `json:"redirect_to,omitempty" yaml:"redirect_to,omitempty"`
}

// Validate validates this scope grant rejected
func (m *ScopeGrantRejected) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this scope grant rejected based on context it is used
func (m *ScopeGrantRejected) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ScopeGrantRejected) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScopeGrantRejected) UnmarshalBinary(b []byte) error {
	var res ScopeGrantRejected
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
