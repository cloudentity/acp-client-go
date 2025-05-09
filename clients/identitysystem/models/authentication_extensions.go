// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// AuthenticationExtensions AuthenticationExtensions represents the AuthenticationExtensionsClientInputs IDL. This member contains additional
// parameters requesting additional processing by the client and authenticator.
//
// Specification: §5.7.1. Authentication Extensions Client Inputs (https://www.w3.org/TR/webauthn/#iface-authentication-extensions-client-inputs)
//
// swagger:model AuthenticationExtensions
type AuthenticationExtensions map[string]interface{}

// Validate validates this authentication extensions
func (m AuthenticationExtensions) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this authentication extensions based on context it is used
func (m AuthenticationExtensions) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
