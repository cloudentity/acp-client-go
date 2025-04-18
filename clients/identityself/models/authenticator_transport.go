// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// AuthenticatorTransport AuthenticatorTransport represents the IDL enum with the same name.
//
// Authenticators may implement various transports for communicating with clients. This enumeration defines hints as to
// how clients might communicate with a particular authenticator in order to obtain an assertion for a specific
// credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may
// be reached. A Relying Party will typically learn of the supported transports for a public key credential via
// getTransports().
//
// Specification: §5.8.4. Authenticator Transport Enumeration (https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport)
//
// swagger:model AuthenticatorTransport
type AuthenticatorTransport string

// Validate validates this authenticator transport
func (m AuthenticatorTransport) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this authenticator transport based on context it is used
func (m AuthenticatorTransport) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
