// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Credential Credential contains all needed information about a WebAuthn credential for storage
//
// swagger:model Credential
type Credential struct {

	// The attestation format used (if any) by the authenticator when creating the credential.
	AttestationType string `json:"AttestationType,omitempty" yaml:"AttestationType,omitempty"`

	// authenticator
	Authenticator *Authenticator `json:"Authenticator,omitempty" yaml:"Authenticator,omitempty"`

	// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
	ID []uint8 `json:"ID" yaml:"ID"`

	// The public key portion of a Relying Party-specific credential key pair, generated by an authenticator and returned to
	// a Relying Party at registration time (see also public key credential). The private key portion of the credential key
	// pair is known as the credential private key. Note that in the case of self attestation, the credential key pair is also
	// used as the attestation key pair, see self attestation for details.
	PublicKey []uint8 `json:"PublicKey" yaml:"PublicKey"`
}

// Validate validates this credential
func (m *Credential) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticator(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Credential) validateAuthenticator(formats strfmt.Registry) error {
	if swag.IsZero(m.Authenticator) { // not required
		return nil
	}

	if m.Authenticator != nil {
		if err := m.Authenticator.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authenticator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authenticator")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this credential based on the context it is used
func (m *Credential) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticator(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Credential) contextValidateAuthenticator(ctx context.Context, formats strfmt.Registry) error {

	if m.Authenticator != nil {

		if swag.IsZero(m.Authenticator) { // not required
			return nil
		}

		if err := m.Authenticator.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authenticator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authenticator")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Credential) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Credential) UnmarshalBinary(b []byte) error {
	var res Credential
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
