// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Credential Credential contains all needed information about a WebAuthn credential for storage. This struct is effectively the
// Credential Record as described in the specification.
//
// See: §4. Terminology: Credential Record (https://www.w3.org/TR/webauthn-3/#credential-record)
//
// swagger:model Credential
type Credential struct {

	// attestation
	Attestation *CredentialAttestation `json:"attestation,omitempty" yaml:"attestation,omitempty"`

	// The attestation format used (if any) by the authenticator when creating the credential.
	AttestationType string `json:"attestationType,omitempty" yaml:"attestationType,omitempty"`

	// authenticator
	Authenticator *Authenticator `json:"authenticator,omitempty" yaml:"authenticator,omitempty"`

	// flags
	Flags *CredentialFlags `json:"flags,omitempty" yaml:"flags,omitempty"`

	// The Credential ID of the public key credential source. Described by the Credential Record 'id' field.
	ID []uint8 `json:"id" yaml:"id"`

	// The credential public key of the public key credential source. Described by the Credential Record 'publicKey field.
	PublicKey []uint8 `json:"publicKey" yaml:"publicKey"`

	// The transport types the authenticator supports.
	Transport []AuthenticatorTransport `json:"transport" yaml:"transport"`
}

// Validate validates this credential
func (m *Credential) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttestation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticator(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFlags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransport(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Credential) validateAttestation(formats strfmt.Registry) error {
	if swag.IsZero(m.Attestation) { // not required
		return nil
	}

	if m.Attestation != nil {
		if err := m.Attestation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attestation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attestation")
			}
			return err
		}
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
				return ve.ValidateName("authenticator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authenticator")
			}
			return err
		}
	}

	return nil
}

func (m *Credential) validateFlags(formats strfmt.Registry) error {
	if swag.IsZero(m.Flags) { // not required
		return nil
	}

	if m.Flags != nil {
		if err := m.Flags.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("flags")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("flags")
			}
			return err
		}
	}

	return nil
}

func (m *Credential) validateTransport(formats strfmt.Registry) error {
	if swag.IsZero(m.Transport) { // not required
		return nil
	}

	for i := 0; i < len(m.Transport); i++ {

		if err := m.Transport[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transport" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transport" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// ContextValidate validate this credential based on the context it is used
func (m *Credential) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttestation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAuthenticator(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFlags(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTransport(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Credential) contextValidateAttestation(ctx context.Context, formats strfmt.Registry) error {

	if m.Attestation != nil {

		if swag.IsZero(m.Attestation) { // not required
			return nil
		}

		if err := m.Attestation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attestation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attestation")
			}
			return err
		}
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
				return ve.ValidateName("authenticator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authenticator")
			}
			return err
		}
	}

	return nil
}

func (m *Credential) contextValidateFlags(ctx context.Context, formats strfmt.Registry) error {

	if m.Flags != nil {

		if swag.IsZero(m.Flags) { // not required
			return nil
		}

		if err := m.Flags.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("flags")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("flags")
			}
			return err
		}
	}

	return nil
}

func (m *Credential) contextValidateTransport(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Transport); i++ {

		if swag.IsZero(m.Transport[i]) { // not required
			return nil
		}

		if err := m.Transport[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transport" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transport" + "." + strconv.Itoa(i))
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
