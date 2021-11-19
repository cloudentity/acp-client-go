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

// ServerJWKs server j w ks
//
// swagger:model ServerJWKs
type ServerJWKs struct {

	// keys
	// Example: []
	Keys []*ServerJWK `json:"keys"`

	// next encryption key
	NextEncryptionKey *ServerJWK `json:"next_encryption_key,omitempty"`

	// next signing key
	NextSigningKey *ServerJWK `json:"next_signing_key,omitempty"`

	// An array of revoked encryption keys
	//
	// Revoked encryption keys cannot be used to encrypt payloads between servers and client applications
	RevokedEncryptionKeys []*ServerJWK `json:"revoked_encryption_keys"`

	// The maximum number of revoked keys that ACP stores.
	RevokedKeysLimit int64 `json:"revoked_keys_limit,omitempty"`

	// An array of revoked sigining keys
	//
	// Revoked signing keys cannot be used to sign any tokens.
	// Any attempt to authenticate using a token signed with a revoked signing key results
	// in failed authentication.
	RevokedSigningKeys []*ServerJWK `json:"revoked_signing_keys"`

	// The maximum number of rotated keys that ACP stores.
	RotatedKeysLimit int64 `json:"rotated_keys_limit,omitempty"`
}

// Validate validates this server j w ks
func (m *ServerJWKs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextEncryptionKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextSigningKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedEncryptionKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedSigningKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServerJWKs) validateKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.Keys) { // not required
		return nil
	}

	for i := 0; i < len(m.Keys); i++ {
		if swag.IsZero(m.Keys[i]) { // not required
			continue
		}

		if m.Keys[i] != nil {
			if err := m.Keys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServerJWKs) validateNextEncryptionKey(formats strfmt.Registry) error {
	if swag.IsZero(m.NextEncryptionKey) { // not required
		return nil
	}

	if m.NextEncryptionKey != nil {
		if err := m.NextEncryptionKey.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_encryption_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_encryption_key")
			}
			return err
		}
	}

	return nil
}

func (m *ServerJWKs) validateNextSigningKey(formats strfmt.Registry) error {
	if swag.IsZero(m.NextSigningKey) { // not required
		return nil
	}

	if m.NextSigningKey != nil {
		if err := m.NextSigningKey.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_signing_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_signing_key")
			}
			return err
		}
	}

	return nil
}

func (m *ServerJWKs) validateRevokedEncryptionKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.RevokedEncryptionKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.RevokedEncryptionKeys); i++ {
		if swag.IsZero(m.RevokedEncryptionKeys[i]) { // not required
			continue
		}

		if m.RevokedEncryptionKeys[i] != nil {
			if err := m.RevokedEncryptionKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_encryption_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_encryption_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServerJWKs) validateRevokedSigningKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.RevokedSigningKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.RevokedSigningKeys); i++ {
		if swag.IsZero(m.RevokedSigningKeys[i]) { // not required
			continue
		}

		if m.RevokedSigningKeys[i] != nil {
			if err := m.RevokedSigningKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_signing_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_signing_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this server j w ks based on the context it is used
func (m *ServerJWKs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNextEncryptionKey(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNextSigningKey(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevokedEncryptionKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevokedSigningKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServerJWKs) contextValidateKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Keys); i++ {

		if m.Keys[i] != nil {
			if err := m.Keys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServerJWKs) contextValidateNextEncryptionKey(ctx context.Context, formats strfmt.Registry) error {

	if m.NextEncryptionKey != nil {
		if err := m.NextEncryptionKey.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_encryption_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_encryption_key")
			}
			return err
		}
	}

	return nil
}

func (m *ServerJWKs) contextValidateNextSigningKey(ctx context.Context, formats strfmt.Registry) error {

	if m.NextSigningKey != nil {
		if err := m.NextSigningKey.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_signing_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_signing_key")
			}
			return err
		}
	}

	return nil
}

func (m *ServerJWKs) contextValidateRevokedEncryptionKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RevokedEncryptionKeys); i++ {

		if m.RevokedEncryptionKeys[i] != nil {
			if err := m.RevokedEncryptionKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_encryption_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_encryption_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServerJWKs) contextValidateRevokedSigningKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RevokedSigningKeys); i++ {

		if m.RevokedSigningKeys[i] != nil {
			if err := m.RevokedSigningKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_signing_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_signing_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ServerJWKs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServerJWKs) UnmarshalBinary(b []byte) error {
	var res ServerJWKs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
