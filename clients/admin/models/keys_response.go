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

// KeysResponse keys response
//
// swagger:model KeysResponse
type KeysResponse struct {

	// current key
	CurrentKey *ServerJWK `json:"current_key,omitempty" yaml:"current_key,omitempty"`

	// next key
	NextKey *ServerJWK `json:"next_key,omitempty" yaml:"next_key,omitempty"`

	// revoked keys
	RevokedKeys []*ServerJWK `json:"revoked_keys" yaml:"revoked_keys"`

	// rotated keys
	RotatedKeys []*ServerJWK `json:"rotated_keys" yaml:"rotated_keys"`
}

// Validate validates this keys response
func (m *KeysResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCurrentKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRotatedKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *KeysResponse) validateCurrentKey(formats strfmt.Registry) error {
	if swag.IsZero(m.CurrentKey) { // not required
		return nil
	}

	if m.CurrentKey != nil {
		if err := m.CurrentKey.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("current_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("current_key")
			}
			return err
		}
	}

	return nil
}

func (m *KeysResponse) validateNextKey(formats strfmt.Registry) error {
	if swag.IsZero(m.NextKey) { // not required
		return nil
	}

	if m.NextKey != nil {
		if err := m.NextKey.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_key")
			}
			return err
		}
	}

	return nil
}

func (m *KeysResponse) validateRevokedKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.RevokedKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.RevokedKeys); i++ {
		if swag.IsZero(m.RevokedKeys[i]) { // not required
			continue
		}

		if m.RevokedKeys[i] != nil {
			if err := m.RevokedKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *KeysResponse) validateRotatedKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.RotatedKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.RotatedKeys); i++ {
		if swag.IsZero(m.RotatedKeys[i]) { // not required
			continue
		}

		if m.RotatedKeys[i] != nil {
			if err := m.RotatedKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rotated_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rotated_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this keys response based on the context it is used
func (m *KeysResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCurrentKey(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNextKey(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevokedKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRotatedKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *KeysResponse) contextValidateCurrentKey(ctx context.Context, formats strfmt.Registry) error {

	if m.CurrentKey != nil {

		if swag.IsZero(m.CurrentKey) { // not required
			return nil
		}

		if err := m.CurrentKey.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("current_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("current_key")
			}
			return err
		}
	}

	return nil
}

func (m *KeysResponse) contextValidateNextKey(ctx context.Context, formats strfmt.Registry) error {

	if m.NextKey != nil {

		if swag.IsZero(m.NextKey) { // not required
			return nil
		}

		if err := m.NextKey.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("next_key")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("next_key")
			}
			return err
		}
	}

	return nil
}

func (m *KeysResponse) contextValidateRevokedKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RevokedKeys); i++ {

		if m.RevokedKeys[i] != nil {

			if swag.IsZero(m.RevokedKeys[i]) { // not required
				return nil
			}

			if err := m.RevokedKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("revoked_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("revoked_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *KeysResponse) contextValidateRotatedKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RotatedKeys); i++ {

		if m.RotatedKeys[i] != nil {

			if swag.IsZero(m.RotatedKeys[i]) { // not required
				return nil
			}

			if err := m.RotatedKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rotated_keys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rotated_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *KeysResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *KeysResponse) UnmarshalBinary(b []byte) error {
	var res KeysResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
