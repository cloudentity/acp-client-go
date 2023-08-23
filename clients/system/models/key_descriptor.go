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

// KeyDescriptor KeyDescriptor represents the XMLSEC object of the same name
//
// swagger:model KeyDescriptor
type KeyDescriptor struct {

	// encryption methods
	EncryptionMethods []*EncryptionMethod `json:"EncryptionMethods"`

	// key info
	KeyInfo *KeyInfo `json:"KeyInfo,omitempty"`

	// use
	Use string `json:"Use,omitempty"`
}

// Validate validates this key descriptor
func (m *KeyDescriptor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEncryptionMethods(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeyInfo(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *KeyDescriptor) validateEncryptionMethods(formats strfmt.Registry) error {
	if swag.IsZero(m.EncryptionMethods) { // not required
		return nil
	}

	for i := 0; i < len(m.EncryptionMethods); i++ {
		if swag.IsZero(m.EncryptionMethods[i]) { // not required
			continue
		}

		if m.EncryptionMethods[i] != nil {
			if err := m.EncryptionMethods[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EncryptionMethods" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EncryptionMethods" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *KeyDescriptor) validateKeyInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.KeyInfo) { // not required
		return nil
	}

	if m.KeyInfo != nil {
		if err := m.KeyInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeyInfo")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeyInfo")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this key descriptor based on the context it is used
func (m *KeyDescriptor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEncryptionMethods(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateKeyInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *KeyDescriptor) contextValidateEncryptionMethods(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.EncryptionMethods); i++ {

		if m.EncryptionMethods[i] != nil {
			if err := m.EncryptionMethods[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EncryptionMethods" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EncryptionMethods" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *KeyDescriptor) contextValidateKeyInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.KeyInfo != nil {
		if err := m.KeyInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("KeyInfo")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("KeyInfo")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *KeyDescriptor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *KeyDescriptor) UnmarshalBinary(b []byte) error {
	var res KeyDescriptor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}