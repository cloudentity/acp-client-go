// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBWriteInternationalConsent5DataInitiationCreditor OBWriteInternationalConsent5DataInitiationCreditor Party to which an amount of money is due.
//
// swagger:model OBWriteInternationalConsent5DataInitiationCreditor
type OBWriteInternationalConsent5DataInitiationCreditor struct {

	// Name by which a party is known and which is usually used to identify that party.
	// Max Length: 140
	// Min Length: 1
	Name string `json:"Name,omitempty" yaml:"Name,omitempty"`

	// postal address
	PostalAddress *OBPostalAddress6 `json:"PostalAddress,omitempty" yaml:"PostalAddress,omitempty"`
}

// Validate validates this o b write international consent5 data initiation creditor
func (m *OBWriteInternationalConsent5DataInitiationCreditor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePostalAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5DataInitiationCreditor) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := validate.MinLength("Name", "body", m.Name, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Name", "body", m.Name, 140); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiationCreditor) validatePostalAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.PostalAddress) { // not required
		return nil
	}

	if m.PostalAddress != nil {
		if err := m.PostalAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write international consent5 data initiation creditor based on the context it is used
func (m *OBWriteInternationalConsent5DataInitiationCreditor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePostalAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5DataInitiationCreditor) contextValidatePostalAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.PostalAddress != nil {

		if swag.IsZero(m.PostalAddress) { // not required
			return nil
		}

		if err := m.PostalAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalConsent5DataInitiationCreditor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalConsent5DataInitiationCreditor) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalConsent5DataInitiationCreditor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
