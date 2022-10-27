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

// X509Certificate X509Certificate represents the XMLSEC object of the same name
//
// swagger:model X509Certificate
type X509Certificate struct {

	// data
	Data string `json:"Data,omitempty"`

	// XML name
	XMLName *Name `json:"XMLName,omitempty"`
}

// Validate validates this x509 certificate
func (m *X509Certificate) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateXMLName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *X509Certificate) validateXMLName(formats strfmt.Registry) error {
	if swag.IsZero(m.XMLName) { // not required
		return nil
	}

	if m.XMLName != nil {
		if err := m.XMLName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("XMLName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("XMLName")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this x509 certificate based on the context it is used
func (m *X509Certificate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateXMLName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *X509Certificate) contextValidateXMLName(ctx context.Context, formats strfmt.Registry) error {

	if m.XMLName != nil {
		if err := m.XMLName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("XMLName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("XMLName")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *X509Certificate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *X509Certificate) UnmarshalBinary(b []byte) error {
	var res X509Certificate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
