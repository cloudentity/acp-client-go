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

// X509Data X509Data represents the XMLSEC object of the same name
//
// swagger:model X509Data
type X509Data struct {

	// x509 certificates
	X509Certificates []*X509Certificate `json:"X509Certificates" yaml:"X509Certificates"`

	// XML name
	XMLName *Name `json:"XMLName,omitempty" yaml:"XMLName,omitempty"`
}

// Validate validates this x509 data
func (m *X509Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateX509Certificates(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateXMLName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *X509Data) validateX509Certificates(formats strfmt.Registry) error {
	if swag.IsZero(m.X509Certificates) { // not required
		return nil
	}

	for i := 0; i < len(m.X509Certificates); i++ {
		if swag.IsZero(m.X509Certificates[i]) { // not required
			continue
		}

		if m.X509Certificates[i] != nil {
			if err := m.X509Certificates[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("X509Certificates" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("X509Certificates" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *X509Data) validateXMLName(formats strfmt.Registry) error {
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

// ContextValidate validate this x509 data based on the context it is used
func (m *X509Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateX509Certificates(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateXMLName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *X509Data) contextValidateX509Certificates(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.X509Certificates); i++ {

		if m.X509Certificates[i] != nil {

			if swag.IsZero(m.X509Certificates[i]) { // not required
				return nil
			}

			if err := m.X509Certificates[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("X509Certificates" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("X509Certificates" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *X509Data) contextValidateXMLName(ctx context.Context, formats strfmt.Registry) error {

	if m.XMLName != nil {

		if swag.IsZero(m.XMLName) { // not required
			return nil
		}

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
func (m *X509Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *X509Data) UnmarshalBinary(b []byte) error {
	var res X509Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
