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

// OBBRConsents o b b r consents
//
// swagger:model OBBRConsents
type OBBRConsents struct {

	// consents
	Consents []*OBBRConsentWithClient `json:"Consents"`
}

// Validate validates this o b b r consents
func (m *OBBRConsents) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConsents(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBBRConsents) validateConsents(formats strfmt.Registry) error {
	if swag.IsZero(m.Consents) { // not required
		return nil
	}

	for i := 0; i < len(m.Consents); i++ {
		if swag.IsZero(m.Consents[i]) { // not required
			continue
		}

		if m.Consents[i] != nil {
			if err := m.Consents[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Consents" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Consents" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this o b b r consents based on the context it is used
func (m *OBBRConsents) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateConsents(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBBRConsents) contextValidateConsents(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Consents); i++ {

		if m.Consents[i] != nil {
			if err := m.Consents[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Consents" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Consents" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBBRConsents) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBBRConsents) UnmarshalBinary(b []byte) error {
	var res OBBRConsents
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
