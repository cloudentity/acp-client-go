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

// ConsentService consent service
//
// swagger:model ConsentService
type ConsentService struct {

	// name
	Name string `json:"name,omitempty"`

	// purpose
	Purposes []*Purpose `json:"purposes"`
}

// Validate validates this consent service
func (m *ConsentService) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePurposes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentService) validatePurposes(formats strfmt.Registry) error {
	if swag.IsZero(m.Purposes) { // not required
		return nil
	}

	for i := 0; i < len(m.Purposes); i++ {
		if swag.IsZero(m.Purposes[i]) { // not required
			continue
		}

		if m.Purposes[i] != nil {
			if err := m.Purposes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("purposes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this consent service based on the context it is used
func (m *ConsentService) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePurposes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentService) contextValidatePurposes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Purposes); i++ {

		if m.Purposes[i] != nil {
			if err := m.Purposes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("purposes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConsentService) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentService) UnmarshalBinary(b []byte) error {
	var res ConsentService
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
