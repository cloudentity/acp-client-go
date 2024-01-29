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

// OPINBusinessEntity OPINBusinessEntity BusinessEntity
//
// Titular, pessoa jurdica a quem se referem os dados que so objeto de compartilhamento.
//
// swagger:model OPINBusinessEntity
type OPINBusinessEntity struct {

	// document
	// Required: true
	Document *OPINDocument1 `json:"document" yaml:"document"`
}

// Validate validates this o p i n business entity
func (m *OPINBusinessEntity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDocument(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OPINBusinessEntity) validateDocument(formats strfmt.Registry) error {

	if err := validate.Required("document", "body", m.Document); err != nil {
		return err
	}

	if m.Document != nil {
		if err := m.Document.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("document")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("document")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o p i n business entity based on the context it is used
func (m *OPINBusinessEntity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDocument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OPINBusinessEntity) contextValidateDocument(ctx context.Context, formats strfmt.Registry) error {

	if m.Document != nil {

		if err := m.Document.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("document")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("document")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OPINBusinessEntity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OPINBusinessEntity) UnmarshalBinary(b []byte) error {
	var res OPINBusinessEntity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
