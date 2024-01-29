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

// OpenbankingBrasilPaymentMeta OpenbankingBrasilPaymentMeta Meta
//
// Meta informaes referente  API requisitada.
//
// swagger:model OpenbankingBrasilPaymentMeta
type OpenbankingBrasilPaymentMeta struct {

	// Data e hora da consulta, conforme especificao RFC-3339, formato UTC.
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	RequestDateTime strfmt.DateTime `json:"requestDateTime" yaml:"requestDateTime"`

	// Nmero total de pginas no resultado
	// Example: 1
	// Required: true
	TotalPages int32 `json:"totalPages" yaml:"totalPages"`

	// Nmero total de registros no resultado
	// Example: 1
	// Required: true
	TotalRecords int32 `json:"totalRecords" yaml:"totalRecords"`
}

// Validate validates this openbanking brasil payment meta
func (m *OpenbankingBrasilPaymentMeta) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRequestDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalPages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalRecords(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentMeta) validateRequestDateTime(formats strfmt.Registry) error {

	if err := validate.Required("requestDateTime", "body", strfmt.DateTime(m.RequestDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("requestDateTime", "body", "date-time", m.RequestDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentMeta) validateTotalPages(formats strfmt.Registry) error {

	if err := validate.Required("totalPages", "body", int32(m.TotalPages)); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentMeta) validateTotalRecords(formats strfmt.Registry) error {

	if err := validate.Required("totalRecords", "body", int32(m.TotalRecords)); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this openbanking brasil payment meta based on context it is used
func (m *OpenbankingBrasilPaymentMeta) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentMeta) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentMeta) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentMeta
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
