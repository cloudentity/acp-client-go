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

// OpenbankingBrasilAutomaticPaymentV1Meta OpenbankingBrasilAutomaticPaymentV1Meta Meta
//
// Meta informao referente a API requisitada.
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1Meta
type OpenbankingBrasilAutomaticPaymentV1Meta struct {

	// Data e hora da consulta, conforme especificao [RFC-3339](https://datatracker.ietf.org/doc/html/rfc3339), formato UTC.
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	RequestDateTime strfmt.DateTime `json:"requestDateTime" yaml:"requestDateTime"`
}

// Validate validates this openbanking brasil automatic payment v1 meta
func (m *OpenbankingBrasilAutomaticPaymentV1Meta) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRequestDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Meta) validateRequestDateTime(formats strfmt.Registry) error {

	if err := validate.Required("requestDateTime", "body", strfmt.DateTime(m.RequestDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("requestDateTime", "body", "date-time", m.RequestDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this openbanking brasil automatic payment v1 meta based on context it is used
func (m *OpenbankingBrasilAutomaticPaymentV1Meta) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1Meta) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1Meta) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilAutomaticPaymentV1Meta
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
