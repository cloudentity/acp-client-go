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

// OpenbankingBrasilPaymentV2Document OpenbankingBrasilPaymentV2Document Document
//
// swagger:model OpenbankingBrasilPaymentV2Document
type OpenbankingBrasilPaymentV2Document struct {

	// Nmero do documento de identificao oficial do titular pessoa jurdica.
	// Example: 11111111111111
	// Required: true
	// Max Length: 14
	// Pattern: ^\d{14}$
	Identification string `json:"identification" yaml:"identification"`

	// Tipo do documento de identificao oficial do titular pessoa jurdica.
	// Example: CNPJ
	// Required: true
	// Max Length: 4
	// Pattern: ^[A-Z]{4}$
	Rel string `json:"rel" yaml:"rel"`
}

// Validate validates this openbanking brasil payment v2 document
func (m *OpenbankingBrasilPaymentV2Document) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRel(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV2Document) validateIdentification(formats strfmt.Registry) error {

	if err := validate.RequiredString("identification", "body", m.Identification); err != nil {
		return err
	}

	if err := validate.MaxLength("identification", "body", m.Identification, 14); err != nil {
		return err
	}

	if err := validate.Pattern("identification", "body", m.Identification, `^\d{14}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV2Document) validateRel(formats strfmt.Registry) error {

	if err := validate.RequiredString("rel", "body", m.Rel); err != nil {
		return err
	}

	if err := validate.MaxLength("rel", "body", m.Rel, 4); err != nil {
		return err
	}

	if err := validate.Pattern("rel", "body", m.Rel, `^[A-Z]{4}$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this openbanking brasil payment v2 document based on context it is used
func (m *OpenbankingBrasilPaymentV2Document) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV2Document) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV2Document) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV2Document
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
