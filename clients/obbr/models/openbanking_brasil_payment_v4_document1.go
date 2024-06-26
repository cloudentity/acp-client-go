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

// OpenbankingBrasilPaymentV4Document1 OpenbankingBrasilPaymentV4Document1 Document1
//
// swagger:model OpenbankingBrasilPaymentV4Document1
type OpenbankingBrasilPaymentV4Document1 struct {

	// Nmero do documento de identificao oficial do usurio.
	// Example: 11111111111
	// Required: true
	// Max Length: 11
	// Pattern: ^\d{11}$
	Identification string `json:"identification" yaml:"identification"`

	// Tipo do documento de identificao oficial do usurio.
	// Example: CPF
	// Required: true
	// Max Length: 3
	// Pattern: ^[A-Z]{3}$
	Rel string `json:"rel" yaml:"rel"`
}

// Validate validates this openbanking brasil payment v4 document1
func (m *OpenbankingBrasilPaymentV4Document1) Validate(formats strfmt.Registry) error {
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

func (m *OpenbankingBrasilPaymentV4Document1) validateIdentification(formats strfmt.Registry) error {

	if err := validate.RequiredString("identification", "body", m.Identification); err != nil {
		return err
	}

	if err := validate.MaxLength("identification", "body", m.Identification, 11); err != nil {
		return err
	}

	if err := validate.Pattern("identification", "body", m.Identification, `^\d{11}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Document1) validateRel(formats strfmt.Registry) error {

	if err := validate.RequiredString("rel", "body", m.Rel); err != nil {
		return err
	}

	if err := validate.MaxLength("rel", "body", m.Rel, 3); err != nil {
		return err
	}

	if err := validate.Pattern("rel", "body", m.Rel, `^[A-Z]{3}$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this openbanking brasil payment v4 document1 based on context it is used
func (m *OpenbankingBrasilPaymentV4Document1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4Document1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4Document1) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV4Document1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
