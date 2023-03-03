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

// OpenbankingBrasilPaymentV2LinkSingle OpenbankingBrasilPaymentV2LinkSingle LinkSingle
//
// Referncias para outros recusos da API requisitada.
//
// swagger:model OpenbankingBrasilPaymentV2LinkSingle
type OpenbankingBrasilPaymentV2LinkSingle struct {

	// URI completo que gerou a resposta atual.
	// Example: https://api.banco.com.br/open-banking/api/v1/resource
	// Required: true
	// Max Length: 2000
	// Pattern: ^(https:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)$
	Self string `json:"self"`
}

// Validate validates this openbanking brasil payment v2 link single
func (m *OpenbankingBrasilPaymentV2LinkSingle) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSelf(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV2LinkSingle) validateSelf(formats strfmt.Registry) error {

	if err := validate.RequiredString("self", "body", m.Self); err != nil {
		return err
	}

	if err := validate.MaxLength("self", "body", m.Self, 2000); err != nil {
		return err
	}

	if err := validate.Pattern("self", "body", m.Self, `^(https:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this openbanking brasil payment v2 link single based on context it is used
func (m *OpenbankingBrasilPaymentV2LinkSingle) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV2LinkSingle) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV2LinkSingle) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV2LinkSingle
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
