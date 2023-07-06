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

// OpenbankingBrasilPaymentLoggedUser OpenbankingBrasilPaymentLoggedUser LoggedUser
//
// Usurio (pessoa natural) que encontra-se logado na instituio Iniciadora de Pagamento.
// [Restrio] Deve obrigatoriamente ser enviado quando a revogao for feita pelo usurio final, ou seja, se o campo revokedBy estiver com o valor 'USER'.
//
// swagger:model OpenbankingBrasilPaymentLoggedUser
type OpenbankingBrasilPaymentLoggedUser struct {

	// document
	// Required: true
	Document *OpenbankingBrasilPaymentDocument1 `json:"document"`
}

// Validate validates this openbanking brasil payment logged user
func (m *OpenbankingBrasilPaymentLoggedUser) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDocument(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentLoggedUser) validateDocument(formats strfmt.Registry) error {

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

// ContextValidate validate this openbanking brasil payment logged user based on the context it is used
func (m *OpenbankingBrasilPaymentLoggedUser) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDocument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentLoggedUser) contextValidateDocument(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OpenbankingBrasilPaymentLoggedUser) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentLoggedUser) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentLoggedUser
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
