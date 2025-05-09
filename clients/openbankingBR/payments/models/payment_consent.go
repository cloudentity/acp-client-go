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

// PaymentConsent PaymentConsent
//
// Objeto contendo dados de pagamento para consentimento.
//
// swagger:model PaymentConsent
type PaymentConsent struct {

	// Valor da transao com 2 casas decimais.
	// Example: 100000.12
	// Required: true
	// Max Length: 19
	// Min Length: 4
	// Pattern: ^((\d{1,16}\.\d{2}))$
	Amount string `json:"amount"`

	// Cdigo da moeda nacional segundo modelo ISO-4217, ou seja, 'BRL'.
	// Todos os valores monetrios informados esto representados com a moeda vigente do Brasil.
	// Example: BRL
	// Required: true
	// Max Length: 3
	// Pattern: ^([A-Z]{3})$
	Currency string `json:"currency"`

	// Data do pagamento, conforme especificao RFC-3339.
	// Example: 2021-01-01
	// Required: true
	// Format: date
	Date strfmt.Date `json:"date"`

	// details
	// Required: true
	Details *Details `json:"details"`

	// Traz o cdigo da cidade segundo o IBGE (Instituto Brasileiro de Geografia e Estatstica).
	// Para o preenchimento deste campo, o Iniciador de Pagamentos deve seguir a orientao do arranjo da forma de pagamento.
	// O preenchimento do campo tanto em pix/payments quanto /consents deve ser igual. Caso haja divergncia dos valores, a instituio deve retornar HTTP 422 com o cdigo de erro PAGAMENTO_DIVERGENTE_DO_CONSENTIMENTO.
	// Este campo faz referncia ao campo CodMun do arranjo Pix.
	// Example: 5300108
	// Max Length: 7
	// Min Length: 7
	// Pattern: ^\d{7}$
	IbgeTownCode string `json:"ibgeTownCode,omitempty"`

	// Este campo define o tipo de pagamento que ser iniciado aps a autorizao do consentimento.
	// Example: PIX
	// Required: true
	Type string `json:"type"`
}

// Validate validates this payment consent
func (m *PaymentConsent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurrency(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetails(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIbgeTownCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaymentConsent) validateAmount(formats strfmt.Registry) error {

	if err := validate.RequiredString("amount", "body", m.Amount); err != nil {
		return err
	}

	if err := validate.MinLength("amount", "body", m.Amount, 4); err != nil {
		return err
	}

	if err := validate.MaxLength("amount", "body", m.Amount, 19); err != nil {
		return err
	}

	if err := validate.Pattern("amount", "body", m.Amount, `^((\d{1,16}\.\d{2}))$`); err != nil {
		return err
	}

	return nil
}

func (m *PaymentConsent) validateCurrency(formats strfmt.Registry) error {

	if err := validate.RequiredString("currency", "body", m.Currency); err != nil {
		return err
	}

	if err := validate.MaxLength("currency", "body", m.Currency, 3); err != nil {
		return err
	}

	if err := validate.Pattern("currency", "body", m.Currency, `^([A-Z]{3})$`); err != nil {
		return err
	}

	return nil
}

func (m *PaymentConsent) validateDate(formats strfmt.Registry) error {

	if err := validate.Required("date", "body", strfmt.Date(m.Date)); err != nil {
		return err
	}

	if err := validate.FormatOf("date", "body", "date", m.Date.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PaymentConsent) validateDetails(formats strfmt.Registry) error {

	if err := validate.Required("details", "body", m.Details); err != nil {
		return err
	}

	if m.Details != nil {
		if err := m.Details.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("details")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("details")
			}
			return err
		}
	}

	return nil
}

func (m *PaymentConsent) validateIbgeTownCode(formats strfmt.Registry) error {
	if swag.IsZero(m.IbgeTownCode) { // not required
		return nil
	}

	if err := validate.MinLength("ibgeTownCode", "body", m.IbgeTownCode, 7); err != nil {
		return err
	}

	if err := validate.MaxLength("ibgeTownCode", "body", m.IbgeTownCode, 7); err != nil {
		return err
	}

	if err := validate.Pattern("ibgeTownCode", "body", m.IbgeTownCode, `^\d{7}$`); err != nil {
		return err
	}

	return nil
}

func (m *PaymentConsent) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this payment consent based on the context it is used
func (m *PaymentConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaymentConsent) contextValidateDetails(ctx context.Context, formats strfmt.Registry) error {

	if m.Details != nil {

		if err := m.Details.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("details")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("details")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PaymentConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaymentConsent) UnmarshalBinary(b []byte) error {
	var res PaymentConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
