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

// DomesticPaymentConsentInstructedAmount DomesticPaymentConsentInstructedAmount Amount of money to be moved between the debtor and creditor, before deduction of charges, expressed in the currency as ordered by the initiating party.
//
// Usage: This amount has to be transported unchanged through the transaction chain.
//
// swagger:model DomesticPaymentConsentInstructedAmount
type DomesticPaymentConsentInstructedAmount struct {

	// amount
	// Required: true
	Amount *string `json:"Amount"`

	// currency
	// Required: true
	// Pattern: ^[A-Z]{3,3}$
	Currency *string `json:"Currency"`
}

// Validate validates this domestic payment consent instructed amount
func (m *DomesticPaymentConsentInstructedAmount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurrency(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticPaymentConsentInstructedAmount) validateAmount(formats strfmt.Registry) error {

	if err := validate.Required("Amount", "body", m.Amount); err != nil {
		return err
	}

	return nil
}

func (m *DomesticPaymentConsentInstructedAmount) validateCurrency(formats strfmt.Registry) error {

	if err := validate.Required("Currency", "body", m.Currency); err != nil {
		return err
	}

	if err := validate.Pattern("Currency", "body", *m.Currency, `^[A-Z]{3,3}$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domestic payment consent instructed amount based on context it is used
func (m *DomesticPaymentConsentInstructedAmount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomesticPaymentConsentInstructedAmount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomesticPaymentConsentInstructedAmount) UnmarshalBinary(b []byte) error {
	var res DomesticPaymentConsentInstructedAmount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
