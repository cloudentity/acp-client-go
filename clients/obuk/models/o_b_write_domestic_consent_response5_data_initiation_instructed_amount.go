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

// OBWriteDomesticConsentResponse5DataInitiationInstructedAmount OBWriteDomesticConsentResponse5DataInitiationInstructedAmount Amount of money to be moved between the debtor and creditor, before deduction of charges, expressed in the currency as ordered by the initiating party.
//
// Usage: This amount has to be transported unchanged through the transaction chain.
//
// swagger:model OBWriteDomesticConsentResponse5DataInitiationInstructedAmount
type OBWriteDomesticConsentResponse5DataInitiationInstructedAmount struct {

	// amount
	// Required: true
	Amount *OBActiveCurrencyAndAmountSimpleType `json:"Amount" yaml:"Amount"`

	// currency
	// Required: true
	Currency *ActiveOrHistoricCurrencyCode `json:"Currency" yaml:"Currency"`
}

// Validate validates this o b write domestic consent response5 data initiation instructed amount
func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) validateAmount(formats strfmt.Registry) error {

	if err := validate.Required("Amount", "body", m.Amount); err != nil {
		return err
	}

	if err := validate.Required("Amount", "body", m.Amount); err != nil {
		return err
	}

	if m.Amount != nil {
		if err := m.Amount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) validateCurrency(formats strfmt.Registry) error {

	if err := validate.Required("Currency", "body", m.Currency); err != nil {
		return err
	}

	if err := validate.Required("Currency", "body", m.Currency); err != nil {
		return err
	}

	if m.Currency != nil {
		if err := m.Currency.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Currency")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Currency")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write domestic consent response5 data initiation instructed amount based on the context it is used
func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCurrency(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) contextValidateAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.Amount != nil {

		if err := m.Amount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) contextValidateCurrency(ctx context.Context, formats strfmt.Registry) error {

	if m.Currency != nil {

		if err := m.Currency.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Currency")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Currency")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticConsentResponse5DataInitiationInstructedAmount) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticConsentResponse5DataInitiationInstructedAmount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
