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

// OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount The amount of the first Standing Order
//
// swagger:model OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount
type OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount struct {

	// amount
	// Required: true
	Amount *OBActiveCurrencyAndAmountSimpleType `json:"Amount"`

	// currency
	// Required: true
	Currency *ActiveOrHistoricCurrencyCode `json:"Currency"`
}

// Validate validates this o b write domestic standing order consent5 data initiation first payment amount
func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) validateAmount(formats strfmt.Registry) error {

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
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) validateCurrency(formats strfmt.Registry) error {

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
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write domestic standing order consent5 data initiation first payment amount based on the context it is used
func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) contextValidateAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.Amount != nil {
		if err := m.Amount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) contextValidateCurrency(ctx context.Context, formats strfmt.Registry) error {

	if m.Currency != nil {
		if err := m.Currency.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Currency")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticStandingOrderConsent5DataInitiationFirstPaymentAmount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
