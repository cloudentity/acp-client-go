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

// OBTransactionCashBalance Set of elements used to define the balance as a numerical representation of the net increases and decreases in an account after a transaction entry is applied to the account.
//
// swagger:model OBTransactionCashBalance
type OBTransactionCashBalance struct {

	// amount
	// Required: true
	Amount OBTransactionCashBalanceAmount `json:"Amount"`

	// credit debit indicator
	// Required: true
	CreditDebitIndicator *OBCreditDebitCode2 `json:"CreditDebitIndicator"`

	// type
	// Required: true
	Type *OBBalanceType1Code `json:"Type"`
}

// Validate validates this o b transaction cash balance
func (m *OBTransactionCashBalance) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditDebitIndicator(formats); err != nil {
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

func (m *OBTransactionCashBalance) validateAmount(formats strfmt.Registry) error {

	if err := m.Amount.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Amount")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Amount")
		}
		return err
	}

	return nil
}

func (m *OBTransactionCashBalance) validateCreditDebitIndicator(formats strfmt.Registry) error {

	if err := validate.Required("CreditDebitIndicator", "body", m.CreditDebitIndicator); err != nil {
		return err
	}

	if err := validate.Required("CreditDebitIndicator", "body", m.CreditDebitIndicator); err != nil {
		return err
	}

	if m.CreditDebitIndicator != nil {
		if err := m.CreditDebitIndicator.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditDebitIndicator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditDebitIndicator")
			}
			return err
		}
	}

	return nil
}

func (m *OBTransactionCashBalance) validateType(formats strfmt.Registry) error {

	if err := validate.Required("Type", "body", m.Type); err != nil {
		return err
	}

	if err := validate.Required("Type", "body", m.Type); err != nil {
		return err
	}

	if m.Type != nil {
		if err := m.Type.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Type")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b transaction cash balance based on the context it is used
func (m *OBTransactionCashBalance) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditDebitIndicator(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBTransactionCashBalance) contextValidateAmount(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Amount.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Amount")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Amount")
		}
		return err
	}

	return nil
}

func (m *OBTransactionCashBalance) contextValidateCreditDebitIndicator(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditDebitIndicator != nil {

		if err := m.CreditDebitIndicator.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditDebitIndicator")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditDebitIndicator")
			}
			return err
		}
	}

	return nil
}

func (m *OBTransactionCashBalance) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if m.Type != nil {

		if err := m.Type.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Type")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBTransactionCashBalance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBTransactionCashBalance) UnmarshalBinary(b []byte) error {
	var res OBTransactionCashBalance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBTransactionCashBalanceAmount Amount of money of the cash balance after a transaction entry is applied to the account..
//
// swagger:model OBTransactionCashBalanceAmount
type OBTransactionCashBalanceAmount struct {

	// amount
	// Required: true
	Amount *OBActiveCurrencyAndAmountSimpleType `json:"Amount"`

	// currency
	// Required: true
	Currency *ActiveOrHistoricCurrencyCode1 `json:"Currency"`
}

// Validate validates this o b transaction cash balance amount
func (m *OBTransactionCashBalanceAmount) Validate(formats strfmt.Registry) error {
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

func (m *OBTransactionCashBalanceAmount) validateAmount(formats strfmt.Registry) error {

	if err := validate.Required("Amount"+"."+"Amount", "body", m.Amount); err != nil {
		return err
	}

	if err := validate.Required("Amount"+"."+"Amount", "body", m.Amount); err != nil {
		return err
	}

	if m.Amount != nil {
		if err := m.Amount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount" + "." + "Amount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount" + "." + "Amount")
			}
			return err
		}
	}

	return nil
}

func (m *OBTransactionCashBalanceAmount) validateCurrency(formats strfmt.Registry) error {

	if err := validate.Required("Amount"+"."+"Currency", "body", m.Currency); err != nil {
		return err
	}

	if err := validate.Required("Amount"+"."+"Currency", "body", m.Currency); err != nil {
		return err
	}

	if m.Currency != nil {
		if err := m.Currency.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount" + "." + "Currency")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount" + "." + "Currency")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b transaction cash balance amount based on the context it is used
func (m *OBTransactionCashBalanceAmount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBTransactionCashBalanceAmount) contextValidateAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.Amount != nil {

		if err := m.Amount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount" + "." + "Amount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount" + "." + "Amount")
			}
			return err
		}
	}

	return nil
}

func (m *OBTransactionCashBalanceAmount) contextValidateCurrency(ctx context.Context, formats strfmt.Registry) error {

	if m.Currency != nil {

		if err := m.Currency.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Amount" + "." + "Currency")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Amount" + "." + "Currency")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBTransactionCashBalanceAmount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBTransactionCashBalanceAmount) UnmarshalBinary(b []byte) error {
	var res OBTransactionCashBalanceAmount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
