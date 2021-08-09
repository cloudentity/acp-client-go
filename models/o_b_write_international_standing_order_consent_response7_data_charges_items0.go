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

// OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0 OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0 Set of elements used to provide details of a charge for the payment initiation.
//
// swagger:model OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0
type OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0 struct {

	// amount
	// Required: true
	Amount *OBActiveOrHistoricCurrencyAndAmount `json:"Amount"`

	// charge bearer
	// Required: true
	ChargeBearer *OBChargeBearerType1Code `json:"ChargeBearer"`

	// type
	// Required: true
	Type *OBExternalPaymentChargeType1Code `json:"Type"`
}

// Validate validates this o b write international standing order consent response7 data charges items0
func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateChargeBearer(formats); err != nil {
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

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) validateAmount(formats strfmt.Registry) error {

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

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) validateChargeBearer(formats strfmt.Registry) error {

	if err := validate.Required("ChargeBearer", "body", m.ChargeBearer); err != nil {
		return err
	}

	if err := validate.Required("ChargeBearer", "body", m.ChargeBearer); err != nil {
		return err
	}

	if m.ChargeBearer != nil {
		if err := m.ChargeBearer.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ChargeBearer")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) validateType(formats strfmt.Registry) error {

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
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write international standing order consent response7 data charges items0 based on the context it is used
func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateChargeBearer(ctx, formats); err != nil {
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

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) contextValidateAmount(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) contextValidateChargeBearer(ctx context.Context, formats strfmt.Registry) error {

	if m.ChargeBearer != nil {
		if err := m.ChargeBearer.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ChargeBearer")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if m.Type != nil {
		if err := m.Type.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Type")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}