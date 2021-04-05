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

// OBConsent o b consent
//
// swagger:model OBConsent
type OBConsent struct {

	// client ID
	ClientID string `json:"client_id,omitempty"`

	// consent ID
	ConsentID string `json:"consent_id,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// server ID
	ServerID string `json:"server_id,omitempty"`

	// tenant ID
	TenantID string `json:"tenant_id,omitempty"`

	// account access consent
	AccountAccessConsent *AccountAccessConsent `json:"account_access_consent,omitempty"`

	// domestic payment consent
	DomesticPaymentConsent *DomesticPaymentConsent `json:"domestic_payment_consent,omitempty"`

	// domestic scheduled payment consent
	DomesticScheduledPaymentConsent *DomesticScheduledPaymentConsent `json:"domestic_scheduled_payment_consent,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty"`
}

// Validate validates this o b consent
func (m *OBConsent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountAccessConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomesticPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomesticScheduledPaymentConsent(formats); err != nil {
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

func (m *OBConsent) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OBConsent) validateAccountAccessConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.AccountAccessConsent) { // not required
		return nil
	}

	if m.AccountAccessConsent != nil {
		if err := m.AccountAccessConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) validateDomesticPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomesticPaymentConsent) { // not required
		return nil
	}

	if m.DomesticPaymentConsent != nil {
		if err := m.DomesticPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) validateDomesticScheduledPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomesticScheduledPaymentConsent) { // not required
		return nil
	}

	if m.DomesticScheduledPaymentConsent != nil {
		if err := m.DomesticScheduledPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b consent based on the context it is used
func (m *OBConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountAccessConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDomesticPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDomesticScheduledPaymentConsent(ctx, formats); err != nil {
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

func (m *OBConsent) contextValidateAccountAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountAccessConsent != nil {
		if err := m.AccountAccessConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) contextValidateDomesticPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticPaymentConsent != nil {
		if err := m.DomesticPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) contextValidateDomesticScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticScheduledPaymentConsent != nil {
		if err := m.DomesticScheduledPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OBConsent) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Type.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBConsent) UnmarshalBinary(b []byte) error {
	var res OBConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
