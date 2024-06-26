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

// BrazilCustomerCreateRecurringPaymentConsentRequestV1 brazil customer create recurring payment consent request v1
//
// swagger:model BrazilCustomerCreateRecurringPaymentConsentRequestV1
type BrazilCustomerCreateRecurringPaymentConsentRequestV1 struct {

	// aud
	Aud string `json:"aud,omitempty" yaml:"aud,omitempty"`

	// data
	// Required: true
	Data *OpenbankingBrasilAutomaticPaymentV1Data `json:"data" yaml:"data"`

	// iat
	Iat int64 `json:"iat,omitempty" yaml:"iat,omitempty"`

	// iss
	Iss string `json:"iss,omitempty" yaml:"iss,omitempty"`

	// jti
	Jti string `json:"jti,omitempty" yaml:"jti,omitempty"`
}

// Validate validates this brazil customer create recurring payment consent request v1
func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) validateData(formats strfmt.Registry) error {

	if err := validate.Required("data", "body", m.Data); err != nil {
		return err
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this brazil customer create recurring payment consent request v1 based on the context it is used
func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {

		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BrazilCustomerCreateRecurringPaymentConsentRequestV1) UnmarshalBinary(b []byte) error {
	var res BrazilCustomerCreateRecurringPaymentConsentRequestV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
