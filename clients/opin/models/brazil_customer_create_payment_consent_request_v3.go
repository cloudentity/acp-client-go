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

// BrazilCustomerCreatePaymentConsentRequestV3 brazil customer create payment consent request v3
//
// swagger:model BrazilCustomerCreatePaymentConsentRequestV3
type BrazilCustomerCreatePaymentConsentRequestV3 struct {

	// aud
	Aud string `json:"aud,omitempty" yaml:"aud,omitempty"`

	// data
	// Required: true
	Data *OpenbankingBrasilPaymentV3Data `json:"data" yaml:"data"`

	// iat
	Iat int64 `json:"iat,omitempty" yaml:"iat,omitempty"`

	// iss
	Iss string `json:"iss,omitempty" yaml:"iss,omitempty"`

	// jti
	Jti string `json:"jti,omitempty" yaml:"jti,omitempty"`
}

// Validate validates this brazil customer create payment consent request v3
func (m *BrazilCustomerCreatePaymentConsentRequestV3) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerCreatePaymentConsentRequestV3) validateData(formats strfmt.Registry) error {

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

// ContextValidate validate this brazil customer create payment consent request v3 based on the context it is used
func (m *BrazilCustomerCreatePaymentConsentRequestV3) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerCreatePaymentConsentRequestV3) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

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
func (m *BrazilCustomerCreatePaymentConsentRequestV3) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BrazilCustomerCreatePaymentConsentRequestV3) UnmarshalBinary(b []byte) error {
	var res BrazilCustomerCreatePaymentConsentRequestV3
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
