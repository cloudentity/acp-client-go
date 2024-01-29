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

// BrazilCustomerPatchPaymentConsentRequest brazil customer patch payment consent request
//
// swagger:model BrazilCustomerPatchPaymentConsentRequest
type BrazilCustomerPatchPaymentConsentRequest struct {

	// aud
	Aud string `json:"aud,omitempty" yaml:"aud,omitempty"`

	// data
	// Required: true
	Data *OpenbankingBrasilPaymentPatchPaymentsConsentData `json:"data" yaml:"data"`

	// iat
	Iat int64 `json:"iat,omitempty" yaml:"iat,omitempty"`

	// iss
	Iss string `json:"iss,omitempty" yaml:"iss,omitempty"`

	// jti
	Jti string `json:"jti,omitempty" yaml:"jti,omitempty"`
}

// Validate validates this brazil customer patch payment consent request
func (m *BrazilCustomerPatchPaymentConsentRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerPatchPaymentConsentRequest) validateData(formats strfmt.Registry) error {

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

// ContextValidate validate this brazil customer patch payment consent request based on the context it is used
func (m *BrazilCustomerPatchPaymentConsentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BrazilCustomerPatchPaymentConsentRequest) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

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
func (m *BrazilCustomerPatchPaymentConsentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BrazilCustomerPatchPaymentConsentRequest) UnmarshalBinary(b []byte) error {
	var res BrazilCustomerPatchPaymentConsentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
