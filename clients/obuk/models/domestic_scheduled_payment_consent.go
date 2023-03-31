// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomesticScheduledPaymentConsent domestic scheduled payment consent
//
// swagger:model DomesticScheduledPaymentConsent
type DomesticScheduledPaymentConsent struct {
	OBWriteDomesticScheduledConsentResponse5Data

	OBRisk1
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *DomesticScheduledPaymentConsent) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 OBWriteDomesticScheduledConsentResponse5Data
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.OBWriteDomesticScheduledConsentResponse5Data = aO0

	// AO1
	var aO1 OBRisk1
	if err := swag.ReadJSON(raw, &aO1); err != nil {
		return err
	}
	m.OBRisk1 = aO1

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m DomesticScheduledPaymentConsent) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.OBWriteDomesticScheduledConsentResponse5Data)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)

	aO1, err := swag.WriteJSON(m.OBRisk1)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this domestic scheduled payment consent
func (m *DomesticScheduledPaymentConsent) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with OBWriteDomesticScheduledConsentResponse5Data
	if err := m.OBWriteDomesticScheduledConsentResponse5Data.Validate(formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with OBRisk1
	if err := m.OBRisk1.Validate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validate this domestic scheduled payment consent based on the context it is used
func (m *DomesticScheduledPaymentConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with OBWriteDomesticScheduledConsentResponse5Data
	if err := m.OBWriteDomesticScheduledConsentResponse5Data.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with OBRisk1
	if err := m.OBRisk1.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *DomesticScheduledPaymentConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomesticScheduledPaymentConsent) UnmarshalBinary(b []byte) error {
	var res DomesticScheduledPaymentConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
