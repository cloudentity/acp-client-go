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

// DomesticStandingOrderConsentRequest domestic standing order consent request
//
// swagger:model DomesticStandingOrderConsentRequest
type DomesticStandingOrderConsentRequest struct {

	// data
	// Required: true
	Data *OBWriteDomesticStandingOrderConsent5Data `json:"Data"`

	// risk
	// Required: true
	Risk *OBRisk1 `json:"Risk"`
}

// Validate validates this domestic standing order consent request
func (m *DomesticStandingOrderConsentRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRisk(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticStandingOrderConsentRequest) validateData(formats strfmt.Registry) error {

	if err := validate.Required("Data", "body", m.Data); err != nil {
		return err
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticStandingOrderConsentRequest) validateRisk(formats strfmt.Registry) error {

	if err := validate.Required("Risk", "body", m.Risk); err != nil {
		return err
	}

	if m.Risk != nil {
		if err := m.Risk.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Risk")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Risk")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domestic standing order consent request based on the context it is used
func (m *DomesticStandingOrderConsentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRisk(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticStandingOrderConsentRequest) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {
		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticStandingOrderConsentRequest) contextValidateRisk(ctx context.Context, formats strfmt.Registry) error {

	if m.Risk != nil {
		if err := m.Risk.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Risk")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Risk")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomesticStandingOrderConsentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomesticStandingOrderConsentRequest) UnmarshalBinary(b []byte) error {
	var res DomesticStandingOrderConsentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
