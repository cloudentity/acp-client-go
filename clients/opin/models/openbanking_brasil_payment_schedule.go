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

// OpenbankingBrasilPaymentSchedule OpenbankingBrasilPaymentSchedule Schedule
//
// Mutuamente exclusivo com o campo date. Este campo  obrigatrio no caso de agendamento. Neste caso, o campo date no deve ser informado.
//
// swagger:model OpenbankingBrasilPaymentSchedule
type OpenbankingBrasilPaymentSchedule struct {

	// single
	// Required: true
	Single *OpenbankingBrasilPaymentSingle `json:"single"`
}

// Validate validates this openbanking brasil payment schedule
func (m *OpenbankingBrasilPaymentSchedule) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSingle(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentSchedule) validateSingle(formats strfmt.Registry) error {

	if err := validate.Required("single", "body", m.Single); err != nil {
		return err
	}

	if m.Single != nil {
		if err := m.Single.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("single")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("single")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking brasil payment schedule based on the context it is used
func (m *OpenbankingBrasilPaymentSchedule) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSingle(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentSchedule) contextValidateSingle(ctx context.Context, formats strfmt.Registry) error {

	if m.Single != nil {

		if err := m.Single.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("single")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("single")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentSchedule) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentSchedule) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentSchedule
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}