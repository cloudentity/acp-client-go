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

// OpenbankingBrasilAutomaticPaymentV1Revocation1 OpenbankingBrasilAutomaticPaymentV1Revocation1 Revocation1
//
// Objeto contendo as informaes de revogao dos consentimentos.
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1Revocation1
type OpenbankingBrasilAutomaticPaymentV1Revocation1 struct {

	// reason
	Reason *OpenbankingBrasilAutomaticPaymentV1Reason `json:"reason,omitempty" yaml:"reason,omitempty"`

	// Data e hora em que o consentimento foi revogado
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	RevokedAt strfmt.DateTime `json:"revokedAt" yaml:"revokedAt"`

	// revoked by
	// Required: true
	RevokedBy *OpenbankingBrasilAutomaticPaymentV1RevokedBy1 `json:"revokedBy" yaml:"revokedBy"`

	// revoked from
	// Required: true
	RevokedFrom *OpenbankingBrasilAutomaticPaymentV1RevokedFrom1 `json:"revokedFrom" yaml:"revokedFrom"`
}

// Validate validates this openbanking brasil automatic payment v1 revocation1
func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateReason(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevokedFrom(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) validateReason(formats strfmt.Registry) error {
	if swag.IsZero(m.Reason) { // not required
		return nil
	}

	if m.Reason != nil {
		if err := m.Reason.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reason")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reason")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) validateRevokedAt(formats strfmt.Registry) error {

	if err := validate.Required("revokedAt", "body", strfmt.DateTime(m.RevokedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("revokedAt", "body", "date-time", m.RevokedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) validateRevokedBy(formats strfmt.Registry) error {

	if err := validate.Required("revokedBy", "body", m.RevokedBy); err != nil {
		return err
	}

	if err := validate.Required("revokedBy", "body", m.RevokedBy); err != nil {
		return err
	}

	if m.RevokedBy != nil {
		if err := m.RevokedBy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revokedBy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revokedBy")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) validateRevokedFrom(formats strfmt.Registry) error {

	if err := validate.Required("revokedFrom", "body", m.RevokedFrom); err != nil {
		return err
	}

	if err := validate.Required("revokedFrom", "body", m.RevokedFrom); err != nil {
		return err
	}

	if m.RevokedFrom != nil {
		if err := m.RevokedFrom.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revokedFrom")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revokedFrom")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking brasil automatic payment v1 revocation1 based on the context it is used
func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateReason(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevokedBy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevokedFrom(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) contextValidateReason(ctx context.Context, formats strfmt.Registry) error {

	if m.Reason != nil {

		if swag.IsZero(m.Reason) { // not required
			return nil
		}

		if err := m.Reason.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("reason")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("reason")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) contextValidateRevokedBy(ctx context.Context, formats strfmt.Registry) error {

	if m.RevokedBy != nil {

		if err := m.RevokedBy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revokedBy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revokedBy")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) contextValidateRevokedFrom(ctx context.Context, formats strfmt.Registry) error {

	if m.RevokedFrom != nil {

		if err := m.RevokedFrom.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revokedFrom")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revokedFrom")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1Revocation1) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilAutomaticPaymentV1Revocation1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}