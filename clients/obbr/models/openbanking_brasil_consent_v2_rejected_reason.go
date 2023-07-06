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

// OpenbankingBrasilConsentV2RejectedReason OpenbankingBrasilConsentV2RejectedReason RejectedReason
//
// Define a razo pela qual o consentimento foi rejeitado.
//
// swagger:model OpenbankingBrasilConsentV2RejectedReason
type OpenbankingBrasilConsentV2RejectedReason struct {

	// Contm informaes adicionais a critrio da transmissora.
	// Example: Tempo de confirmao da mltipla alada excedido.
	// Max Length: 140
	// Pattern: [\w\W\s]*
	AdditionalInformation string `json:"additionalInformation,omitempty"`

	// code
	// Required: true
	Code *OpenbankingBrasilConsentV2EnumReasonCode `json:"code"`
}

// Validate validates this openbanking brasil consent v2 rejected reason
func (m *OpenbankingBrasilConsentV2RejectedReason) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAdditionalInformation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilConsentV2RejectedReason) validateAdditionalInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.AdditionalInformation) { // not required
		return nil
	}

	if err := validate.MaxLength("additionalInformation", "body", m.AdditionalInformation, 140); err != nil {
		return err
	}

	if err := validate.Pattern("additionalInformation", "body", m.AdditionalInformation, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilConsentV2RejectedReason) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	if m.Code != nil {
		if err := m.Code.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking brasil consent v2 rejected reason based on the context it is used
func (m *OpenbankingBrasilConsentV2RejectedReason) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilConsentV2RejectedReason) contextValidateCode(ctx context.Context, formats strfmt.Registry) error {

	if m.Code != nil {

		if err := m.Code.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilConsentV2RejectedReason) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilConsentV2RejectedReason) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilConsentV2RejectedReason
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
