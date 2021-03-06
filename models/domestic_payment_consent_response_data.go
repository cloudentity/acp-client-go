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

// DomesticPaymentConsentResponseData domestic payment consent response data
//
// swagger:model DomesticPaymentConsentResponseData
type DomesticPaymentConsentResponseData struct {

	// Unique identification as assigned to identify the domestic payment consent resource.
	ConsentID string `json:"ConsentId,omitempty"`

	// Date and time at which the resource was created.
	// Format: date-time
	CreationDateTime strfmt.DateTime `json:"CreationDateTime,omitempty"`

	// initiation
	Initiation *DomesticPaymentConsentDataInitiation `json:"Initiation,omitempty"`

	// read refund account
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// Specifies the status of consent resource in code form.
	Status string `json:"Status,omitempty"`

	// Date and time at which the resource status was updated.
	// Format: date-time
	StatusUpdateDateTime strfmt.DateTime `json:"StatusUpdateDateTime,omitempty"`
}

// Validate validates this domestic payment consent response data
func (m *DomesticPaymentConsentResponseData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdateDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticPaymentConsentResponseData) validateCreationDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreationDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomesticPaymentConsentResponseData) validateInitiation(formats strfmt.Registry) error {
	if swag.IsZero(m.Initiation) { // not required
		return nil
	}

	if m.Initiation != nil {
		if err := m.Initiation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentResponseData) validateStatusUpdateDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.StatusUpdateDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("StatusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domestic payment consent response data based on the context it is used
func (m *DomesticPaymentConsentResponseData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateInitiation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticPaymentConsentResponseData) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if m.Initiation != nil {
		if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomesticPaymentConsentResponseData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomesticPaymentConsentResponseData) UnmarshalBinary(b []byte) error {
	var res DomesticPaymentConsentResponseData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
