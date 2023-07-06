// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBWriteInternationalConsent5Data OBWriteInternationalConsent5Data o b write international consent5 data
//
// swagger:model OBWriteInternationalConsent5Data
type OBWriteInternationalConsent5Data struct {

	// authorisation
	Authorisation *OBWriteInternationalConsent5DataAuthorisation `json:"Authorisation,omitempty"`

	// initiation
	// Required: true
	Initiation *OBWriteInternationalConsent5DataInitiation `json:"Initiation"`

	// Specifies to share the refund account details with PISP
	// Enum: [No Yes]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *OBWriteInternationalConsent5DataSCASupportData `json:"SCASupportData,omitempty"`
}

// Validate validates this o b write international consent5 data
func (m *OBWriteInternationalConsent5Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReadRefundAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSCASupportData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5Data) validateAuthorisation(formats strfmt.Registry) error {
	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if m.Authorisation != nil {
		if err := m.Authorisation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5Data) validateInitiation(formats strfmt.Registry) error {

	if err := validate.Required("Initiation", "body", m.Initiation); err != nil {
		return err
	}

	if m.Initiation != nil {
		if err := m.Initiation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

var oBWriteInternationalConsent5DataTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["No","Yes"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalConsent5DataTypeReadRefundAccountPropEnum = append(oBWriteInternationalConsent5DataTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OBWriteInternationalConsent5DataReadRefundAccountNo captures enum value "No"
	OBWriteInternationalConsent5DataReadRefundAccountNo string = "No"

	// OBWriteInternationalConsent5DataReadRefundAccountYes captures enum value "Yes"
	OBWriteInternationalConsent5DataReadRefundAccountYes string = "Yes"
)

// prop value enum
func (m *OBWriteInternationalConsent5Data) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalConsent5DataTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalConsent5Data) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5Data) validateSCASupportData(formats strfmt.Registry) error {
	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if m.SCASupportData != nil {
		if err := m.SCASupportData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write international consent5 data based on the context it is used
func (m *OBWriteInternationalConsent5Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthorisation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInitiation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSCASupportData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if m.Authorisation != nil {

		if swag.IsZero(m.Authorisation) { // not required
			return nil
		}

		if err := m.Authorisation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if m.Initiation != nil {

		if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if m.SCASupportData != nil {

		if swag.IsZero(m.SCASupportData) { // not required
			return nil
		}

		if err := m.SCASupportData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalConsent5Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalConsent5Data) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalConsent5Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
