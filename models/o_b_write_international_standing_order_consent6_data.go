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

// OBWriteInternationalStandingOrderConsent6Data OBWriteInternationalStandingOrderConsent6Data o b write international standing order consent6 data
//
// swagger:model OBWriteInternationalStandingOrderConsent6Data
type OBWriteInternationalStandingOrderConsent6Data struct {

	// authorisation
	Authorisation *OBWriteInternationalStandingOrderConsent6DataAuthorisation `json:"Authorisation,omitempty"`

	// initiation
	// Required: true
	Initiation *OBWriteInternationalStandingOrderConsent6DataInitiation `json:"Initiation"`

	// Specifies the Open Banking service request types.
	// Required: true
	// Enum: [Create]
	Permission *string `json:"Permission"`

	// Specifies to share the refund account details with PISP
	// Enum: [No Yes]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *OBWriteInternationalStandingOrderConsent6DataSCASupportData `json:"SCASupportData,omitempty"`
}

// Validate validates this o b write international standing order consent6 data
func (m *OBWriteInternationalStandingOrderConsent6Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermission(formats); err != nil {
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

func (m *OBWriteInternationalStandingOrderConsent6Data) validateAuthorisation(formats strfmt.Registry) error {
	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if m.Authorisation != nil {
		if err := m.Authorisation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsent6Data) validateInitiation(formats strfmt.Registry) error {

	if err := validate.Required("Initiation", "body", m.Initiation); err != nil {
		return err
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

var oBWriteInternationalStandingOrderConsent6DataTypePermissionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Create"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsent6DataTypePermissionPropEnum = append(oBWriteInternationalStandingOrderConsent6DataTypePermissionPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsent6DataPermissionCreate captures enum value "Create"
	OBWriteInternationalStandingOrderConsent6DataPermissionCreate string = "Create"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsent6Data) validatePermissionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsent6DataTypePermissionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsent6Data) validatePermission(formats strfmt.Registry) error {

	if err := validate.Required("Permission", "body", m.Permission); err != nil {
		return err
	}

	// value enum
	if err := m.validatePermissionEnum("Permission", "body", *m.Permission); err != nil {
		return err
	}

	return nil
}

var oBWriteInternationalStandingOrderConsent6DataTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["No","Yes"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsent6DataTypeReadRefundAccountPropEnum = append(oBWriteInternationalStandingOrderConsent6DataTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsent6DataReadRefundAccountNo captures enum value "No"
	OBWriteInternationalStandingOrderConsent6DataReadRefundAccountNo string = "No"

	// OBWriteInternationalStandingOrderConsent6DataReadRefundAccountYes captures enum value "Yes"
	OBWriteInternationalStandingOrderConsent6DataReadRefundAccountYes string = "Yes"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsent6Data) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsent6DataTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsent6Data) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsent6Data) validateSCASupportData(formats strfmt.Registry) error {
	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if m.SCASupportData != nil {
		if err := m.SCASupportData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write international standing order consent6 data based on the context it is used
func (m *OBWriteInternationalStandingOrderConsent6Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteInternationalStandingOrderConsent6Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if m.Authorisation != nil {
		if err := m.Authorisation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsent6Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteInternationalStandingOrderConsent6Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if m.SCASupportData != nil {
		if err := m.SCASupportData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsent6Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsent6Data) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsent6Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
