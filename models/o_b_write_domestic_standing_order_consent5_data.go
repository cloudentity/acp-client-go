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

// OBWriteDomesticStandingOrderConsent5Data OBWriteDomesticStandingOrderConsent5Data o b write domestic standing order consent5 data
//
// swagger:model OBWriteDomesticStandingOrderConsent5Data
type OBWriteDomesticStandingOrderConsent5Data struct {

	// authorisation
	Authorisation *OBWriteDomesticStandingOrderConsent5DataAuthorisation `json:"Authorisation,omitempty"`

	// initiation
	// Required: true
	Initiation *OBWriteDomesticStandingOrderConsent5DataInitiation `json:"Initiation"`

	// Specifies the Open Banking service request types.
	// Required: true
	// Enum: [Create]
	Permission string `json:"Permission"`

	// Specifies to share the refund account details with PISP
	// Enum: [No Yes]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *OBWriteDomesticStandingOrderConsent5DataSCASupportData `json:"SCASupportData,omitempty"`
}

// Validate validates this o b write domestic standing order consent5 data
func (m *OBWriteDomesticStandingOrderConsent5Data) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticStandingOrderConsent5Data) validateAuthorisation(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticStandingOrderConsent5Data) validateInitiation(formats strfmt.Registry) error {

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

var oBWriteDomesticStandingOrderConsent5DataTypePermissionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Create"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticStandingOrderConsent5DataTypePermissionPropEnum = append(oBWriteDomesticStandingOrderConsent5DataTypePermissionPropEnum, v)
	}
}

const (

	// OBWriteDomesticStandingOrderConsent5DataPermissionCreate captures enum value "Create"
	OBWriteDomesticStandingOrderConsent5DataPermissionCreate string = "Create"
)

// prop value enum
func (m *OBWriteDomesticStandingOrderConsent5Data) validatePermissionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticStandingOrderConsent5DataTypePermissionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticStandingOrderConsent5Data) validatePermission(formats strfmt.Registry) error {

	if err := validate.RequiredString("Permission", "body", m.Permission); err != nil {
		return err
	}

	// value enum
	if err := m.validatePermissionEnum("Permission", "body", m.Permission); err != nil {
		return err
	}

	return nil
}

var oBWriteDomesticStandingOrderConsent5DataTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["No","Yes"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticStandingOrderConsent5DataTypeReadRefundAccountPropEnum = append(oBWriteDomesticStandingOrderConsent5DataTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OBWriteDomesticStandingOrderConsent5DataReadRefundAccountNo captures enum value "No"
	OBWriteDomesticStandingOrderConsent5DataReadRefundAccountNo string = "No"

	// OBWriteDomesticStandingOrderConsent5DataReadRefundAccountYes captures enum value "Yes"
	OBWriteDomesticStandingOrderConsent5DataReadRefundAccountYes string = "Yes"
)

// prop value enum
func (m *OBWriteDomesticStandingOrderConsent5Data) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticStandingOrderConsent5DataTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticStandingOrderConsent5Data) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsent5Data) validateSCASupportData(formats strfmt.Registry) error {
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

// ContextValidate validate this o b write domestic standing order consent5 data based on the context it is used
func (m *OBWriteDomesticStandingOrderConsent5Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteDomesticStandingOrderConsent5Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteDomesticStandingOrderConsent5Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteDomesticStandingOrderConsent5Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OBWriteDomesticStandingOrderConsent5Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticStandingOrderConsent5Data) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticStandingOrderConsent5Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
