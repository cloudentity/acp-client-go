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

// OBWriteDomesticScheduledConsent4Data OBWriteDomesticScheduledConsent4Data o b write domestic scheduled consent4 data
//
// swagger:model OBWriteDomesticScheduledConsent4Data
type OBWriteDomesticScheduledConsent4Data struct {

	// authorisation
	Authorisation *OBWriteDomesticScheduledConsent4DataAuthorisation `json:"Authorisation,omitempty"`

	// initiation
	// Required: true
	Initiation *OBWriteDomesticScheduledConsent4DataInitiation `json:"Initiation"`

	// Specifies the Open Banking service request types.
	// Required: true
	// Enum: [Create]
	Permission string `json:"Permission"`

	// Specifies to share the refund account details with PISP
	// Enum: [No Yes]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *OBWriteDomesticScheduledConsent4DataSCASupportData `json:"SCASupportData,omitempty"`
}

// Validate validates this o b write domestic scheduled consent4 data
func (m *OBWriteDomesticScheduledConsent4Data) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticScheduledConsent4Data) validateAuthorisation(formats strfmt.Registry) error {
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

func (m *OBWriteDomesticScheduledConsent4Data) validateInitiation(formats strfmt.Registry) error {

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

var oBWriteDomesticScheduledConsent4DataTypePermissionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Create"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticScheduledConsent4DataTypePermissionPropEnum = append(oBWriteDomesticScheduledConsent4DataTypePermissionPropEnum, v)
	}
}

const (

	// OBWriteDomesticScheduledConsent4DataPermissionCreate captures enum value "Create"
	OBWriteDomesticScheduledConsent4DataPermissionCreate string = "Create"
)

// prop value enum
func (m *OBWriteDomesticScheduledConsent4Data) validatePermissionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticScheduledConsent4DataTypePermissionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticScheduledConsent4Data) validatePermission(formats strfmt.Registry) error {

	if err := validate.RequiredString("Permission", "body", m.Permission); err != nil {
		return err
	}

	// value enum
	if err := m.validatePermissionEnum("Permission", "body", m.Permission); err != nil {
		return err
	}

	return nil
}

var oBWriteDomesticScheduledConsent4DataTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["No","Yes"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticScheduledConsent4DataTypeReadRefundAccountPropEnum = append(oBWriteDomesticScheduledConsent4DataTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OBWriteDomesticScheduledConsent4DataReadRefundAccountNo captures enum value "No"
	OBWriteDomesticScheduledConsent4DataReadRefundAccountNo string = "No"

	// OBWriteDomesticScheduledConsent4DataReadRefundAccountYes captures enum value "Yes"
	OBWriteDomesticScheduledConsent4DataReadRefundAccountYes string = "Yes"
)

// prop value enum
func (m *OBWriteDomesticScheduledConsent4Data) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticScheduledConsent4DataTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticScheduledConsent4Data) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteDomesticScheduledConsent4Data) validateSCASupportData(formats strfmt.Registry) error {
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

// ContextValidate validate this o b write domestic scheduled consent4 data based on the context it is used
func (m *OBWriteDomesticScheduledConsent4Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteDomesticScheduledConsent4Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if m.Authorisation != nil {
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

func (m *OBWriteDomesticScheduledConsent4Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteDomesticScheduledConsent4Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if m.SCASupportData != nil {
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
func (m *OBWriteDomesticScheduledConsent4Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticScheduledConsent4Data) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticScheduledConsent4Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
