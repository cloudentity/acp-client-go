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

// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData Supporting Data provided by TPP, when requesting SCA Exemption.
//
// swagger:model OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData
type OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData struct {

	// Specifies a character string with a maximum length of 40 characters.
	// Usage: This field indicates whether the PSU was subject to SCA performed by the TPP
	// Enum: ["CA","SCA"]
	AppliedAuthenticationApproach string `json:"AppliedAuthenticationApproach,omitempty" yaml:"AppliedAuthenticationApproach,omitempty"`

	// Specifies a character string with a maximum length of 140 characters.
	// Usage: If the payment is recurring then the transaction identifier of the previous payment occurrence so that the ASPSP can verify that the PISP, amount and the payee are the same as the previous occurrence.
	// Max Length: 128
	// Min Length: 1
	ReferencePaymentOrderID string `json:"ReferencePaymentOrderId,omitempty" yaml:"ReferencePaymentOrderId,omitempty"`

	// This field allows a PISP to request specific SCA Exemption for a Payment Initiation
	// Enum: ["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]
	RequestedSCAExemptionType string `json:"RequestedSCAExemptionType,omitempty" yaml:"RequestedSCAExemptionType,omitempty"`
}

// Validate validates this o b write international standing order consent response7 data s c a support data
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAppliedAuthenticationApproach(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReferencePaymentOrderID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedSCAExemptionType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CA","SCA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataAppliedAuthenticationApproachCA captures enum value "CA"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataAppliedAuthenticationApproachCA string = "CA"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataAppliedAuthenticationApproachSCA captures enum value "SCA"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataAppliedAuthenticationApproachSCA string = "SCA"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) validateAppliedAuthenticationApproachEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) validateAppliedAuthenticationApproach(formats strfmt.Registry) error {
	if swag.IsZero(m.AppliedAuthenticationApproach) { // not required
		return nil
	}

	// value enum
	if err := m.validateAppliedAuthenticationApproachEnum("AppliedAuthenticationApproach", "body", m.AppliedAuthenticationApproach); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) validateReferencePaymentOrderID(formats strfmt.Registry) error {
	if swag.IsZero(m.ReferencePaymentOrderID) { // not required
		return nil
	}

	if err := validate.MinLength("ReferencePaymentOrderId", "body", m.ReferencePaymentOrderID, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("ReferencePaymentOrderId", "body", m.ReferencePaymentOrderID, 128); err != nil {
		return err
	}

	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeBillPayment captures enum value "BillPayment"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeBillPayment string = "BillPayment"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel captures enum value "ContactlessTravel"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel string = "ContactlessTravel"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods captures enum value "EcommerceGoods"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods string = "EcommerceGoods"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices captures enum value "EcommerceServices"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices string = "EcommerceServices"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeKiosk captures enum value "Kiosk"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeKiosk string = "Kiosk"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeParking captures enum value "Parking"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypeParking string = "Parking"

	// OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypePartyToParty captures enum value "PartyToParty"
	OBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataRequestedSCAExemptionTypePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) validateRequestedSCAExemptionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) validateRequestedSCAExemptionType(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedSCAExemptionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateRequestedSCAExemptionTypeEnum("RequestedSCAExemptionType", "body", m.RequestedSCAExemptionType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international standing order consent response7 data s c a support data based on context it is used
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
