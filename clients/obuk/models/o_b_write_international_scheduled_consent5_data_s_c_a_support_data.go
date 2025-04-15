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

// OBWriteInternationalScheduledConsent5DataSCASupportData OBWriteInternationalScheduledConsent5DataSCASupportData Supporting Data provided by TPP, when requesting SCA Exemption.
//
// swagger:model OBWriteInternationalScheduledConsent5DataSCASupportData
type OBWriteInternationalScheduledConsent5DataSCASupportData struct {

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

// Validate validates this o b write international scheduled consent5 data s c a support data
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) Validate(formats strfmt.Registry) error {
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

var oBWriteInternationalScheduledConsent5DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CA","SCA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalScheduledConsent5DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum = append(oBWriteInternationalScheduledConsent5DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, v)
	}
}

const (

	// OBWriteInternationalScheduledConsent5DataSCASupportDataAppliedAuthenticationApproachCA captures enum value "CA"
	OBWriteInternationalScheduledConsent5DataSCASupportDataAppliedAuthenticationApproachCA string = "CA"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataAppliedAuthenticationApproachSCA captures enum value "SCA"
	OBWriteInternationalScheduledConsent5DataSCASupportDataAppliedAuthenticationApproachSCA string = "SCA"
)

// prop value enum
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) validateAppliedAuthenticationApproachEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalScheduledConsent5DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) validateAppliedAuthenticationApproach(formats strfmt.Registry) error {
	if swag.IsZero(m.AppliedAuthenticationApproach) { // not required
		return nil
	}

	// value enum
	if err := m.validateAppliedAuthenticationApproachEnum("AppliedAuthenticationApproach", "body", m.AppliedAuthenticationApproach); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) validateReferencePaymentOrderID(formats strfmt.Registry) error {
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

var oBWriteInternationalScheduledConsent5DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalScheduledConsent5DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum = append(oBWriteInternationalScheduledConsent5DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeBillPayment captures enum value "BillPayment"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeBillPayment string = "BillPayment"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel captures enum value "ContactlessTravel"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel string = "ContactlessTravel"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods captures enum value "EcommerceGoods"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods string = "EcommerceGoods"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices captures enum value "EcommerceServices"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices string = "EcommerceServices"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeKiosk captures enum value "Kiosk"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeKiosk string = "Kiosk"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeParking captures enum value "Parking"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypeParking string = "Parking"

	// OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypePartyToParty captures enum value "PartyToParty"
	OBWriteInternationalScheduledConsent5DataSCASupportDataRequestedSCAExemptionTypePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) validateRequestedSCAExemptionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalScheduledConsent5DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) validateRequestedSCAExemptionType(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedSCAExemptionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateRequestedSCAExemptionTypeEnum("RequestedSCAExemptionType", "body", m.RequestedSCAExemptionType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international scheduled consent5 data s c a support data based on context it is used
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsent5DataSCASupportData) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalScheduledConsent5DataSCASupportData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
