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

// OBWriteInternationalScheduledConsentResponse6DataSCASupportData OBWriteInternationalScheduledConsentResponse6DataSCASupportData Supporting Data provided by TPP, when requesting SCA Exemption.
//
// swagger:model OBWriteInternationalScheduledConsentResponse6DataSCASupportData
type OBWriteInternationalScheduledConsentResponse6DataSCASupportData struct {

	// Specifies a character string with a maximum length of 40 characters.
	// Usage: This field indicates whether the PSU was subject to SCA performed by the TPP
	// Enum: [CA SCA]
	AppliedAuthenticationApproach string `json:"AppliedAuthenticationApproach,omitempty" yaml:"AppliedAuthenticationApproach,omitempty"`

	// Specifies a character string with a maximum length of 140 characters.
	// Usage: If the payment is recurring then the transaction identifier of the previous payment occurrence so that the ASPSP can verify that the PISP, amount and the payee are the same as the previous occurrence.
	// Max Length: 128
	// Min Length: 1
	ReferencePaymentOrderID string `json:"ReferencePaymentOrderId,omitempty" yaml:"ReferencePaymentOrderId,omitempty"`

	// This field allows a PISP to request specific SCA Exemption for a Payment Initiation
	// Enum: [BillPayment ContactlessTravel EcommerceGoods EcommerceServices Kiosk Parking PartyToParty]
	RequestedSCAExemptionType string `json:"RequestedSCAExemptionType,omitempty" yaml:"RequestedSCAExemptionType,omitempty"`
}

// Validate validates this o b write international scheduled consent response6 data s c a support data
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) Validate(formats strfmt.Registry) error {
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

var oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CA","SCA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum = append(oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, v)
	}
}

const (

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataAppliedAuthenticationApproachCA captures enum value "CA"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataAppliedAuthenticationApproachCA string = "CA"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataAppliedAuthenticationApproachSCA captures enum value "SCA"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataAppliedAuthenticationApproachSCA string = "SCA"
)

// prop value enum
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) validateAppliedAuthenticationApproachEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) validateAppliedAuthenticationApproach(formats strfmt.Registry) error {
	if swag.IsZero(m.AppliedAuthenticationApproach) { // not required
		return nil
	}

	// value enum
	if err := m.validateAppliedAuthenticationApproachEnum("AppliedAuthenticationApproach", "body", m.AppliedAuthenticationApproach); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) validateReferencePaymentOrderID(formats strfmt.Registry) error {
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

var oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum = append(oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeBillPayment captures enum value "BillPayment"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeBillPayment string = "BillPayment"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel captures enum value "ContactlessTravel"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel string = "ContactlessTravel"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods captures enum value "EcommerceGoods"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods string = "EcommerceGoods"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices captures enum value "EcommerceServices"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices string = "EcommerceServices"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeKiosk captures enum value "Kiosk"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeKiosk string = "Kiosk"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeParking captures enum value "Parking"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypeParking string = "Parking"

	// OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypePartyToParty captures enum value "PartyToParty"
	OBWriteInternationalScheduledConsentResponse6DataSCASupportDataRequestedSCAExemptionTypePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) validateRequestedSCAExemptionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalScheduledConsentResponse6DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) validateRequestedSCAExemptionType(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedSCAExemptionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateRequestedSCAExemptionTypeEnum("RequestedSCAExemptionType", "body", m.RequestedSCAExemptionType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international scheduled consent response6 data s c a support data based on context it is used
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataSCASupportData) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalScheduledConsentResponse6DataSCASupportData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
