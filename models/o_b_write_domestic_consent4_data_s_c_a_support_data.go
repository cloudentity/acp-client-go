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

// OBWriteDomesticConsent4DataSCASupportData OBWriteDomesticConsent4DataSCASupportData Supporting Data provided by TPP, when requesting SCA Exemption.
//
// swagger:model OBWriteDomesticConsent4DataSCASupportData
type OBWriteDomesticConsent4DataSCASupportData struct {

	// Specifies a character string with a maximum length of 40 characters.
	// Usage: This field indicates whether the PSU was subject to SCA performed by the TPP
	// Enum: [CA SCA]
	AppliedAuthenticationApproach string `json:"AppliedAuthenticationApproach,omitempty"`

	// Specifies a character string with a maximum length of 140 characters.
	// Usage: If the payment is recurring then the transaction identifier of the previous payment occurrence so that the ASPSP can verify that the PISP, amount and the payee are the same as the previous occurrence.
	// Max Length: 128
	// Min Length: 1
	ReferencePaymentOrderID string `json:"ReferencePaymentOrderId,omitempty"`

	// This field allows a PISP to request specific SCA Exemption for a Payment Initiation
	// Enum: [BillPayment ContactlessTravel EcommerceGoods EcommerceServices Kiosk Parking PartyToParty]
	RequestedSCAExemptionType string `json:"RequestedSCAExemptionType,omitempty"`
}

// Validate validates this o b write domestic consent4 data s c a support data
func (m *OBWriteDomesticConsent4DataSCASupportData) Validate(formats strfmt.Registry) error {
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

var oBWriteDomesticConsent4DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CA","SCA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticConsent4DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum = append(oBWriteDomesticConsent4DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, v)
	}
}

const (

	// OBWriteDomesticConsent4DataSCASupportDataAppliedAuthenticationApproachCA captures enum value "CA"
	OBWriteDomesticConsent4DataSCASupportDataAppliedAuthenticationApproachCA string = "CA"

	// OBWriteDomesticConsent4DataSCASupportDataAppliedAuthenticationApproachSCA captures enum value "SCA"
	OBWriteDomesticConsent4DataSCASupportDataAppliedAuthenticationApproachSCA string = "SCA"
)

// prop value enum
func (m *OBWriteDomesticConsent4DataSCASupportData) validateAppliedAuthenticationApproachEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticConsent4DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticConsent4DataSCASupportData) validateAppliedAuthenticationApproach(formats strfmt.Registry) error {
	if swag.IsZero(m.AppliedAuthenticationApproach) { // not required
		return nil
	}

	// value enum
	if err := m.validateAppliedAuthenticationApproachEnum("AppliedAuthenticationApproach", "body", m.AppliedAuthenticationApproach); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteDomesticConsent4DataSCASupportData) validateReferencePaymentOrderID(formats strfmt.Registry) error {
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

var oBWriteDomesticConsent4DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteDomesticConsent4DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum = append(oBWriteDomesticConsent4DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, v)
	}
}

const (

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeBillPayment captures enum value "BillPayment"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeBillPayment string = "BillPayment"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel captures enum value "ContactlessTravel"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel string = "ContactlessTravel"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods captures enum value "EcommerceGoods"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods string = "EcommerceGoods"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices captures enum value "EcommerceServices"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices string = "EcommerceServices"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeKiosk captures enum value "Kiosk"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeKiosk string = "Kiosk"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeParking captures enum value "Parking"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypeParking string = "Parking"

	// OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypePartyToParty captures enum value "PartyToParty"
	OBWriteDomesticConsent4DataSCASupportDataRequestedSCAExemptionTypePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBWriteDomesticConsent4DataSCASupportData) validateRequestedSCAExemptionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteDomesticConsent4DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteDomesticConsent4DataSCASupportData) validateRequestedSCAExemptionType(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedSCAExemptionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateRequestedSCAExemptionTypeEnum("RequestedSCAExemptionType", "body", m.RequestedSCAExemptionType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write domestic consent4 data s c a support data based on context it is used
func (m *OBWriteDomesticConsent4DataSCASupportData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteDomesticConsent4DataSCASupportData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticConsent4DataSCASupportData) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticConsent4DataSCASupportData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
