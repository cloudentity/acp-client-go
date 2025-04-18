// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBRisk1 The Risk section is sent by the initiating party to the ASPSP. It is used to specify additional details for risk scoring for Payments.
//
// swagger:model OBRisk1
type OBRisk1 struct {

	// delivery address
	DeliveryAddress OBRisk1DeliveryAddress `json:"DeliveryAddress,omitempty"`

	// Category code conform to ISO 18245, related to the type of services or goods the merchant provides for the transaction.
	// Max Length: 4
	// Min Length: 3
	MerchantCategoryCode string `json:"MerchantCategoryCode,omitempty"`

	// The unique customer identifier of the PSU with the merchant.
	// Max Length: 70
	// Min Length: 1
	MerchantCustomerIdentification string `json:"MerchantCustomerIdentification,omitempty"`

	// Specifies the payment context
	// Enum: ["BillPayment","EcommerceGoods","EcommerceServices","Other","PartyToParty"]
	PaymentContextCode string `json:"PaymentContextCode,omitempty"`
}

// Validate validates this o b risk1
func (m *OBRisk1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDeliveryAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMerchantCategoryCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMerchantCustomerIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentContextCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBRisk1) validateDeliveryAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.DeliveryAddress) { // not required
		return nil
	}

	if err := m.DeliveryAddress.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress")
		}
		return err
	}

	return nil
}

func (m *OBRisk1) validateMerchantCategoryCode(formats strfmt.Registry) error {
	if swag.IsZero(m.MerchantCategoryCode) { // not required
		return nil
	}

	if err := validate.MinLength("MerchantCategoryCode", "body", m.MerchantCategoryCode, 3); err != nil {
		return err
	}

	if err := validate.MaxLength("MerchantCategoryCode", "body", m.MerchantCategoryCode, 4); err != nil {
		return err
	}

	return nil
}

func (m *OBRisk1) validateMerchantCustomerIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.MerchantCustomerIdentification) { // not required
		return nil
	}

	if err := validate.MinLength("MerchantCustomerIdentification", "body", m.MerchantCustomerIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("MerchantCustomerIdentification", "body", m.MerchantCustomerIdentification, 70); err != nil {
		return err
	}

	return nil
}

var oBRisk1TypePaymentContextCodePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","EcommerceGoods","EcommerceServices","Other","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBRisk1TypePaymentContextCodePropEnum = append(oBRisk1TypePaymentContextCodePropEnum, v)
	}
}

const (

	// OBRisk1PaymentContextCodeBillPayment captures enum value "BillPayment"
	OBRisk1PaymentContextCodeBillPayment string = "BillPayment"

	// OBRisk1PaymentContextCodeEcommerceGoods captures enum value "EcommerceGoods"
	OBRisk1PaymentContextCodeEcommerceGoods string = "EcommerceGoods"

	// OBRisk1PaymentContextCodeEcommerceServices captures enum value "EcommerceServices"
	OBRisk1PaymentContextCodeEcommerceServices string = "EcommerceServices"

	// OBRisk1PaymentContextCodeOther captures enum value "Other"
	OBRisk1PaymentContextCodeOther string = "Other"

	// OBRisk1PaymentContextCodePartyToParty captures enum value "PartyToParty"
	OBRisk1PaymentContextCodePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBRisk1) validatePaymentContextCodeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBRisk1TypePaymentContextCodePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBRisk1) validatePaymentContextCode(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentContextCode) { // not required
		return nil
	}

	// value enum
	if err := m.validatePaymentContextCodeEnum("PaymentContextCode", "body", m.PaymentContextCode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this o b risk1 based on the context it is used
func (m *OBRisk1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDeliveryAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBRisk1) contextValidateDeliveryAddress(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.DeliveryAddress) { // not required
		return nil
	}

	if err := m.DeliveryAddress.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBRisk1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBRisk1) UnmarshalBinary(b []byte) error {
	var res OBRisk1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBRisk1DeliveryAddress Information that locates and identifies a specific address, as defined by postal services or in free format text.
//
// swagger:model OBRisk1DeliveryAddress
type OBRisk1DeliveryAddress struct {

	// address line
	// Max Items: 2
	AddressLine []string `json:"AddressLine"`

	// building number
	BuildingNumber BuildingNumber `json:"BuildingNumber,omitempty"`

	// Nation with its own government, occupying a particular territory.
	// Required: true
	// Pattern: ^[A-Z]{2,2}$
	Country string `json:"Country"`

	// country sub division
	CountrySubDivision CountrySubDivision `json:"CountrySubDivision,omitempty"`

	// post code
	PostCode PostCode `json:"PostCode,omitempty"`

	// street name
	StreetName StreetName `json:"StreetName,omitempty"`

	// town name
	// Required: true
	TownName *TownName `json:"TownName"`
}

// Validate validates this o b risk1 delivery address
func (m *OBRisk1DeliveryAddress) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddressLine(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBuildingNumber(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCountry(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCountrySubDivision(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePostCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStreetName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTownName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBRisk1DeliveryAddress) validateAddressLine(formats strfmt.Registry) error {
	if swag.IsZero(m.AddressLine) { // not required
		return nil
	}

	iAddressLineSize := int64(len(m.AddressLine))

	if err := validate.MaxItems("DeliveryAddress"+"."+"AddressLine", "body", iAddressLineSize, 2); err != nil {
		return err
	}

	for i := 0; i < len(m.AddressLine); i++ {

		if err := validate.MinLength("DeliveryAddress"+"."+"AddressLine"+"."+strconv.Itoa(i), "body", m.AddressLine[i], 1); err != nil {
			return err
		}

		if err := validate.MaxLength("DeliveryAddress"+"."+"AddressLine"+"."+strconv.Itoa(i), "body", m.AddressLine[i], 70); err != nil {
			return err
		}

	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validateBuildingNumber(formats strfmt.Registry) error {
	if swag.IsZero(m.BuildingNumber) { // not required
		return nil
	}

	if err := m.BuildingNumber.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "BuildingNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "BuildingNumber")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validateCountry(formats strfmt.Registry) error {

	if err := validate.RequiredString("DeliveryAddress"+"."+"Country", "body", m.Country); err != nil {
		return err
	}

	if err := validate.Pattern("DeliveryAddress"+"."+"Country", "body", m.Country, `^[A-Z]{2,2}$`); err != nil {
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validateCountrySubDivision(formats strfmt.Registry) error {
	if swag.IsZero(m.CountrySubDivision) { // not required
		return nil
	}

	if err := m.CountrySubDivision.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "CountrySubDivision")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "CountrySubDivision")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validatePostCode(formats strfmt.Registry) error {
	if swag.IsZero(m.PostCode) { // not required
		return nil
	}

	if err := m.PostCode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "PostCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "PostCode")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validateStreetName(formats strfmt.Registry) error {
	if swag.IsZero(m.StreetName) { // not required
		return nil
	}

	if err := m.StreetName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "StreetName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "StreetName")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) validateTownName(formats strfmt.Registry) error {

	if err := validate.Required("DeliveryAddress"+"."+"TownName", "body", m.TownName); err != nil {
		return err
	}

	if err := validate.Required("DeliveryAddress"+"."+"TownName", "body", m.TownName); err != nil {
		return err
	}

	if m.TownName != nil {
		if err := m.TownName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DeliveryAddress" + "." + "TownName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DeliveryAddress" + "." + "TownName")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b risk1 delivery address based on the context it is used
func (m *OBRisk1DeliveryAddress) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBuildingNumber(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCountrySubDivision(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePostCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStreetName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTownName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBRisk1DeliveryAddress) contextValidateBuildingNumber(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.BuildingNumber) { // not required
		return nil
	}

	if err := m.BuildingNumber.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "BuildingNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "BuildingNumber")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) contextValidateCountrySubDivision(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.CountrySubDivision) { // not required
		return nil
	}

	if err := m.CountrySubDivision.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "CountrySubDivision")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "CountrySubDivision")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) contextValidatePostCode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PostCode) { // not required
		return nil
	}

	if err := m.PostCode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "PostCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "PostCode")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) contextValidateStreetName(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.StreetName) { // not required
		return nil
	}

	if err := m.StreetName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DeliveryAddress" + "." + "StreetName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DeliveryAddress" + "." + "StreetName")
		}
		return err
	}

	return nil
}

func (m *OBRisk1DeliveryAddress) contextValidateTownName(ctx context.Context, formats strfmt.Registry) error {

	if m.TownName != nil {

		if err := m.TownName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DeliveryAddress" + "." + "TownName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DeliveryAddress" + "." + "TownName")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBRisk1DeliveryAddress) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBRisk1DeliveryAddress) UnmarshalBinary(b []byte) error {
	var res OBRisk1DeliveryAddress
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
