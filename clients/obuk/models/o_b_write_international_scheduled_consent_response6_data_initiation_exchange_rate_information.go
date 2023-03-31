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

// OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation Provides details on the currency exchange rate and contract.
//
// swagger:model OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation
type OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation struct {

	// Unique and unambiguous reference to the foreign exchange contract agreed between the initiating party/creditor and the debtor agent.
	// Max Length: 256
	// Min Length: 1
	ContractIdentification string `json:"ContractIdentification,omitempty"`

	// The factor used for conversion of an amount from one currency to another. This reflects the price at which one currency was bought with another currency.
	ExchangeRate float64 `json:"ExchangeRate,omitempty"`

	// Specifies the type used to complete the currency exchange.
	// Required: true
	// Enum: [Actual Agreed Indicative]
	RateType string `json:"RateType"`

	// Currency in which the rate of exchange is expressed in a currency exchange. In the example 1GBP = xxxCUR, the unit currency is GBP.
	// Required: true
	// Pattern: ^[A-Z]{3,3}$
	UnitCurrency string `json:"UnitCurrency"`
}

// Validate validates this o b write international scheduled consent response6 data initiation exchange rate information
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContractIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnitCurrency(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) validateContractIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.ContractIdentification) { // not required
		return nil
	}

	if err := validate.MinLength("ContractIdentification", "body", m.ContractIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("ContractIdentification", "body", m.ContractIdentification, 256); err != nil {
		return err
	}

	return nil
}

var oBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationTypeRateTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Actual","Agreed","Indicative"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationTypeRateTypePropEnum = append(oBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationTypeRateTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeActual captures enum value "Actual"
	OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeActual string = "Actual"

	// OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeAgreed captures enum value "Agreed"
	OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeAgreed string = "Agreed"

	// OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeIndicative captures enum value "Indicative"
	OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationRateTypeIndicative string = "Indicative"
)

// prop value enum
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) validateRateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformationTypeRateTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) validateRateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("RateType", "body", m.RateType); err != nil {
		return err
	}

	// value enum
	if err := m.validateRateTypeEnum("RateType", "body", m.RateType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) validateUnitCurrency(formats strfmt.Registry) error {

	if err := validate.RequiredString("UnitCurrency", "body", m.UnitCurrency); err != nil {
		return err
	}

	if err := validate.Pattern("UnitCurrency", "body", m.UnitCurrency, `^[A-Z]{3,3}$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international scheduled consent response6 data initiation exchange rate information based on context it is used
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalScheduledConsentResponse6DataInitiationExchangeRateInformation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
