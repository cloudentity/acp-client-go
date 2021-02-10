// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// RiskDeliveryAddress DeliveryAddress Information that locates and identifies a specific address, as defined by postal services or in free format text.
//
// swagger:model RiskDeliveryAddress
type RiskDeliveryAddress struct {

	// address line
	// Max Items: 2
	// Min Items: 0
	AddressLine []string `json:"AddressLine"`

	// building number
	BuildingNumber string `json:"BuildingNumber,omitempty"`

	// Nation with its own government, occupying a particular territory.
	// Required: true
	// Pattern: ^[A-Z]{2,2}$
	Country *string `json:"Country"`

	// country sub division
	CountrySubDivision string `json:"CountrySubDivision,omitempty"`

	// post code
	PostCode string `json:"PostCode,omitempty"`

	// street name
	StreetName string `json:"StreetName,omitempty"`

	// town name
	// Required: true
	TownName *string `json:"TownName"`
}

// Validate validates this risk delivery address
func (m *RiskDeliveryAddress) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddressLine(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCountry(formats); err != nil {
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

func (m *RiskDeliveryAddress) validateAddressLine(formats strfmt.Registry) error {
	if swag.IsZero(m.AddressLine) { // not required
		return nil
	}

	iAddressLineSize := int64(len(m.AddressLine))

	if err := validate.MinItems("AddressLine", "body", iAddressLineSize, 0); err != nil {
		return err
	}

	if err := validate.MaxItems("AddressLine", "body", iAddressLineSize, 2); err != nil {
		return err
	}

	return nil
}

func (m *RiskDeliveryAddress) validateCountry(formats strfmt.Registry) error {

	if err := validate.Required("Country", "body", m.Country); err != nil {
		return err
	}

	if err := validate.Pattern("Country", "body", *m.Country, `^[A-Z]{2,2}$`); err != nil {
		return err
	}

	return nil
}

func (m *RiskDeliveryAddress) validateTownName(formats strfmt.Registry) error {

	if err := validate.Required("TownName", "body", m.TownName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this risk delivery address based on context it is used
func (m *RiskDeliveryAddress) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RiskDeliveryAddress) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RiskDeliveryAddress) UnmarshalBinary(b []byte) error {
	var res RiskDeliveryAddress
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
