// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBPostalAddress6 Information that locates and identifies a specific address, as defined by postal services.
//
// swagger:model OBPostalAddress6
type OBPostalAddress6 struct {

	// address line
	// Max Items: 7
	AddressLine []string `json:"AddressLine"`

	// address type
	AddressType OBAddressTypeCode `json:"AddressType,omitempty"`

	// building number
	BuildingNumber BuildingNumber `json:"BuildingNumber,omitempty"`

	// Nation with its own government.
	// Pattern: ^[A-Z]{2,2}$
	Country string `json:"Country,omitempty"`

	// Identifies a subdivision of a country such as state, region, county.
	// Max Length: 35
	// Min Length: 1
	CountrySubDivision string `json:"CountrySubDivision,omitempty"`

	// Identification of a division of a large organisation or building.
	// Max Length: 70
	// Min Length: 1
	Department string `json:"Department,omitempty"`

	// post code
	PostCode PostCode `json:"PostCode,omitempty"`

	// street name
	StreetName StreetName `json:"StreetName,omitempty"`

	// Identification of a sub-division of a large organisation or building.
	// Max Length: 70
	// Min Length: 1
	SubDepartment string `json:"SubDepartment,omitempty"`

	// town name
	TownName TownName `json:"TownName,omitempty"`
}

// Validate validates this o b postal address6
func (m *OBPostalAddress6) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddressLine(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAddressType(formats); err != nil {
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

	if err := m.validateDepartment(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePostCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStreetName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubDepartment(formats); err != nil {
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

func (m *OBPostalAddress6) validateAddressLine(formats strfmt.Registry) error {
	if swag.IsZero(m.AddressLine) { // not required
		return nil
	}

	iAddressLineSize := int64(len(m.AddressLine))

	if err := validate.MaxItems("AddressLine", "body", iAddressLineSize, 7); err != nil {
		return err
	}

	for i := 0; i < len(m.AddressLine); i++ {

		if err := validate.MinLength("AddressLine"+"."+strconv.Itoa(i), "body", m.AddressLine[i], 1); err != nil {
			return err
		}

		if err := validate.MaxLength("AddressLine"+"."+strconv.Itoa(i), "body", m.AddressLine[i], 70); err != nil {
			return err
		}

	}

	return nil
}

func (m *OBPostalAddress6) validateAddressType(formats strfmt.Registry) error {
	if swag.IsZero(m.AddressType) { // not required
		return nil
	}

	if err := m.AddressType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("AddressType")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("AddressType")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateBuildingNumber(formats strfmt.Registry) error {
	if swag.IsZero(m.BuildingNumber) { // not required
		return nil
	}

	if err := m.BuildingNumber.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("BuildingNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("BuildingNumber")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateCountry(formats strfmt.Registry) error {
	if swag.IsZero(m.Country) { // not required
		return nil
	}

	if err := validate.Pattern("Country", "body", m.Country, `^[A-Z]{2,2}$`); err != nil {
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateCountrySubDivision(formats strfmt.Registry) error {
	if swag.IsZero(m.CountrySubDivision) { // not required
		return nil
	}

	if err := validate.MinLength("CountrySubDivision", "body", m.CountrySubDivision, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("CountrySubDivision", "body", m.CountrySubDivision, 35); err != nil {
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateDepartment(formats strfmt.Registry) error {
	if swag.IsZero(m.Department) { // not required
		return nil
	}

	if err := validate.MinLength("Department", "body", m.Department, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Department", "body", m.Department, 70); err != nil {
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validatePostCode(formats strfmt.Registry) error {
	if swag.IsZero(m.PostCode) { // not required
		return nil
	}

	if err := m.PostCode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PostCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PostCode")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateStreetName(formats strfmt.Registry) error {
	if swag.IsZero(m.StreetName) { // not required
		return nil
	}

	if err := m.StreetName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("StreetName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("StreetName")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateSubDepartment(formats strfmt.Registry) error {
	if swag.IsZero(m.SubDepartment) { // not required
		return nil
	}

	if err := validate.MinLength("SubDepartment", "body", m.SubDepartment, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("SubDepartment", "body", m.SubDepartment, 70); err != nil {
		return err
	}

	return nil
}

func (m *OBPostalAddress6) validateTownName(formats strfmt.Registry) error {
	if swag.IsZero(m.TownName) { // not required
		return nil
	}

	if err := m.TownName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("TownName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("TownName")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b postal address6 based on the context it is used
func (m *OBPostalAddress6) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAddressType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBuildingNumber(ctx, formats); err != nil {
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

func (m *OBPostalAddress6) contextValidateAddressType(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.AddressType) { // not required
		return nil
	}

	if err := m.AddressType.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("AddressType")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("AddressType")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) contextValidateBuildingNumber(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.BuildingNumber) { // not required
		return nil
	}

	if err := m.BuildingNumber.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("BuildingNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("BuildingNumber")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) contextValidatePostCode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PostCode) { // not required
		return nil
	}

	if err := m.PostCode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PostCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PostCode")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) contextValidateStreetName(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.StreetName) { // not required
		return nil
	}

	if err := m.StreetName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("StreetName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("StreetName")
		}
		return err
	}

	return nil
}

func (m *OBPostalAddress6) contextValidateTownName(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.TownName) { // not required
		return nil
	}

	if err := m.TownName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("TownName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("TownName")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBPostalAddress6) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBPostalAddress6) UnmarshalBinary(b []byte) error {
	var res OBPostalAddress6
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
