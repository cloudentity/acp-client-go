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

// OBParty2 o b party2
//
// swagger:model OBParty2
type OBParty2 struct {

	// account role
	AccountRole OBExternalAccountRole1Code `json:"AccountRole,omitempty"`

	// address
	Address []*OBParty2AddressItems0 `json:"Address"`

	// beneficial ownership
	BeneficialOwnership bool `json:"BeneficialOwnership,omitempty"`

	// email address
	EmailAddress EmailAddress `json:"EmailAddress,omitempty"`

	// full legal name
	FullLegalName FullLegalName `json:"FullLegalName,omitempty"`

	// legal structure
	LegalStructure OBExternalLegalStructureType1Code `json:"LegalStructure,omitempty"`

	// mobile
	Mobile PhoneNumber1 `json:"Mobile,omitempty"`

	// name
	Name Name3 `json:"Name,omitempty"`

	// party Id
	// Required: true
	PartyID *PartyID `json:"PartyId"`

	// party number
	PartyNumber PartyNumber `json:"PartyNumber,omitempty"`

	// party type
	PartyType OBExternalPartyType1Code `json:"PartyType,omitempty"`

	// phone
	Phone PhoneNumber0 `json:"Phone,omitempty"`

	// relationships
	Relationships *OBPartyRelationships1 `json:"Relationships,omitempty"`
}

// Validate validates this o b party2
func (m *OBParty2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountRole(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEmailAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFullLegalName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLegalStructure(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMobile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePartyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePartyNumber(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePartyType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePhone(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRelationships(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBParty2) validateAccountRole(formats strfmt.Registry) error {
	if swag.IsZero(m.AccountRole) { // not required
		return nil
	}

	if err := m.AccountRole.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("AccountRole")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("AccountRole")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.Address) { // not required
		return nil
	}

	for i := 0; i < len(m.Address); i++ {
		if swag.IsZero(m.Address[i]) { // not required
			continue
		}

		if m.Address[i] != nil {
			if err := m.Address[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Address" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *OBParty2) validateEmailAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.EmailAddress) { // not required
		return nil
	}

	if err := m.EmailAddress.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("EmailAddress")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("EmailAddress")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateFullLegalName(formats strfmt.Registry) error {
	if swag.IsZero(m.FullLegalName) { // not required
		return nil
	}

	if err := m.FullLegalName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("FullLegalName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("FullLegalName")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateLegalStructure(formats strfmt.Registry) error {
	if swag.IsZero(m.LegalStructure) { // not required
		return nil
	}

	if err := m.LegalStructure.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LegalStructure")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LegalStructure")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateMobile(formats strfmt.Registry) error {
	if swag.IsZero(m.Mobile) { // not required
		return nil
	}

	if err := m.Mobile.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Mobile")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Mobile")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := m.Name.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Name")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Name")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validatePartyID(formats strfmt.Registry) error {

	if err := validate.Required("PartyId", "body", m.PartyID); err != nil {
		return err
	}

	if err := validate.Required("PartyId", "body", m.PartyID); err != nil {
		return err
	}

	if m.PartyID != nil {
		if err := m.PartyID.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PartyId")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PartyId")
			}
			return err
		}
	}

	return nil
}

func (m *OBParty2) validatePartyNumber(formats strfmt.Registry) error {
	if swag.IsZero(m.PartyNumber) { // not required
		return nil
	}

	if err := m.PartyNumber.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PartyNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PartyNumber")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validatePartyType(formats strfmt.Registry) error {
	if swag.IsZero(m.PartyType) { // not required
		return nil
	}

	if err := m.PartyType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PartyType")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PartyType")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validatePhone(formats strfmt.Registry) error {
	if swag.IsZero(m.Phone) { // not required
		return nil
	}

	if err := m.Phone.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Phone")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Phone")
		}
		return err
	}

	return nil
}

func (m *OBParty2) validateRelationships(formats strfmt.Registry) error {
	if swag.IsZero(m.Relationships) { // not required
		return nil
	}

	if m.Relationships != nil {
		if err := m.Relationships.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Relationships")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Relationships")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b party2 based on the context it is used
func (m *OBParty2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountRole(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEmailAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFullLegalName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLegalStructure(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMobile(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePartyID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePartyNumber(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePartyType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePhone(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRelationships(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBParty2) contextValidateAccountRole(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.AccountRole) { // not required
		return nil
	}

	if err := m.AccountRole.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("AccountRole")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("AccountRole")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateAddress(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Address); i++ {

		if m.Address[i] != nil {

			if swag.IsZero(m.Address[i]) { // not required
				return nil
			}

			if err := m.Address[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Address" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Address" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *OBParty2) contextValidateEmailAddress(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.EmailAddress) { // not required
		return nil
	}

	if err := m.EmailAddress.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("EmailAddress")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("EmailAddress")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateFullLegalName(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.FullLegalName) { // not required
		return nil
	}

	if err := m.FullLegalName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("FullLegalName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("FullLegalName")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateLegalStructure(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.LegalStructure) { // not required
		return nil
	}

	if err := m.LegalStructure.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LegalStructure")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LegalStructure")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateMobile(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Mobile) { // not required
		return nil
	}

	if err := m.Mobile.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Mobile")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Mobile")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateName(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := m.Name.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Name")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Name")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidatePartyID(ctx context.Context, formats strfmt.Registry) error {

	if m.PartyID != nil {

		if err := m.PartyID.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PartyId")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PartyId")
			}
			return err
		}
	}

	return nil
}

func (m *OBParty2) contextValidatePartyNumber(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PartyNumber) { // not required
		return nil
	}

	if err := m.PartyNumber.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PartyNumber")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PartyNumber")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidatePartyType(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PartyType) { // not required
		return nil
	}

	if err := m.PartyType.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PartyType")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PartyType")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidatePhone(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Phone) { // not required
		return nil
	}

	if err := m.Phone.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Phone")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Phone")
		}
		return err
	}

	return nil
}

func (m *OBParty2) contextValidateRelationships(ctx context.Context, formats strfmt.Registry) error {

	if m.Relationships != nil {

		if swag.IsZero(m.Relationships) { // not required
			return nil
		}

		if err := m.Relationships.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Relationships")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Relationships")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBParty2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBParty2) UnmarshalBinary(b []byte) error {
	var res OBParty2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBParty2AddressItems0 Postal address of a party.
//
// swagger:model OBParty2AddressItems0
type OBParty2AddressItems0 struct {

	// address line
	// Max Items: 5
	AddressLine []string `json:"AddressLine"`

	// address type
	AddressType OBAddressTypeCode `json:"AddressType,omitempty"`

	// building number
	BuildingNumber BuildingNumber `json:"BuildingNumber,omitempty"`

	// country
	// Required: true
	Country *CountryCode `json:"Country"`

	// country sub division
	CountrySubDivision CountrySubDivision `json:"CountrySubDivision,omitempty"`

	// post code
	PostCode PostCode `json:"PostCode,omitempty"`

	// street name
	StreetName StreetName `json:"StreetName,omitempty"`

	// town name
	TownName TownName `json:"TownName,omitempty"`
}

// Validate validates this o b party2 address items0
func (m *OBParty2AddressItems0) Validate(formats strfmt.Registry) error {
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

func (m *OBParty2AddressItems0) validateAddressLine(formats strfmt.Registry) error {
	if swag.IsZero(m.AddressLine) { // not required
		return nil
	}

	iAddressLineSize := int64(len(m.AddressLine))

	if err := validate.MaxItems("AddressLine", "body", iAddressLineSize, 5); err != nil {
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

func (m *OBParty2AddressItems0) validateAddressType(formats strfmt.Registry) error {
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

func (m *OBParty2AddressItems0) validateBuildingNumber(formats strfmt.Registry) error {
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

func (m *OBParty2AddressItems0) validateCountry(formats strfmt.Registry) error {

	if err := validate.Required("Country", "body", m.Country); err != nil {
		return err
	}

	if err := validate.Required("Country", "body", m.Country); err != nil {
		return err
	}

	if m.Country != nil {
		if err := m.Country.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Country")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Country")
			}
			return err
		}
	}

	return nil
}

func (m *OBParty2AddressItems0) validateCountrySubDivision(formats strfmt.Registry) error {
	if swag.IsZero(m.CountrySubDivision) { // not required
		return nil
	}

	if err := m.CountrySubDivision.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("CountrySubDivision")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("CountrySubDivision")
		}
		return err
	}

	return nil
}

func (m *OBParty2AddressItems0) validatePostCode(formats strfmt.Registry) error {
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

func (m *OBParty2AddressItems0) validateStreetName(formats strfmt.Registry) error {
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

func (m *OBParty2AddressItems0) validateTownName(formats strfmt.Registry) error {
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

// ContextValidate validate this o b party2 address items0 based on the context it is used
func (m *OBParty2AddressItems0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAddressType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBuildingNumber(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCountry(ctx, formats); err != nil {
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

func (m *OBParty2AddressItems0) contextValidateAddressType(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBParty2AddressItems0) contextValidateBuildingNumber(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBParty2AddressItems0) contextValidateCountry(ctx context.Context, formats strfmt.Registry) error {

	if m.Country != nil {

		if err := m.Country.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Country")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Country")
			}
			return err
		}
	}

	return nil
}

func (m *OBParty2AddressItems0) contextValidateCountrySubDivision(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.CountrySubDivision) { // not required
		return nil
	}

	if err := m.CountrySubDivision.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("CountrySubDivision")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("CountrySubDivision")
		}
		return err
	}

	return nil
}

func (m *OBParty2AddressItems0) contextValidatePostCode(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBParty2AddressItems0) contextValidateStreetName(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBParty2AddressItems0) contextValidateTownName(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OBParty2AddressItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBParty2AddressItems0) UnmarshalBinary(b []byte) error {
	var res OBParty2AddressItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
