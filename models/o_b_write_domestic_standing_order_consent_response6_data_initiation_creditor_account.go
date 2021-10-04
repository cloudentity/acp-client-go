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

// OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount Identification assigned by an institution to identify an account. This identification is known by the account owner.
//
// swagger:model OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount
type OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount struct {

	// identification
	// Required: true
	Identification *Identification0 `json:"Identification"`

	// The account name is the name or names of the account owner(s) represented at an account level.
	// Note, the account name is not the product name or the nickname of the account.
	// OB: ASPSPs may carry out name validation for Confirmation of Payee, but it is not mandatory.
	// Required: true
	// Max Length: 350
	// Min Length: 1
	Name string `json:"Name"`

	// scheme name
	// Required: true
	SchemeName *OBExternalAccountIdentification4Code `json:"SchemeName"`

	// secondary identification
	SecondaryIdentification SecondaryIdentification `json:"SecondaryIdentification,omitempty"`
}

// Validate validates this o b write domestic standing order consent response6 data initiation creditor account
func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchemeName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSecondaryIdentification(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) validateIdentification(formats strfmt.Registry) error {

	if err := validate.Required("Identification", "body", m.Identification); err != nil {
		return err
	}

	if err := validate.Required("Identification", "body", m.Identification); err != nil {
		return err
	}

	if m.Identification != nil {
		if err := m.Identification.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) validateName(formats strfmt.Registry) error {

	if err := validate.RequiredString("Name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.MinLength("Name", "body", m.Name, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Name", "body", m.Name, 350); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) validateSchemeName(formats strfmt.Registry) error {

	if err := validate.Required("SchemeName", "body", m.SchemeName); err != nil {
		return err
	}

	if err := validate.Required("SchemeName", "body", m.SchemeName); err != nil {
		return err
	}

	if m.SchemeName != nil {
		if err := m.SchemeName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) validateSecondaryIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondaryIdentification) { // not required
		return nil
	}

	if err := m.SecondaryIdentification.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SecondaryIdentification")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write domestic standing order consent response6 data initiation creditor account based on the context it is used
func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateIdentification(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSchemeName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSecondaryIdentification(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) contextValidateIdentification(ctx context.Context, formats strfmt.Registry) error {

	if m.Identification != nil {
		if err := m.Identification.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) contextValidateSchemeName(ctx context.Context, formats strfmt.Registry) error {

	if m.SchemeName != nil {
		if err := m.SchemeName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) contextValidateSecondaryIdentification(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SecondaryIdentification.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SecondaryIdentification")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticStandingOrderConsentResponse6DataInitiationCreditorAccount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
