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

// OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent Party that manages the account on behalf of the account owner, that is manages the registration and booking of entries on the account, calculates balances on the account and provides information about the account.
//
// This is the servicer of the beneficiary account.
//
// swagger:model OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent
type OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent struct {

	// Unique and unambiguous identification of the servicing institution.
	// Max Length: 35
	// Min Length: 1
	Identification string `json:"Identification,omitempty"`

	// name
	Name *Name `json:"Name,omitempty"`

	// postal address
	PostalAddress *OBPostalAddress6 `json:"PostalAddress,omitempty"`

	// scheme name
	SchemeName OBExternalFinancialInstitutionIdentification4Code `json:"SchemeName,omitempty"`
}

// Validate validates this o b write international standing order consent response7 data initiation creditor agent
func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePostalAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchemeName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) validateIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.Identification) { // not required
		return nil
	}

	if err := validate.MinLength("Identification", "body", m.Identification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Identification", "body", m.Identification, 35); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if m.Name != nil {
		if err := m.Name.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Name")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Name")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) validatePostalAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.PostalAddress) { // not required
		return nil
	}

	if m.PostalAddress != nil {
		if err := m.PostalAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) validateSchemeName(formats strfmt.Registry) error {
	if swag.IsZero(m.SchemeName) { // not required
		return nil
	}

	if err := m.SchemeName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SchemeName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("SchemeName")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write international standing order consent response7 data initiation creditor agent based on the context it is used
func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePostalAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSchemeName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) contextValidateName(ctx context.Context, formats strfmt.Registry) error {

	if m.Name != nil {
		if err := m.Name.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Name")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Name")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) contextValidatePostalAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.PostalAddress != nil {
		if err := m.PostalAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) contextValidateSchemeName(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SchemeName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SchemeName")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("SchemeName")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsentResponse7DataInitiationCreditorAgent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
