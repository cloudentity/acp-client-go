// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent Financial institution servicing an account for the creditor.
//
// swagger:model OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent
type OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent struct {

	// identification
	Identification Identification1 `json:"Identification,omitempty"`

	// name
	Name Name `json:"Name,omitempty"`

	// postal address
	PostalAddress *OBPostalAddress6 `json:"PostalAddress,omitempty"`

	// scheme name
	SchemeName OBExternalFinancialInstitutionIdentification4Code `json:"SchemeName,omitempty"`
}

// Validate validates this o b write international scheduled consent response6 data initiation creditor agent
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) validateIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.Identification) { // not required
		return nil
	}

	if err := m.Identification.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Identification")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := m.Name.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Name")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) validatePostalAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.PostalAddress) { // not required
		return nil
	}

	if m.PostalAddress != nil {
		if err := m.PostalAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) validateSchemeName(formats strfmt.Registry) error {
	if swag.IsZero(m.SchemeName) { // not required
		return nil
	}

	if err := m.SchemeName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SchemeName")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write international scheduled consent response6 data initiation creditor agent based on the context it is used
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateIdentification(ctx, formats); err != nil {
		res = append(res, err)
	}

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

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) contextValidateIdentification(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Identification.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Identification")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) contextValidateName(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Name.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Name")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) contextValidatePostalAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.PostalAddress != nil {
		if err := m.PostalAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) contextValidateSchemeName(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SchemeName.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SchemeName")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalScheduledConsentResponse6DataInitiationCreditorAgent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
