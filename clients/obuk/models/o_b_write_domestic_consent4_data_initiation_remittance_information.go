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

// OBWriteDomesticConsent4DataInitiationRemittanceInformation OBWriteDomesticConsent4DataInitiationRemittanceInformation Information supplied to enable the matching of an entry with the items that the transfer is intended to settle, such as commercial invoices in an accounts' receivable system.
//
// swagger:model OBWriteDomesticConsent4DataInitiationRemittanceInformation
type OBWriteDomesticConsent4DataInitiationRemittanceInformation struct {

	// Unique reference, as assigned by the creditor, to unambiguously refer to the payment transaction.
	// Usage: If available, the initiating party should provide this reference in the structured remittance information, to enable reconciliation by the creditor upon receipt of the amount of money.
	// If the business context requires the use of a creditor reference or a payment remit identification, and only one identifier can be passed through the end-to-end chain, the creditor's reference or payment remittance identification should be quoted in the end-to-end transaction identification.
	// OB: The Faster Payments Scheme can only accept 18 characters for the ReferenceInformation field - which is where this ISO field will be mapped.
	// Max Length: 35
	// Min Length: 1
	Reference string `json:"Reference,omitempty"`

	// Information supplied to enable the matching/reconciliation of an entry with the items that the payment is intended to settle, such as commercial invoices in an accounts' receivable system, in an unstructured form.
	// Max Length: 140
	// Min Length: 1
	Unstructured string `json:"Unstructured,omitempty"`
}

// Validate validates this o b write domestic consent4 data initiation remittance information
func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateReference(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnstructured(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) validateReference(formats strfmt.Registry) error {
	if swag.IsZero(m.Reference) { // not required
		return nil
	}

	if err := validate.MinLength("Reference", "body", m.Reference, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Reference", "body", m.Reference, 35); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) validateUnstructured(formats strfmt.Registry) error {
	if swag.IsZero(m.Unstructured) { // not required
		return nil
	}

	if err := validate.MinLength("Unstructured", "body", m.Unstructured, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Unstructured", "body", m.Unstructured, 140); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write domestic consent4 data initiation remittance information based on context it is used
func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteDomesticConsent4DataInitiationRemittanceInformation) UnmarshalBinary(b []byte) error {
	var res OBWriteDomesticConsent4DataInitiationRemittanceInformation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
