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

// DomesticPaymentConsentDataInitiation DomesticPaymentConsentDataInitiation The Initiation payload is sent by the initiating party
// to the ASPSP. It is used to request movement of funds from the debtor account to a creditor
// for a single domestic payment.
//
// swagger:model DomesticPaymentConsentDataInitiation
type DomesticPaymentConsentDataInitiation struct {

	// creditor account
	// Required: true
	CreditorAccount *DomesticPaymentConsentCreditorAccount `json:"CreditorAccount"`

	// creditor postal address
	CreditorPostalAddress *PostalAddress `json:"CreditorPostalAddress,omitempty"`

	// debtor account
	DebtorAccount *DomesticPaymentConsentDebtorAccount `json:"DebtorAccount,omitempty"`

	// Unique identification assigned by the initiating party to unambiguously identify the transaction. This identification is passed on, unchanged, throughout the entire end-to-end chain.
	// Usage: The end-to-end identification can be used for reconciliation or to link tasks relating to the transaction. It can be included in several messages related to the transaction.
	// OB: The Faster Payments Scheme can only access 31 characters for the EndToEndIdentification field.
	// Required: true
	// Max Length: 35
	// Min Length: 1
	EndToEndIdentification *string `json:"EndToEndIdentification"`

	// instructed amount
	// Required: true
	InstructedAmount *DomesticPaymentConsentInstructedAmount `json:"InstructedAmount"`

	// Unique identification as assigned by an instructing party for an instructed party to unambiguously identify the instruction.
	// Usage: the  instruction identification is a point to point reference that can be used between the instructing party and the instructed party to refer to the individual instruction. It can be included in several messages related to the instruction.
	// Required: true
	// Max Length: 35
	// Min Length: 1
	InstructionIdentification *string `json:"InstructionIdentification"`

	// local instrument
	LocalInstrument string `json:"LocalInstrument,omitempty"`

	// remittance information
	RemittanceInformation *DomesticPaymentConsentRemittanceInformation `json:"RemittanceInformation,omitempty"`

	// supplementary data
	SupplementaryData SupplementaryData `json:"SupplementaryData,omitempty"`
}

// Validate validates this domestic payment consent data initiation
func (m *DomesticPaymentConsentDataInitiation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreditorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditorPostalAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDebtorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndToEndIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructedAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructionIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemittanceInformation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSupplementaryData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateCreditorAccount(formats strfmt.Registry) error {

	if err := validate.Required("CreditorAccount", "body", m.CreditorAccount); err != nil {
		return err
	}

	if m.CreditorAccount != nil {
		if err := m.CreditorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateCreditorPostalAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.CreditorPostalAddress) { // not required
		return nil
	}

	if m.CreditorPostalAddress != nil {
		if err := m.CreditorPostalAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorPostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateDebtorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if m.DebtorAccount != nil {
		if err := m.DebtorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DebtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateEndToEndIdentification(formats strfmt.Registry) error {

	if err := validate.Required("EndToEndIdentification", "body", m.EndToEndIdentification); err != nil {
		return err
	}

	if err := validate.MinLength("EndToEndIdentification", "body", *m.EndToEndIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("EndToEndIdentification", "body", *m.EndToEndIdentification, 35); err != nil {
		return err
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateInstructedAmount(formats strfmt.Registry) error {

	if err := validate.Required("InstructedAmount", "body", m.InstructedAmount); err != nil {
		return err
	}

	if m.InstructedAmount != nil {
		if err := m.InstructedAmount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("InstructedAmount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateInstructionIdentification(formats strfmt.Registry) error {

	if err := validate.Required("InstructionIdentification", "body", m.InstructionIdentification); err != nil {
		return err
	}

	if err := validate.MinLength("InstructionIdentification", "body", *m.InstructionIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("InstructionIdentification", "body", *m.InstructionIdentification, 35); err != nil {
		return err
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateRemittanceInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.RemittanceInformation) { // not required
		return nil
	}

	if m.RemittanceInformation != nil {
		if err := m.RemittanceInformation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RemittanceInformation")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) validateSupplementaryData(formats strfmt.Registry) error {
	if swag.IsZero(m.SupplementaryData) { // not required
		return nil
	}

	if m.SupplementaryData != nil {
		if err := m.SupplementaryData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SupplementaryData")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domestic payment consent data initiation based on the context it is used
func (m *DomesticPaymentConsentDataInitiation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreditorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditorPostalAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInstructedAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemittanceInformation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSupplementaryData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateCreditorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorAccount != nil {
		if err := m.CreditorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateCreditorPostalAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorPostalAddress != nil {
		if err := m.CreditorPostalAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorPostalAddress")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.DebtorAccount != nil {
		if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DebtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateInstructedAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.InstructedAmount != nil {
		if err := m.InstructedAmount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("InstructedAmount")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateRemittanceInformation(ctx context.Context, formats strfmt.Registry) error {

	if m.RemittanceInformation != nil {
		if err := m.RemittanceInformation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RemittanceInformation")
			}
			return err
		}
	}

	return nil
}

func (m *DomesticPaymentConsentDataInitiation) contextValidateSupplementaryData(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SupplementaryData.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("SupplementaryData")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomesticPaymentConsentDataInitiation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomesticPaymentConsentDataInitiation) UnmarshalBinary(b []byte) error {
	var res DomesticPaymentConsentDataInitiation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
