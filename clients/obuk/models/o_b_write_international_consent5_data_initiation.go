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

// OBWriteInternationalConsent5DataInitiation OBWriteInternationalConsent5DataInitiation The Initiation payload is sent by the initiating party to the ASPSP. It is used to request movement of funds from the debtor account to a creditor for a single international payment.
//
// swagger:model OBWriteInternationalConsent5DataInitiation
type OBWriteInternationalConsent5DataInitiation struct {

	// charge bearer
	ChargeBearer OBChargeBearerType1Code `json:"ChargeBearer,omitempty"`

	// creditor
	Creditor *OBWriteInternationalConsent5DataInitiationCreditor `json:"Creditor,omitempty"`

	// creditor account
	// Required: true
	CreditorAccount *OBWriteInternationalConsent5DataInitiationCreditorAccount `json:"CreditorAccount"`

	// creditor agent
	CreditorAgent *OBWriteInternationalConsent5DataInitiationCreditorAgent `json:"CreditorAgent,omitempty"`

	// Specifies the currency of the to be transferred amount, which is different from the currency of the debtor's account.
	// Required: true
	// Pattern: ^[A-Z]{3,3}$
	CurrencyOfTransfer string `json:"CurrencyOfTransfer"`

	// debtor account
	DebtorAccount *OBWriteInternationalConsent5DataInitiationDebtorAccount `json:"DebtorAccount,omitempty"`

	// Country in which Credit Account is domiciled. Code to identify a country, a dependency, or another area of particular geopolitical interest, on the basis of country names obtained from the United Nations (ISO 3166, Alpha-2 code).
	// Pattern: [A-Z]{2,2}
	DestinationCountryCode string `json:"DestinationCountryCode,omitempty"`

	// Unique identification assigned by the initiating party to unambiguously identify the transaction. This identification is passed on, unchanged, throughout the entire end-to-end chain.
	// Usage: The end-to-end identification can be used for reconciliation or to link tasks relating to the transaction. It can be included in several messages related to the transaction.
	// OB: The Faster Payments Scheme can only access 31 characters for the EndToEndIdentification field.
	// Required: true
	// Max Length: 35
	// Min Length: 1
	EndToEndIdentification string `json:"EndToEndIdentification"`

	// exchange rate information
	ExchangeRateInformation *OBWriteInternationalConsent5DataInitiationExchangeRateInformation `json:"ExchangeRateInformation,omitempty"`

	// Specifies the purpose of an international payment, when there is no corresponding 4 character code available in the ISO20022 list of Purpose Codes.
	// Max Length: 140
	// Min Length: 1
	ExtendedPurpose string `json:"ExtendedPurpose,omitempty"`

	// instructed amount
	// Required: true
	InstructedAmount *OBWriteInternationalConsent5DataInitiationInstructedAmount `json:"InstructedAmount"`

	// Unique identification as assigned by an instructing party for an instructed party to unambiguously identify the instruction.
	// Usage: the  instruction identification is a point to point reference that can be used between the instructing party and the instructed party to refer to the individual instruction. It can be included in several messages related to the instruction.
	// Required: true
	// Max Length: 35
	// Min Length: 1
	InstructionIdentification string `json:"InstructionIdentification"`

	// Indicator of the urgency or order of importance that the instructing party would like the instructed party to apply to the processing of the instruction.
	// Enum: [Normal Urgent]
	InstructionPriority string `json:"InstructionPriority,omitempty"`

	// local instrument
	LocalInstrument OBExternalLocalInstrument1Code `json:"LocalInstrument,omitempty"`

	// Specifies the external purpose code in the format of character string with a maximum length of 4 characters.
	// The list of valid codes is an external code list published separately.
	// External code sets can be downloaded from www.iso20022.org.
	// Max Length: 4
	// Min Length: 1
	Purpose string `json:"Purpose,omitempty"`

	// remittance information
	RemittanceInformation *OBWriteInternationalConsent5DataInitiationRemittanceInformation `json:"RemittanceInformation,omitempty"`

	// supplementary data
	SupplementaryData OBSupplementaryData1 `json:"SupplementaryData,omitempty"`
}

// Validate validates this o b write international consent5 data initiation
func (m *OBWriteInternationalConsent5DataInitiation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateChargeBearer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditorAgent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurrencyOfTransfer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDebtorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDestinationCountryCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndToEndIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExchangeRateInformation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExtendedPurpose(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructedAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructionIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructionPriority(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocalInstrument(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePurpose(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemittanceInformation(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateChargeBearer(formats strfmt.Registry) error {
	if swag.IsZero(m.ChargeBearer) { // not required
		return nil
	}

	if err := m.ChargeBearer.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("ChargeBearer")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("ChargeBearer")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateCreditor(formats strfmt.Registry) error {
	if swag.IsZero(m.Creditor) { // not required
		return nil
	}

	if m.Creditor != nil {
		if err := m.Creditor.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Creditor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Creditor")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateCreditorAccount(formats strfmt.Registry) error {

	if err := validate.Required("CreditorAccount", "body", m.CreditorAccount); err != nil {
		return err
	}

	if m.CreditorAccount != nil {
		if err := m.CreditorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateCreditorAgent(formats strfmt.Registry) error {
	if swag.IsZero(m.CreditorAgent) { // not required
		return nil
	}

	if m.CreditorAgent != nil {
		if err := m.CreditorAgent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAgent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditorAgent")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateCurrencyOfTransfer(formats strfmt.Registry) error {

	if err := validate.RequiredString("CurrencyOfTransfer", "body", m.CurrencyOfTransfer); err != nil {
		return err
	}

	if err := validate.Pattern("CurrencyOfTransfer", "body", m.CurrencyOfTransfer, `^[A-Z]{3,3}$`); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateDebtorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if m.DebtorAccount != nil {
		if err := m.DebtorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DebtorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DebtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateDestinationCountryCode(formats strfmt.Registry) error {
	if swag.IsZero(m.DestinationCountryCode) { // not required
		return nil
	}

	if err := validate.Pattern("DestinationCountryCode", "body", m.DestinationCountryCode, `[A-Z]{2,2}`); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateEndToEndIdentification(formats strfmt.Registry) error {

	if err := validate.RequiredString("EndToEndIdentification", "body", m.EndToEndIdentification); err != nil {
		return err
	}

	if err := validate.MinLength("EndToEndIdentification", "body", m.EndToEndIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("EndToEndIdentification", "body", m.EndToEndIdentification, 35); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateExchangeRateInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.ExchangeRateInformation) { // not required
		return nil
	}

	if m.ExchangeRateInformation != nil {
		if err := m.ExchangeRateInformation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ExchangeRateInformation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ExchangeRateInformation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateExtendedPurpose(formats strfmt.Registry) error {
	if swag.IsZero(m.ExtendedPurpose) { // not required
		return nil
	}

	if err := validate.MinLength("ExtendedPurpose", "body", m.ExtendedPurpose, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("ExtendedPurpose", "body", m.ExtendedPurpose, 140); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateInstructedAmount(formats strfmt.Registry) error {

	if err := validate.Required("InstructedAmount", "body", m.InstructedAmount); err != nil {
		return err
	}

	if m.InstructedAmount != nil {
		if err := m.InstructedAmount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("InstructedAmount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("InstructedAmount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateInstructionIdentification(formats strfmt.Registry) error {

	if err := validate.RequiredString("InstructionIdentification", "body", m.InstructionIdentification); err != nil {
		return err
	}

	if err := validate.MinLength("InstructionIdentification", "body", m.InstructionIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("InstructionIdentification", "body", m.InstructionIdentification, 35); err != nil {
		return err
	}

	return nil
}

var oBWriteInternationalConsent5DataInitiationTypeInstructionPriorityPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Normal","Urgent"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalConsent5DataInitiationTypeInstructionPriorityPropEnum = append(oBWriteInternationalConsent5DataInitiationTypeInstructionPriorityPropEnum, v)
	}
}

const (

	// OBWriteInternationalConsent5DataInitiationInstructionPriorityNormal captures enum value "Normal"
	OBWriteInternationalConsent5DataInitiationInstructionPriorityNormal string = "Normal"

	// OBWriteInternationalConsent5DataInitiationInstructionPriorityUrgent captures enum value "Urgent"
	OBWriteInternationalConsent5DataInitiationInstructionPriorityUrgent string = "Urgent"
)

// prop value enum
func (m *OBWriteInternationalConsent5DataInitiation) validateInstructionPriorityEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalConsent5DataInitiationTypeInstructionPriorityPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateInstructionPriority(formats strfmt.Registry) error {
	if swag.IsZero(m.InstructionPriority) { // not required
		return nil
	}

	// value enum
	if err := m.validateInstructionPriorityEnum("InstructionPriority", "body", m.InstructionPriority); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateLocalInstrument(formats strfmt.Registry) error {
	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LocalInstrument")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validatePurpose(formats strfmt.Registry) error {
	if swag.IsZero(m.Purpose) { // not required
		return nil
	}

	if err := validate.MinLength("Purpose", "body", m.Purpose, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Purpose", "body", m.Purpose, 4); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) validateRemittanceInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.RemittanceInformation) { // not required
		return nil
	}

	if m.RemittanceInformation != nil {
		if err := m.RemittanceInformation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RemittanceInformation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("RemittanceInformation")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b write international consent5 data initiation based on the context it is used
func (m *OBWriteInternationalConsent5DataInitiation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateChargeBearer(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditor(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditorAgent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateExchangeRateInformation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInstructedAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLocalInstrument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemittanceInformation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateChargeBearer(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.ChargeBearer) { // not required
		return nil
	}

	if err := m.ChargeBearer.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("ChargeBearer")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("ChargeBearer")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateCreditor(ctx context.Context, formats strfmt.Registry) error {

	if m.Creditor != nil {

		if swag.IsZero(m.Creditor) { // not required
			return nil
		}

		if err := m.Creditor.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Creditor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Creditor")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateCreditorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorAccount != nil {

		if err := m.CreditorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateCreditorAgent(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorAgent != nil {

		if swag.IsZero(m.CreditorAgent) { // not required
			return nil
		}

		if err := m.CreditorAgent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreditorAgent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CreditorAgent")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.DebtorAccount != nil {

		if swag.IsZero(m.DebtorAccount) { // not required
			return nil
		}

		if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DebtorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DebtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateExchangeRateInformation(ctx context.Context, formats strfmt.Registry) error {

	if m.ExchangeRateInformation != nil {

		if swag.IsZero(m.ExchangeRateInformation) { // not required
			return nil
		}

		if err := m.ExchangeRateInformation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ExchangeRateInformation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ExchangeRateInformation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateInstructedAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.InstructedAmount != nil {

		if err := m.InstructedAmount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("InstructedAmount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("InstructedAmount")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateLocalInstrument(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LocalInstrument")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsent5DataInitiation) contextValidateRemittanceInformation(ctx context.Context, formats strfmt.Registry) error {

	if m.RemittanceInformation != nil {

		if swag.IsZero(m.RemittanceInformation) { // not required
			return nil
		}

		if err := m.RemittanceInformation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RemittanceInformation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("RemittanceInformation")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalConsent5DataInitiation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalConsent5DataInitiation) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalConsent5DataInitiation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
