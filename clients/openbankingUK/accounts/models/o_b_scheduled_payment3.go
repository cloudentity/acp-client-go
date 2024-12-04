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

// OBScheduledPayment3 o b scheduled payment3
//
// swagger:model OBScheduledPayment3
type OBScheduledPayment3 struct {

	// account Id
	// Required: true
	AccountID *AccountID `json:"AccountId"`

	// creditor account
	CreditorAccount *OBCashAccount51 `json:"CreditorAccount,omitempty"`

	// creditor agent
	CreditorAgent *OBBranchAndFinancialInstitutionIdentification51 `json:"CreditorAgent,omitempty"`

	// debtor reference
	DebtorReference DebtorReference `json:"DebtorReference,omitempty"`

	// instructed amount
	// Required: true
	InstructedAmount *OBActiveOrHistoricCurrencyAndAmount1 `json:"InstructedAmount"`

	// reference
	Reference Reference `json:"Reference,omitempty"`

	// scheduled payment date time
	// Required: true
	// Format: date-time
	ScheduledPaymentDateTime *ScheduledPaymentDateTime `json:"ScheduledPaymentDateTime"`

	// scheduled payment Id
	ScheduledPaymentID ScheduledPaymentID `json:"ScheduledPaymentId,omitempty"`

	// scheduled type
	// Required: true
	ScheduledType *OBExternalScheduleType1Code `json:"ScheduledType"`
}

// Validate validates this o b scheduled payment3
func (m *OBScheduledPayment3) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditorAgent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDebtorReference(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstructedAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReference(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScheduledPaymentDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScheduledPaymentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScheduledType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBScheduledPayment3) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("AccountId", "body", m.AccountID); err != nil {
		return err
	}

	if err := validate.Required("AccountId", "body", m.AccountID); err != nil {
		return err
	}

	if m.AccountID != nil {
		if err := m.AccountID.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountId")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountId")
			}
			return err
		}
	}

	return nil
}

func (m *OBScheduledPayment3) validateCreditorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.CreditorAccount) { // not required
		return nil
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

func (m *OBScheduledPayment3) validateCreditorAgent(formats strfmt.Registry) error {
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

func (m *OBScheduledPayment3) validateDebtorReference(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorReference) { // not required
		return nil
	}

	if err := m.DebtorReference.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DebtorReference")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DebtorReference")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) validateInstructedAmount(formats strfmt.Registry) error {

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

func (m *OBScheduledPayment3) validateReference(formats strfmt.Registry) error {
	if swag.IsZero(m.Reference) { // not required
		return nil
	}

	if err := m.Reference.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Reference")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Reference")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) validateScheduledPaymentDateTime(formats strfmt.Registry) error {

	if err := validate.Required("ScheduledPaymentDateTime", "body", m.ScheduledPaymentDateTime); err != nil {
		return err
	}

	if err := validate.Required("ScheduledPaymentDateTime", "body", m.ScheduledPaymentDateTime); err != nil {
		return err
	}

	if m.ScheduledPaymentDateTime != nil {
		if err := m.ScheduledPaymentDateTime.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ScheduledPaymentDateTime")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ScheduledPaymentDateTime")
			}
			return err
		}
	}

	return nil
}

func (m *OBScheduledPayment3) validateScheduledPaymentID(formats strfmt.Registry) error {
	if swag.IsZero(m.ScheduledPaymentID) { // not required
		return nil
	}

	if err := m.ScheduledPaymentID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("ScheduledPaymentId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("ScheduledPaymentId")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) validateScheduledType(formats strfmt.Registry) error {

	if err := validate.Required("ScheduledType", "body", m.ScheduledType); err != nil {
		return err
	}

	if err := validate.Required("ScheduledType", "body", m.ScheduledType); err != nil {
		return err
	}

	if m.ScheduledType != nil {
		if err := m.ScheduledType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ScheduledType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ScheduledType")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b scheduled payment3 based on the context it is used
func (m *OBScheduledPayment3) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditorAgent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtorReference(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInstructedAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateReference(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScheduledPaymentDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScheduledPaymentID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScheduledType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBScheduledPayment3) contextValidateAccountID(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountID != nil {

		if err := m.AccountID.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountId")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountId")
			}
			return err
		}
	}

	return nil
}

func (m *OBScheduledPayment3) contextValidateCreditorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorAccount != nil {

		if swag.IsZero(m.CreditorAccount) { // not required
			return nil
		}

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

func (m *OBScheduledPayment3) contextValidateCreditorAgent(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBScheduledPayment3) contextValidateDebtorReference(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.DebtorReference) { // not required
		return nil
	}

	if err := m.DebtorReference.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DebtorReference")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DebtorReference")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) contextValidateInstructedAmount(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBScheduledPayment3) contextValidateReference(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Reference) { // not required
		return nil
	}

	if err := m.Reference.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Reference")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Reference")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) contextValidateScheduledPaymentDateTime(ctx context.Context, formats strfmt.Registry) error {

	if m.ScheduledPaymentDateTime != nil {

		if err := m.ScheduledPaymentDateTime.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ScheduledPaymentDateTime")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ScheduledPaymentDateTime")
			}
			return err
		}
	}

	return nil
}

func (m *OBScheduledPayment3) contextValidateScheduledPaymentID(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.ScheduledPaymentID) { // not required
		return nil
	}

	if err := m.ScheduledPaymentID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("ScheduledPaymentId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("ScheduledPaymentId")
		}
		return err
	}

	return nil
}

func (m *OBScheduledPayment3) contextValidateScheduledType(ctx context.Context, formats strfmt.Registry) error {

	if m.ScheduledType != nil {

		if err := m.ScheduledType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ScheduledType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ScheduledType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBScheduledPayment3) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBScheduledPayment3) UnmarshalBinary(b []byte) error {
	var res OBScheduledPayment3
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
