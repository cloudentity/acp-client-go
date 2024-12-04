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

// OBReadDirectDebit2 o b read direct debit2
//
// swagger:model OBReadDirectDebit2
type OBReadDirectDebit2 struct {

	// data
	// Required: true
	Data OBReadDirectDebit2Data `json:"Data"`

	// links
	Links *Links `json:"Links,omitempty"`

	// meta
	Meta *Meta `json:"Meta,omitempty"`
}

// Validate validates this o b read direct debit2
func (m *OBReadDirectDebit2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMeta(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2) validateData(formats strfmt.Registry) error {

	if err := m.Data.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2) validateLinks(formats strfmt.Registry) error {
	if swag.IsZero(m.Links) { // not required
		return nil
	}

	if m.Links != nil {
		if err := m.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Links")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2) validateMeta(formats strfmt.Registry) error {
	if swag.IsZero(m.Meta) { // not required
		return nil
	}

	if m.Meta != nil {
		if err := m.Meta.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Meta")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this o b read direct debit2 based on the context it is used
func (m *OBReadDirectDebit2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLinks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMeta(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Data.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2) contextValidateLinks(ctx context.Context, formats strfmt.Registry) error {

	if m.Links != nil {

		if swag.IsZero(m.Links) { // not required
			return nil
		}

		if err := m.Links.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Links")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Links")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2) contextValidateMeta(ctx context.Context, formats strfmt.Registry) error {

	if m.Meta != nil {

		if swag.IsZero(m.Meta) { // not required
			return nil
		}

		if err := m.Meta.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Meta")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBReadDirectDebit2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBReadDirectDebit2) UnmarshalBinary(b []byte) error {
	var res OBReadDirectDebit2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBReadDirectDebit2Data o b read direct debit2 data
//
// swagger:model OBReadDirectDebit2Data
type OBReadDirectDebit2Data struct {

	// direct debit
	DirectDebit []*OBReadDirectDebit2DataDirectDebitItems0 `json:"DirectDebit"`
}

// Validate validates this o b read direct debit2 data
func (m *OBReadDirectDebit2Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDirectDebit(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2Data) validateDirectDebit(formats strfmt.Registry) error {
	if swag.IsZero(m.DirectDebit) { // not required
		return nil
	}

	for i := 0; i < len(m.DirectDebit); i++ {
		if swag.IsZero(m.DirectDebit[i]) { // not required
			continue
		}

		if m.DirectDebit[i] != nil {
			if err := m.DirectDebit[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Data" + "." + "DirectDebit" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Data" + "." + "DirectDebit" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this o b read direct debit2 data based on the context it is used
func (m *OBReadDirectDebit2Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDirectDebit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2Data) contextValidateDirectDebit(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DirectDebit); i++ {

		if m.DirectDebit[i] != nil {

			if swag.IsZero(m.DirectDebit[i]) { // not required
				return nil
			}

			if err := m.DirectDebit[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Data" + "." + "DirectDebit" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Data" + "." + "DirectDebit" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBReadDirectDebit2Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBReadDirectDebit2Data) UnmarshalBinary(b []byte) error {
	var res OBReadDirectDebit2Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBReadDirectDebit2DataDirectDebitItems0 Account to or from which a cash entry is made.
//
// swagger:model OBReadDirectDebit2DataDirectDebitItems0
type OBReadDirectDebit2DataDirectDebitItems0 struct {

	// account Id
	// Required: true
	AccountID *AccountID `json:"AccountId"`

	// direct debit Id
	DirectDebitID DirectDebitID `json:"DirectDebitId,omitempty"`

	// direct debit status code
	DirectDebitStatusCode OBExternalDirectDebitStatus1Code `json:"DirectDebitStatusCode,omitempty"`

	// Regularity with which direct debit instructions are to be created and processed.
	Frequency string `json:"Frequency,omitempty"`

	// mandate identification
	// Required: true
	MandateIdentification *MandateIdentification `json:"MandateIdentification"`

	// name
	// Required: true
	Name *Name2 `json:"Name"`

	// previous payment amount
	PreviousPaymentAmount *OBActiveOrHistoricCurrencyAndAmount0 `json:"PreviousPaymentAmount,omitempty"`

	// previous payment date time
	// Format: date-time
	PreviousPaymentDateTime PreviousPaymentDateTime `json:"PreviousPaymentDateTime,omitempty"`
}

// Validate validates this o b read direct debit2 data direct debit items0
func (m *OBReadDirectDebit2DataDirectDebitItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDirectDebitID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDirectDebitStatusCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMandateIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreviousPaymentAmount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreviousPaymentDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) validateAccountID(formats strfmt.Registry) error {

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

func (m *OBReadDirectDebit2DataDirectDebitItems0) validateDirectDebitID(formats strfmt.Registry) error {
	if swag.IsZero(m.DirectDebitID) { // not required
		return nil
	}

	if err := m.DirectDebitID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DirectDebitId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DirectDebitId")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) validateDirectDebitStatusCode(formats strfmt.Registry) error {
	if swag.IsZero(m.DirectDebitStatusCode) { // not required
		return nil
	}

	if err := m.DirectDebitStatusCode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DirectDebitStatusCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DirectDebitStatusCode")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) validateMandateIdentification(formats strfmt.Registry) error {

	if err := validate.Required("MandateIdentification", "body", m.MandateIdentification); err != nil {
		return err
	}

	if err := validate.Required("MandateIdentification", "body", m.MandateIdentification); err != nil {
		return err
	}

	if m.MandateIdentification != nil {
		if err := m.MandateIdentification.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("MandateIdentification")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("MandateIdentification")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) validateName(formats strfmt.Registry) error {

	if err := validate.Required("Name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.Required("Name", "body", m.Name); err != nil {
		return err
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

func (m *OBReadDirectDebit2DataDirectDebitItems0) validatePreviousPaymentAmount(formats strfmt.Registry) error {
	if swag.IsZero(m.PreviousPaymentAmount) { // not required
		return nil
	}

	if m.PreviousPaymentAmount != nil {
		if err := m.PreviousPaymentAmount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PreviousPaymentAmount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PreviousPaymentAmount")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) validatePreviousPaymentDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.PreviousPaymentDateTime) { // not required
		return nil
	}

	if err := m.PreviousPaymentDateTime.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PreviousPaymentDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PreviousPaymentDateTime")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b read direct debit2 data direct debit items0 based on the context it is used
func (m *OBReadDirectDebit2DataDirectDebitItems0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDirectDebitID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDirectDebitStatusCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMandateIdentification(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePreviousPaymentAmount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePreviousPaymentDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidateAccountID(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidateDirectDebitID(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.DirectDebitID) { // not required
		return nil
	}

	if err := m.DirectDebitID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DirectDebitId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DirectDebitId")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidateDirectDebitStatusCode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.DirectDebitStatusCode) { // not required
		return nil
	}

	if err := m.DirectDebitStatusCode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("DirectDebitStatusCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("DirectDebitStatusCode")
		}
		return err
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidateMandateIdentification(ctx context.Context, formats strfmt.Registry) error {

	if m.MandateIdentification != nil {

		if err := m.MandateIdentification.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("MandateIdentification")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("MandateIdentification")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidateName(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidatePreviousPaymentAmount(ctx context.Context, formats strfmt.Registry) error {

	if m.PreviousPaymentAmount != nil {

		if swag.IsZero(m.PreviousPaymentAmount) { // not required
			return nil
		}

		if err := m.PreviousPaymentAmount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PreviousPaymentAmount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PreviousPaymentAmount")
			}
			return err
		}
	}

	return nil
}

func (m *OBReadDirectDebit2DataDirectDebitItems0) contextValidatePreviousPaymentDateTime(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PreviousPaymentDateTime) { // not required
		return nil
	}

	if err := m.PreviousPaymentDateTime.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("PreviousPaymentDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("PreviousPaymentDateTime")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBReadDirectDebit2DataDirectDebitItems0) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBReadDirectDebit2DataDirectDebitItems0) UnmarshalBinary(b []byte) error {
	var res OBReadDirectDebit2DataDirectDebitItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
