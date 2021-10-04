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

// OBWriteFileConsentResponse4DataInitiation OBWriteFileConsentResponse4DataInitiation The Initiation payload is sent by the initiating party to the ASPSP. It is used to request movement of funds using a payment file.
//
// swagger:model OBWriteFileConsentResponse4DataInitiation
type OBWriteFileConsentResponse4DataInitiation struct {

	// Total of all individual amounts included in the group, irrespective of currencies.
	ControlSum float64 `json:"ControlSum,omitempty"`

	// debtor account
	DebtorAccount *OBWriteFileConsentResponse4DataInitiationDebtorAccount `json:"DebtorAccount,omitempty"`

	// A base64 encoding of a SHA256 hash of the file to be uploaded.
	// Required: true
	// Max Length: 44
	// Min Length: 1
	FileHash string `json:"FileHash"`

	// Reference for the file.
	// Max Length: 40
	// Min Length: 1
	FileReference string `json:"FileReference,omitempty"`

	// Specifies the payment file type.
	// Required: true
	FileType string `json:"FileType"`

	// local instrument
	LocalInstrument OBExternalLocalInstrument1Code `json:"LocalInstrument,omitempty"`

	// Number of individual transactions contained in the payment information group.
	// Pattern: [0-9]{1,15}
	NumberOfTransactions string `json:"NumberOfTransactions,omitempty"`

	// remittance information
	RemittanceInformation *OBWriteFileConsentResponse4DataInitiationRemittanceInformation `json:"RemittanceInformation,omitempty"`

	// Date at which the initiating party requests the clearing agent to process the payment.
	// Usage: This is the date on which the debtor's account is to be debited.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	RequestedExecutionDateTime strfmt.DateTime `json:"RequestedExecutionDateTime,omitempty"`

	// supplementary data
	SupplementaryData OBSupplementaryData1 `json:"SupplementaryData,omitempty"`
}

// Validate validates this o b write file consent response4 data initiation
func (m *OBWriteFileConsentResponse4DataInitiation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDebtorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFileHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFileReference(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFileType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocalInstrument(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNumberOfTransactions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemittanceInformation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedExecutionDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateDebtorAccount(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsentResponse4DataInitiation) validateFileHash(formats strfmt.Registry) error {

	if err := validate.RequiredString("FileHash", "body", m.FileHash); err != nil {
		return err
	}

	if err := validate.MinLength("FileHash", "body", m.FileHash, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("FileHash", "body", m.FileHash, 44); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateFileReference(formats strfmt.Registry) error {
	if swag.IsZero(m.FileReference) { // not required
		return nil
	}

	if err := validate.MinLength("FileReference", "body", m.FileReference, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("FileReference", "body", m.FileReference, 40); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateFileType(formats strfmt.Registry) error {

	if err := validate.RequiredString("FileType", "body", m.FileType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateLocalInstrument(formats strfmt.Registry) error {
	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateNumberOfTransactions(formats strfmt.Registry) error {
	if swag.IsZero(m.NumberOfTransactions) { // not required
		return nil
	}

	if err := validate.Pattern("NumberOfTransactions", "body", m.NumberOfTransactions, `[0-9]{1,15}`); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) validateRemittanceInformation(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsentResponse4DataInitiation) validateRequestedExecutionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedExecutionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("RequestedExecutionDateTime", "body", "date-time", m.RequestedExecutionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this o b write file consent response4 data initiation based on the context it is used
func (m *OBWriteFileConsentResponse4DataInitiation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
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

func (m *OBWriteFileConsentResponse4DataInitiation) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OBWriteFileConsentResponse4DataInitiation) contextValidateLocalInstrument(ctx context.Context, formats strfmt.Registry) error {

	if err := m.LocalInstrument.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsentResponse4DataInitiation) contextValidateRemittanceInformation(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *OBWriteFileConsentResponse4DataInitiation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsentResponse4DataInitiation) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsentResponse4DataInitiation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
