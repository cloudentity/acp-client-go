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

// OBWriteFile2 o b write file2
//
// swagger:model OBWriteFile2
type OBWriteFile2 struct {

	// data
	// Required: true
	Data OBWriteFile2Data `json:"Data"`
}

// Validate validates this o b write file2
func (m *OBWriteFile2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFile2) validateData(formats strfmt.Registry) error {

	if err := m.Data.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write file2 based on the context it is used
func (m *OBWriteFile2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFile2) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Data.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFile2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFile2) UnmarshalBinary(b []byte) error {
	var res OBWriteFile2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFile2Data o b write file2 data
//
// swagger:model OBWriteFile2Data
type OBWriteFile2Data struct {

	// OB: Unique identification as assigned by the ASPSP to uniquely identify the consent resource.
	// Required: true
	// Max Length: 128
	// Min Length: 1
	ConsentID string `json:"ConsentId"`

	// initiation
	// Required: true
	Initiation OBWriteFile2DataInitiation `json:"Initiation"`
}

// Validate validates this o b write file2 data
func (m *OBWriteFile2Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFile2Data) validateConsentID(formats strfmt.Registry) error {

	if err := validate.RequiredString("Data"+"."+"ConsentId", "body", m.ConsentID); err != nil {
		return err
	}

	if err := validate.MinLength("Data"+"."+"ConsentId", "body", m.ConsentID, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"ConsentId", "body", m.ConsentID, 128); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2Data) validateInitiation(formats strfmt.Registry) error {

	if err := m.Initiation.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write file2 data based on the context it is used
func (m *OBWriteFile2Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateInitiation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFile2Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFile2Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFile2Data) UnmarshalBinary(b []byte) error {
	var res OBWriteFile2Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFile2DataInitiation The Initiation payload is sent by the initiating party to the ASPSP. It is used to request movement of funds using a payment file.
//
// swagger:model OBWriteFile2DataInitiation
type OBWriteFile2DataInitiation struct {

	// Total of all individual amounts included in the group, irrespective of currencies.
	ControlSum float64 `json:"ControlSum,omitempty"`

	// debtor account
	DebtorAccount OBWriteFile2DataInitiationDebtorAccount `json:"DebtorAccount,omitempty"`

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
	RemittanceInformation OBWriteFile2DataInitiationRemittanceInformation `json:"RemittanceInformation,omitempty"`

	// Date at which the initiating party requests the clearing agent to process the payment.
	// Usage: This is the date on which the debtor's account is to be debited.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	RequestedExecutionDateTime strfmt.DateTime `json:"RequestedExecutionDateTime,omitempty"`

	// supplementary data
	SupplementaryData OBSupplementaryData1 `json:"SupplementaryData,omitempty"`
}

// Validate validates this o b write file2 data initiation
func (m *OBWriteFile2DataInitiation) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFile2DataInitiation) validateDebtorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if err := m.DebtorAccount.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		}
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateFileHash(formats strfmt.Registry) error {

	if err := validate.RequiredString("Data"+"."+"Initiation"+"."+"FileHash", "body", m.FileHash); err != nil {
		return err
	}

	if err := validate.MinLength("Data"+"."+"Initiation"+"."+"FileHash", "body", m.FileHash, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"Initiation"+"."+"FileHash", "body", m.FileHash, 44); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateFileReference(formats strfmt.Registry) error {
	if swag.IsZero(m.FileReference) { // not required
		return nil
	}

	if err := validate.MinLength("Data"+"."+"Initiation"+"."+"FileReference", "body", m.FileReference, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"Initiation"+"."+"FileReference", "body", m.FileReference, 40); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateFileType(formats strfmt.Registry) error {

	if err := validate.RequiredString("Data"+"."+"Initiation"+"."+"FileType", "body", m.FileType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateLocalInstrument(formats strfmt.Registry) error {
	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateNumberOfTransactions(formats strfmt.Registry) error {
	if swag.IsZero(m.NumberOfTransactions) { // not required
		return nil
	}

	if err := validate.Pattern("Data"+"."+"Initiation"+"."+"NumberOfTransactions", "body", m.NumberOfTransactions, `[0-9]{1,15}`); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateRemittanceInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.RemittanceInformation) { // not required
		return nil
	}

	if err := m.RemittanceInformation.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) validateRequestedExecutionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedExecutionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("Data"+"."+"Initiation"+"."+"RequestedExecutionDateTime", "body", "date-time", m.RequestedExecutionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this o b write file2 data initiation based on the context it is used
func (m *OBWriteFile2DataInitiation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteFile2DataInitiation) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		}
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) contextValidateLocalInstrument(ctx context.Context, formats strfmt.Registry) error {

	if err := m.LocalInstrument.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiation) contextValidateRemittanceInformation(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RemittanceInformation.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFile2DataInitiation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFile2DataInitiation) UnmarshalBinary(b []byte) error {
	var res OBWriteFile2DataInitiation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFile2DataInitiationDebtorAccount Unambiguous identification of the account of the debtor to which a debit entry will be made as a result of the transaction.
//
// swagger:model OBWriteFile2DataInitiationDebtorAccount
type OBWriteFile2DataInitiationDebtorAccount struct {

	// identification
	// Required: true
	Identification *Identification0 `json:"Identification"`

	// The account name is the name or names of the account owner(s) represented at an account level, as displayed by the ASPSP's online channels.
	// Note, the account name is not the product name or the nickname of the account.
	// Max Length: 350
	// Min Length: 1
	Name string `json:"Name,omitempty"`

	// scheme name
	// Required: true
	SchemeName *OBExternalAccountIdentification4Code `json:"SchemeName"`

	// secondary identification
	SecondaryIdentification SecondaryIdentification `json:"SecondaryIdentification,omitempty"`
}

// Validate validates this o b write file2 data initiation debtor account
func (m *OBWriteFile2DataInitiationDebtorAccount) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFile2DataInitiationDebtorAccount) validateIdentification(formats strfmt.Registry) error {

	if err := validate.Required("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"Identification", "body", m.Identification); err != nil {
		return err
	}

	if err := validate.Required("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"Identification", "body", m.Identification); err != nil {
		return err
	}

	if m.Identification != nil {
		if err := m.Identification.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFile2DataInitiationDebtorAccount) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := validate.MinLength("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"Name", "body", m.Name, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"Name", "body", m.Name, 350); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiationDebtorAccount) validateSchemeName(formats strfmt.Registry) error {

	if err := validate.Required("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"SchemeName", "body", m.SchemeName); err != nil {
		return err
	}

	if err := validate.Required("Data"+"."+"Initiation"+"."+"DebtorAccount"+"."+"SchemeName", "body", m.SchemeName); err != nil {
		return err
	}

	if m.SchemeName != nil {
		if err := m.SchemeName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFile2DataInitiationDebtorAccount) validateSecondaryIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondaryIdentification) { // not required
		return nil
	}

	if err := m.SecondaryIdentification.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write file2 data initiation debtor account based on the context it is used
func (m *OBWriteFile2DataInitiationDebtorAccount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteFile2DataInitiationDebtorAccount) contextValidateIdentification(ctx context.Context, formats strfmt.Registry) error {

	if m.Identification != nil {
		if err := m.Identification.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFile2DataInitiationDebtorAccount) contextValidateSchemeName(ctx context.Context, formats strfmt.Registry) error {

	if m.SchemeName != nil {
		if err := m.SchemeName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFile2DataInitiationDebtorAccount) contextValidateSecondaryIdentification(ctx context.Context, formats strfmt.Registry) error {

	if err := m.SecondaryIdentification.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFile2DataInitiationDebtorAccount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFile2DataInitiationDebtorAccount) UnmarshalBinary(b []byte) error {
	var res OBWriteFile2DataInitiationDebtorAccount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFile2DataInitiationRemittanceInformation Information supplied to enable the matching of an entry with the items that the transfer is intended to settle, such as commercial invoices in an accounts' receivable system.
//
// swagger:model OBWriteFile2DataInitiationRemittanceInformation
type OBWriteFile2DataInitiationRemittanceInformation struct {

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

// Validate validates this o b write file2 data initiation remittance information
func (m *OBWriteFile2DataInitiationRemittanceInformation) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFile2DataInitiationRemittanceInformation) validateReference(formats strfmt.Registry) error {
	if swag.IsZero(m.Reference) { // not required
		return nil
	}

	if err := validate.MinLength("Data"+"."+"Initiation"+"."+"RemittanceInformation"+"."+"Reference", "body", m.Reference, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"Initiation"+"."+"RemittanceInformation"+"."+"Reference", "body", m.Reference, 35); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFile2DataInitiationRemittanceInformation) validateUnstructured(formats strfmt.Registry) error {
	if swag.IsZero(m.Unstructured) { // not required
		return nil
	}

	if err := validate.MinLength("Data"+"."+"Initiation"+"."+"RemittanceInformation"+"."+"Unstructured", "body", m.Unstructured, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"Initiation"+"."+"RemittanceInformation"+"."+"Unstructured", "body", m.Unstructured, 140); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write file2 data initiation remittance information based on context it is used
func (m *OBWriteFile2DataInitiationRemittanceInformation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFile2DataInitiationRemittanceInformation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFile2DataInitiationRemittanceInformation) UnmarshalBinary(b []byte) error {
	var res OBWriteFile2DataInitiationRemittanceInformation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}