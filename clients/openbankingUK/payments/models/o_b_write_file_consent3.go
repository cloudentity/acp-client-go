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

// OBWriteFileConsent3 o b write file consent3
//
// swagger:model OBWriteFileConsent3
type OBWriteFileConsent3 struct {

	// data
	// Required: true
	Data OBWriteFileConsent3Data `json:"Data"`
}

// Validate validates this o b write file consent3
func (m *OBWriteFileConsent3) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFileConsent3) validateData(formats strfmt.Registry) error {

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

// ContextValidate validate this o b write file consent3 based on the context it is used
func (m *OBWriteFileConsent3) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFileConsent3) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3Data o b write file consent3 data
//
// swagger:model OBWriteFileConsent3Data
type OBWriteFileConsent3Data struct {

	// authorisation
	Authorisation OBWriteFileConsent3DataAuthorisation `json:"Authorisation,omitempty"`

	// initiation
	// Required: true
	Initiation OBWriteFileConsent3DataInitiation `json:"Initiation"`

	// s c a support data
	SCASupportData OBWriteFileConsent3DataSCASupportData `json:"SCASupportData,omitempty"`
}

// Validate validates this o b write file consent3 data
func (m *OBWriteFileConsent3Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSCASupportData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFileConsent3Data) validateAuthorisation(formats strfmt.Registry) error {
	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if err := m.Authorisation.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Authorisation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Authorisation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3Data) validateInitiation(formats strfmt.Registry) error {

	if err := m.Initiation.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3Data) validateSCASupportData(formats strfmt.Registry) error {
	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if err := m.SCASupportData.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "SCASupportData")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "SCASupportData")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write file consent3 data based on the context it is used
func (m *OBWriteFileConsent3Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthorisation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInitiation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSCASupportData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteFileConsent3Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if err := m.Authorisation.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Authorisation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Authorisation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if err := m.SCASupportData.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "SCASupportData")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "SCASupportData")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3Data) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3DataAuthorisation The authorisation type request from the TPP.
//
// swagger:model OBWriteFileConsent3DataAuthorisation
type OBWriteFileConsent3DataAuthorisation struct {

	// Type of authorisation flow requested.
	// Required: true
	// Enum: ["Any","Single"]
	AuthorisationType string `json:"AuthorisationType"`

	// Date and time at which the requested authorisation flow must be completed.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	CompletionDateTime strfmt.DateTime `json:"CompletionDateTime,omitempty"`
}

// Validate validates this o b write file consent3 data authorisation
func (m *OBWriteFileConsent3DataAuthorisation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisationType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCompletionDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oBWriteFileConsent3DataAuthorisationTypeAuthorisationTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Any","Single"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteFileConsent3DataAuthorisationTypeAuthorisationTypePropEnum = append(oBWriteFileConsent3DataAuthorisationTypeAuthorisationTypePropEnum, v)
	}
}

const (

	// OBWriteFileConsent3DataAuthorisationAuthorisationTypeAny captures enum value "Any"
	OBWriteFileConsent3DataAuthorisationAuthorisationTypeAny string = "Any"

	// OBWriteFileConsent3DataAuthorisationAuthorisationTypeSingle captures enum value "Single"
	OBWriteFileConsent3DataAuthorisationAuthorisationTypeSingle string = "Single"
)

// prop value enum
func (m *OBWriteFileConsent3DataAuthorisation) validateAuthorisationTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteFileConsent3DataAuthorisationTypeAuthorisationTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteFileConsent3DataAuthorisation) validateAuthorisationType(formats strfmt.Registry) error {

	if err := validate.RequiredString("Data"+"."+"Authorisation"+"."+"AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	// value enum
	if err := m.validateAuthorisationTypeEnum("Data"+"."+"Authorisation"+"."+"AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataAuthorisation) validateCompletionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CompletionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("Data"+"."+"Authorisation"+"."+"CompletionDateTime", "body", "date-time", m.CompletionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write file consent3 data authorisation based on context it is used
func (m *OBWriteFileConsent3DataAuthorisation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3DataAuthorisation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3DataAuthorisation) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3DataAuthorisation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3DataInitiation The Initiation payload is sent by the initiating party to the ASPSP. It is used to request movement of funds using a payment file.
//
// swagger:model OBWriteFileConsent3DataInitiation
type OBWriteFileConsent3DataInitiation struct {

	// Total of all individual amounts included in the group, irrespective of currencies.
	ControlSum float64 `json:"ControlSum,omitempty"`

	// debtor account
	DebtorAccount OBWriteFileConsent3DataInitiationDebtorAccount `json:"DebtorAccount,omitempty"`

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
	RemittanceInformation OBWriteFileConsent3DataInitiationRemittanceInformation `json:"RemittanceInformation,omitempty"`

	// Date at which the initiating party requests the clearing agent to process the payment.
	// Usage: This is the date on which the debtor's account is to be debited.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	RequestedExecutionDateTime strfmt.DateTime `json:"RequestedExecutionDateTime,omitempty"`

	// supplementary data
	SupplementaryData OBSupplementaryData1 `json:"SupplementaryData,omitempty"`
}

// Validate validates this o b write file consent3 data initiation
func (m *OBWriteFileConsent3DataInitiation) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiation) validateDebtorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if err := m.DebtorAccount.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) validateFileHash(formats strfmt.Registry) error {

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

func (m *OBWriteFileConsent3DataInitiation) validateFileReference(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiation) validateFileType(formats strfmt.Registry) error {

	if err := validate.RequiredString("Data"+"."+"Initiation"+"."+"FileType", "body", m.FileType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) validateLocalInstrument(formats strfmt.Registry) error {
	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) validateNumberOfTransactions(formats strfmt.Registry) error {
	if swag.IsZero(m.NumberOfTransactions) { // not required
		return nil
	}

	if err := validate.Pattern("Data"+"."+"Initiation"+"."+"NumberOfTransactions", "body", m.NumberOfTransactions, `[0-9]{1,15}`); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) validateRemittanceInformation(formats strfmt.Registry) error {
	if swag.IsZero(m.RemittanceInformation) { // not required
		return nil
	}

	if err := m.RemittanceInformation.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) validateRequestedExecutionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedExecutionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("Data"+"."+"Initiation"+"."+"RequestedExecutionDateTime", "body", "date-time", m.RequestedExecutionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this o b write file consent3 data initiation based on the context it is used
func (m *OBWriteFileConsent3DataInitiation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiation) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) contextValidateLocalInstrument(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.LocalInstrument) { // not required
		return nil
	}

	if err := m.LocalInstrument.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "LocalInstrument")
		}
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiation) contextValidateRemittanceInformation(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.RemittanceInformation) { // not required
		return nil
	}

	if err := m.RemittanceInformation.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "RemittanceInformation")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiation) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3DataInitiation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3DataInitiationDebtorAccount Unambiguous identification of the account of the debtor to which a debit entry will be made as a result of the transaction.
//
// swagger:model OBWriteFileConsent3DataInitiationDebtorAccount
type OBWriteFileConsent3DataInitiationDebtorAccount struct {

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

// Validate validates this o b write file consent3 data initiation debtor account
func (m *OBWriteFileConsent3DataInitiationDebtorAccount) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) validateIdentification(formats strfmt.Registry) error {

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
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) validateName(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) validateSchemeName(formats strfmt.Registry) error {

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
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) validateSecondaryIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.SecondaryIdentification) { // not required
		return nil
	}

	if err := m.SecondaryIdentification.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b write file consent3 data initiation debtor account based on the context it is used
func (m *OBWriteFileConsent3DataInitiationDebtorAccount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) contextValidateIdentification(ctx context.Context, formats strfmt.Registry) error {

	if m.Identification != nil {

		if err := m.Identification.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "Identification")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "Identification")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) contextValidateSchemeName(ctx context.Context, formats strfmt.Registry) error {

	if m.SchemeName != nil {

		if err := m.SchemeName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SchemeName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SchemeName")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteFileConsent3DataInitiationDebtorAccount) contextValidateSecondaryIdentification(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.SecondaryIdentification) { // not required
		return nil
	}

	if err := m.SecondaryIdentification.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("Data" + "." + "Initiation" + "." + "DebtorAccount" + "." + "SecondaryIdentification")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiationDebtorAccount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiationDebtorAccount) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3DataInitiationDebtorAccount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3DataInitiationRemittanceInformation Information supplied to enable the matching of an entry with the items that the transfer is intended to settle, such as commercial invoices in an accounts' receivable system.
//
// swagger:model OBWriteFileConsent3DataInitiationRemittanceInformation
type OBWriteFileConsent3DataInitiationRemittanceInformation struct {

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

// Validate validates this o b write file consent3 data initiation remittance information
func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) Validate(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) validateReference(formats strfmt.Registry) error {
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

func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) validateUnstructured(formats strfmt.Registry) error {
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

// ContextValidate validates this o b write file consent3 data initiation remittance information based on context it is used
func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3DataInitiationRemittanceInformation) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3DataInitiationRemittanceInformation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// OBWriteFileConsent3DataSCASupportData Supporting Data provided by TPP, when requesting SCA Exemption.
//
// swagger:model OBWriteFileConsent3DataSCASupportData
type OBWriteFileConsent3DataSCASupportData struct {

	// Specifies a character string with a maximum length of 40 characters.
	// Usage: This field indicates whether the PSU was subject to SCA performed by the TPP
	// Enum: ["CA","SCA"]
	AppliedAuthenticationApproach string `json:"AppliedAuthenticationApproach,omitempty"`

	// Specifies a character string with a maximum length of 140 characters.
	// Usage: If the payment is recurring then the transaction identifier of the previous payment occurrence so that the ASPSP can verify that the PISP, amount and the payee are the same as the previous occurrence.
	// Max Length: 128
	// Min Length: 1
	ReferencePaymentOrderID string `json:"ReferencePaymentOrderId,omitempty"`

	// This field allows a PISP to request specific SCA Exemption for a Payment Initiation
	// Enum: ["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]
	RequestedSCAExemptionType string `json:"RequestedSCAExemptionType,omitempty"`
}

// Validate validates this o b write file consent3 data s c a support data
func (m *OBWriteFileConsent3DataSCASupportData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAppliedAuthenticationApproach(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReferencePaymentOrderID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedSCAExemptionType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oBWriteFileConsent3DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["CA","SCA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteFileConsent3DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum = append(oBWriteFileConsent3DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, v)
	}
}

const (

	// OBWriteFileConsent3DataSCASupportDataAppliedAuthenticationApproachCA captures enum value "CA"
	OBWriteFileConsent3DataSCASupportDataAppliedAuthenticationApproachCA string = "CA"

	// OBWriteFileConsent3DataSCASupportDataAppliedAuthenticationApproachSCA captures enum value "SCA"
	OBWriteFileConsent3DataSCASupportDataAppliedAuthenticationApproachSCA string = "SCA"
)

// prop value enum
func (m *OBWriteFileConsent3DataSCASupportData) validateAppliedAuthenticationApproachEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteFileConsent3DataSCASupportDataTypeAppliedAuthenticationApproachPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteFileConsent3DataSCASupportData) validateAppliedAuthenticationApproach(formats strfmt.Registry) error {
	if swag.IsZero(m.AppliedAuthenticationApproach) { // not required
		return nil
	}

	// value enum
	if err := m.validateAppliedAuthenticationApproachEnum("Data"+"."+"SCASupportData"+"."+"AppliedAuthenticationApproach", "body", m.AppliedAuthenticationApproach); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteFileConsent3DataSCASupportData) validateReferencePaymentOrderID(formats strfmt.Registry) error {
	if swag.IsZero(m.ReferencePaymentOrderID) { // not required
		return nil
	}

	if err := validate.MinLength("Data"+"."+"SCASupportData"+"."+"ReferencePaymentOrderId", "body", m.ReferencePaymentOrderID, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Data"+"."+"SCASupportData"+"."+"ReferencePaymentOrderId", "body", m.ReferencePaymentOrderID, 128); err != nil {
		return err
	}

	return nil
}

var oBWriteFileConsent3DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BillPayment","ContactlessTravel","EcommerceGoods","EcommerceServices","Kiosk","Parking","PartyToParty"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteFileConsent3DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum = append(oBWriteFileConsent3DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, v)
	}
}

const (

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeBillPayment captures enum value "BillPayment"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeBillPayment string = "BillPayment"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel captures enum value "ContactlessTravel"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeContactlessTravel string = "ContactlessTravel"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods captures enum value "EcommerceGoods"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeEcommerceGoods string = "EcommerceGoods"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices captures enum value "EcommerceServices"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeEcommerceServices string = "EcommerceServices"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeKiosk captures enum value "Kiosk"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeKiosk string = "Kiosk"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeParking captures enum value "Parking"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypeParking string = "Parking"

	// OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypePartyToParty captures enum value "PartyToParty"
	OBWriteFileConsent3DataSCASupportDataRequestedSCAExemptionTypePartyToParty string = "PartyToParty"
)

// prop value enum
func (m *OBWriteFileConsent3DataSCASupportData) validateRequestedSCAExemptionTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteFileConsent3DataSCASupportDataTypeRequestedSCAExemptionTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteFileConsent3DataSCASupportData) validateRequestedSCAExemptionType(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedSCAExemptionType) { // not required
		return nil
	}

	// value enum
	if err := m.validateRequestedSCAExemptionTypeEnum("Data"+"."+"SCASupportData"+"."+"RequestedSCAExemptionType", "body", m.RequestedSCAExemptionType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write file consent3 data s c a support data based on context it is used
func (m *OBWriteFileConsent3DataSCASupportData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteFileConsent3DataSCASupportData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteFileConsent3DataSCASupportData) UnmarshalBinary(b []byte) error {
	var res OBWriteFileConsent3DataSCASupportData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
