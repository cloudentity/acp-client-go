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

// AccountAccessConsent account access consent
//
// swagger:model AccountAccessConsent
type AccountAccessConsent struct {

	// Unique identification as assigned to identify the account access consent resource.
	// Required: true
	// Max Length: 128
	// Min Length: 1
	ConsentID *string `json:"ConsentId"`

	// creation date time
	// Required: true
	// Format: date-time
	CreationDateTime *CreationDateTime `json:"CreationDateTime"`

	// Specified date and time the permissions will expire.
	// If this is not populated, the permissions will be open ended.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	ExpirationDateTime strfmt.DateTime `json:"ExpirationDateTime,omitempty"`

	// permissions
	// Required: true
	// Min Items: 1
	Permissions []string `json:"Permissions"`

	// Specifies the status of consent resource in code form.
	// Required: true
	// Enum: [Authorised AwaitingAuthorisation Rejected Revoked]
	Status *string `json:"Status"`

	// status update date time
	// Required: true
	// Format: date-time
	StatusUpdateDateTime *StatusUpdateDateTime `json:"StatusUpdateDateTime"`

	// Specified start date and time for the transaction query period.
	// If this is not populated, the start date will be open ended, and data will be returned from the earliest available transaction.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	TransactionFromDateTime strfmt.DateTime `json:"TransactionFromDateTime,omitempty"`

	// Specified end date and time for the transaction query period.
	// If this is not populated, the end date will be open ended, and data will be returned to the latest available transaction.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	TransactionToDateTime strfmt.DateTime `json:"TransactionToDateTime,omitempty"`
}

// Validate validates this account access consent
func (m *AccountAccessConsent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpirationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdateDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransactionFromDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransactionToDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountAccessConsent) validateConsentID(formats strfmt.Registry) error {

	if err := validate.Required("ConsentId", "body", m.ConsentID); err != nil {
		return err
	}

	if err := validate.MinLength("ConsentId", "body", *m.ConsentID, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("ConsentId", "body", *m.ConsentID, 128); err != nil {
		return err
	}

	return nil
}

func (m *AccountAccessConsent) validateCreationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("CreationDateTime", "body", m.CreationDateTime); err != nil {
		return err
	}

	if err := validate.Required("CreationDateTime", "body", m.CreationDateTime); err != nil {
		return err
	}

	if m.CreationDateTime != nil {
		if err := m.CreationDateTime.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreationDateTime")
			}
			return err
		}
	}

	return nil
}

func (m *AccountAccessConsent) validateExpirationDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpirationDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("ExpirationDateTime", "body", "date-time", m.ExpirationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountAccessConsent) validatePermissions(formats strfmt.Registry) error {

	if err := validate.Required("Permissions", "body", m.Permissions); err != nil {
		return err
	}

	iPermissionsSize := int64(len(m.Permissions))

	if err := validate.MinItems("Permissions", "body", iPermissionsSize, 1); err != nil {
		return err
	}

	return nil
}

var accountAccessConsentTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Authorised","AwaitingAuthorisation","Rejected","Revoked"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		accountAccessConsentTypeStatusPropEnum = append(accountAccessConsentTypeStatusPropEnum, v)
	}
}

const (

	// AccountAccessConsentStatusAuthorised captures enum value "Authorised"
	AccountAccessConsentStatusAuthorised string = "Authorised"

	// AccountAccessConsentStatusAwaitingAuthorisation captures enum value "AwaitingAuthorisation"
	AccountAccessConsentStatusAwaitingAuthorisation string = "AwaitingAuthorisation"

	// AccountAccessConsentStatusRejected captures enum value "Rejected"
	AccountAccessConsentStatusRejected string = "Rejected"

	// AccountAccessConsentStatusRevoked captures enum value "Revoked"
	AccountAccessConsentStatusRevoked string = "Revoked"
)

// prop value enum
func (m *AccountAccessConsent) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, accountAccessConsentTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AccountAccessConsent) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("Status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("Status", "body", *m.Status); err != nil {
		return err
	}

	return nil
}

func (m *AccountAccessConsent) validateStatusUpdateDateTime(formats strfmt.Registry) error {

	if err := validate.Required("StatusUpdateDateTime", "body", m.StatusUpdateDateTime); err != nil {
		return err
	}

	if err := validate.Required("StatusUpdateDateTime", "body", m.StatusUpdateDateTime); err != nil {
		return err
	}

	if m.StatusUpdateDateTime != nil {
		if err := m.StatusUpdateDateTime.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("StatusUpdateDateTime")
			}
			return err
		}
	}

	return nil
}

func (m *AccountAccessConsent) validateTransactionFromDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.TransactionFromDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("TransactionFromDateTime", "body", "date-time", m.TransactionFromDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountAccessConsent) validateTransactionToDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.TransactionToDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("TransactionToDateTime", "body", "date-time", m.TransactionToDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this account access consent based on the context it is used
func (m *AccountAccessConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreationDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStatusUpdateDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountAccessConsent) contextValidateCreationDateTime(ctx context.Context, formats strfmt.Registry) error {

	if m.CreationDateTime != nil {
		if err := m.CreationDateTime.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CreationDateTime")
			}
			return err
		}
	}

	return nil
}

func (m *AccountAccessConsent) contextValidateStatusUpdateDateTime(ctx context.Context, formats strfmt.Registry) error {

	if m.StatusUpdateDateTime != nil {
		if err := m.StatusUpdateDateTime.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("StatusUpdateDateTime")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccountAccessConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccountAccessConsent) UnmarshalBinary(b []byte) error {
	var res AccountAccessConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
