// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBWriteInternationalStandingOrderConsentResponse7Data OBWriteInternationalStandingOrderConsentResponse7Data o b write international standing order consent response7 data
//
// swagger:model OBWriteInternationalStandingOrderConsentResponse7Data
type OBWriteInternationalStandingOrderConsentResponse7Data struct {

	// authorisation
	Authorisation *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation `json:"Authorisation,omitempty"`

	// charges
	Charges []*OBWriteInternationalStandingOrderConsentResponse7DataChargesItems0 `json:"Charges"`

	// OB: Unique identification as assigned by the ASPSP to uniquely identify the consent resource.
	// Required: true
	// Max Length: 128
	// Min Length: 1
	ConsentID string `json:"ConsentId"`

	// Date and time at which the resource was created.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Required: true
	// Format: date-time
	CreationDateTime strfmt.DateTime `json:"CreationDateTime"`

	// Specified cut-off date and time for the payment consent.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	CutOffDateTime strfmt.DateTime `json:"CutOffDateTime,omitempty"`

	// debtor
	Debtor *OBDebtorIdentification1 `json:"Debtor,omitempty"`

	// initiation
	// Required: true
	Initiation *OBWriteInternationalStandingOrderConsentResponse7DataInitiation `json:"Initiation"`

	// Specifies the Open Banking service request types.
	// Required: true
	// Enum: [Create]
	Permission string `json:"Permission"`

	// Specifies to share the refund account details with PISP
	// Enum: [No Yes]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *OBWriteInternationalStandingOrderConsentResponse7DataSCASupportData `json:"SCASupportData,omitempty"`

	// Specifies the status of resource in code form.
	// Required: true
	// Enum: [Authorised AwaitingAuthorisation Consumed Rejected]
	Status string `json:"Status"`

	// Date and time at which the resource status was updated.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Required: true
	// Format: date-time
	StatusUpdateDateTime strfmt.DateTime `json:"StatusUpdateDateTime"`
}

// Validate validates this o b write international standing order consent response7 data
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCharges(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCutOffDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDebtor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermission(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReadRefundAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSCASupportData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdateDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateAuthorisation(formats strfmt.Registry) error {
	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if m.Authorisation != nil {
		if err := m.Authorisation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateCharges(formats strfmt.Registry) error {
	if swag.IsZero(m.Charges) { // not required
		return nil
	}

	for i := 0; i < len(m.Charges); i++ {
		if swag.IsZero(m.Charges[i]) { // not required
			continue
		}

		if m.Charges[i] != nil {
			if err := m.Charges[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Charges" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Charges" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateConsentID(formats strfmt.Registry) error {

	if err := validate.RequiredString("ConsentId", "body", m.ConsentID); err != nil {
		return err
	}

	if err := validate.MinLength("ConsentId", "body", m.ConsentID, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("ConsentId", "body", m.ConsentID, 128); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateCreationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("CreationDateTime", "body", strfmt.DateTime(m.CreationDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("CreationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateCutOffDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CutOffDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CutOffDateTime", "body", "date-time", m.CutOffDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateDebtor(formats strfmt.Registry) error {
	if swag.IsZero(m.Debtor) { // not required
		return nil
	}

	if m.Debtor != nil {
		if err := m.Debtor.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Debtor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Debtor")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateInitiation(formats strfmt.Registry) error {

	if err := validate.Required("Initiation", "body", m.Initiation); err != nil {
		return err
	}

	if m.Initiation != nil {
		if err := m.Initiation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataTypePermissionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Create"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataTypePermissionPropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataTypePermissionPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataPermissionCreate captures enum value "Create"
	OBWriteInternationalStandingOrderConsentResponse7DataPermissionCreate string = "Create"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validatePermissionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataTypePermissionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validatePermission(formats strfmt.Registry) error {

	if err := validate.RequiredString("Permission", "body", m.Permission); err != nil {
		return err
	}

	// value enum
	if err := m.validatePermissionEnum("Permission", "body", m.Permission); err != nil {
		return err
	}

	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["No","Yes"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataTypeReadRefundAccountPropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataReadRefundAccountNo captures enum value "No"
	OBWriteInternationalStandingOrderConsentResponse7DataReadRefundAccountNo string = "No"

	// OBWriteInternationalStandingOrderConsentResponse7DataReadRefundAccountYes captures enum value "Yes"
	OBWriteInternationalStandingOrderConsentResponse7DataReadRefundAccountYes string = "Yes"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateSCASupportData(formats strfmt.Registry) error {
	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if m.SCASupportData != nil {
		if err := m.SCASupportData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Authorised","AwaitingAuthorisation","Consumed","Rejected"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataTypeStatusPropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataTypeStatusPropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataStatusAuthorised captures enum value "Authorised"
	OBWriteInternationalStandingOrderConsentResponse7DataStatusAuthorised string = "Authorised"

	// OBWriteInternationalStandingOrderConsentResponse7DataStatusAwaitingAuthorisation captures enum value "AwaitingAuthorisation"
	OBWriteInternationalStandingOrderConsentResponse7DataStatusAwaitingAuthorisation string = "AwaitingAuthorisation"

	// OBWriteInternationalStandingOrderConsentResponse7DataStatusConsumed captures enum value "Consumed"
	OBWriteInternationalStandingOrderConsentResponse7DataStatusConsumed string = "Consumed"

	// OBWriteInternationalStandingOrderConsentResponse7DataStatusRejected captures enum value "Rejected"
	OBWriteInternationalStandingOrderConsentResponse7DataStatusRejected string = "Rejected"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateStatus(formats strfmt.Registry) error {

	if err := validate.RequiredString("Status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("Status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) validateStatusUpdateDateTime(formats strfmt.Registry) error {

	if err := validate.Required("StatusUpdateDateTime", "body", strfmt.DateTime(m.StatusUpdateDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("StatusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this o b write international standing order consent response7 data based on the context it is used
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthorisation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCharges(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtor(ctx, formats); err != nil {
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

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if m.Authorisation != nil {

		if swag.IsZero(m.Authorisation) { // not required
			return nil
		}

		if err := m.Authorisation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) contextValidateCharges(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Charges); i++ {

		if m.Charges[i] != nil {

			if swag.IsZero(m.Charges[i]) { // not required
				return nil
			}

			if err := m.Charges[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Charges" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Charges" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) contextValidateDebtor(ctx context.Context, formats strfmt.Registry) error {

	if m.Debtor != nil {

		if swag.IsZero(m.Debtor) { // not required
			return nil
		}

		if err := m.Debtor.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Debtor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Debtor")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if m.Initiation != nil {

		if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7Data) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if m.SCASupportData != nil {

		if swag.IsZero(m.SCASupportData) { // not required
			return nil
		}

		if err := m.SCASupportData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7Data) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsentResponse7Data
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
