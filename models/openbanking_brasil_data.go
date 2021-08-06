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

// OpenbankingBrasilData OpenbankingBrasilData Data
//
// swagger:model OpenbankingBrasilData
type OpenbankingBrasilData struct {

	// business entity
	BusinessEntity *OpenbankingBrasilBusinessEntity `json:"businessEntity,omitempty"`

	// Data e hora de expirao da permisso. Se no for preenchido, a permisso ter a data aberta. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Format: date-time
	ExpirationDateTime strfmt.DateTime `json:"expirationDateTime,omitempty"`

	// logged user
	// Required: true
	LoggedUser *OpenbankingBrasilLoggedUser `json:"loggedUser"`

	// permissions
	// Example: ["ACCOUNTS_READ","ACCOUNTS_OVERDRAFT_LIMITS_READ","RESOURCES_READ"]
	// Required: true
	// Max Items: 30
	// Min Items: 1
	Permissions []OpenbankingBrasilPermission `json:"permissions"`

	// Data e hora da transao inicial. Se no for preenchido, a transao ter a data aberta e a data ser retornada com a primeira transao disponvel. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-01-01T00:00:00Z
	// Format: date-time
	TransactionFromDateTime strfmt.DateTime `json:"transactionFromDateTime,omitempty"`

	// Data e hora final da transao. Se no for preenchido, a transao ter a data aberta e a data ser retornada com a ultima transao disponvel. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-02-01T23:59:59Z
	// Format: date-time
	TransactionToDateTime strfmt.DateTime `json:"transactionToDateTime,omitempty"`
}

// Validate validates this openbanking brasil data
func (m *OpenbankingBrasilData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBusinessEntity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpirationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLoggedUser(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
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

func (m *OpenbankingBrasilData) validateBusinessEntity(formats strfmt.Registry) error {
	if swag.IsZero(m.BusinessEntity) { // not required
		return nil
	}

	if m.BusinessEntity != nil {
		if err := m.BusinessEntity.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("businessEntity")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilData) validateExpirationDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpirationDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("expirationDateTime", "body", "date-time", m.ExpirationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilData) validateLoggedUser(formats strfmt.Registry) error {

	if err := validate.Required("loggedUser", "body", m.LoggedUser); err != nil {
		return err
	}

	if m.LoggedUser != nil {
		if err := m.LoggedUser.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("loggedUser")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilData) validatePermissions(formats strfmt.Registry) error {

	if err := validate.Required("permissions", "body", m.Permissions); err != nil {
		return err
	}

	iPermissionsSize := int64(len(m.Permissions))

	if err := validate.MinItems("permissions", "body", iPermissionsSize, 1); err != nil {
		return err
	}

	if err := validate.MaxItems("permissions", "body", iPermissionsSize, 30); err != nil {
		return err
	}

	for i := 0; i < len(m.Permissions); i++ {

		if err := m.Permissions[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *OpenbankingBrasilData) validateTransactionFromDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.TransactionFromDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("transactionFromDateTime", "body", "date-time", m.TransactionFromDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilData) validateTransactionToDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.TransactionToDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("transactionToDateTime", "body", "date-time", m.TransactionToDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil data based on the context it is used
func (m *OpenbankingBrasilData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBusinessEntity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLoggedUser(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePermissions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilData) contextValidateBusinessEntity(ctx context.Context, formats strfmt.Registry) error {

	if m.BusinessEntity != nil {
		if err := m.BusinessEntity.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("businessEntity")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilData) contextValidateLoggedUser(ctx context.Context, formats strfmt.Registry) error {

	if m.LoggedUser != nil {
		if err := m.LoggedUser.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("loggedUser")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilData) contextValidatePermissions(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Permissions); i++ {

		if err := m.Permissions[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilData) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
