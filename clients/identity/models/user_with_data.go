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

// UserWithData user with data
//
// swagger:model UserWithData
type UserWithData struct {

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// credentials
	Credentials []*UserCredential `json:"credentials"`

	// id
	ID string `json:"id,omitempty"`

	// identifiers
	Identifiers []*UserIdentifier `json:"identifiers"`

	// metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// metadata schema id
	MetadataSchemaID string `json:"metadata_schema_id,omitempty"`

	// payload
	Payload map[string]interface{} `json:"payload,omitempty"`

	// payload schema id
	PayloadSchemaID string `json:"payload_schema_id,omitempty"`

	// status
	// Required: true
	// Enum: [active inactive deleted new]
	Status string `json:"status"`

	// status updated at
	// Format: date-time
	StatusUpdatedAt strfmt.DateTime `json:"status_updated_at,omitempty"`

	// tenant id
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id"`

	// updated at
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty"`

	// user pool id
	// Example: default
	// Required: true
	UserPoolID string `json:"user_pool_id"`

	// verifiable addresses
	VerifiableAddresses []*UserVerifiableAddress `json:"verifiable_addresses"`
}

// Validate validates this user with data
func (m *UserWithData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCredentials(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentifiers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserPoolID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerifiableAddresses(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserWithData) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateCredentials(formats strfmt.Registry) error {
	if swag.IsZero(m.Credentials) { // not required
		return nil
	}

	for i := 0; i < len(m.Credentials); i++ {
		if swag.IsZero(m.Credentials[i]) { // not required
			continue
		}

		if m.Credentials[i] != nil {
			if err := m.Credentials[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserWithData) validateIdentifiers(formats strfmt.Registry) error {
	if swag.IsZero(m.Identifiers) { // not required
		return nil
	}

	for i := 0; i < len(m.Identifiers); i++ {
		if swag.IsZero(m.Identifiers[i]) { // not required
			continue
		}

		if m.Identifiers[i] != nil {
			if err := m.Identifiers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("identifiers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("identifiers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var userWithDataTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["active","inactive","deleted","new"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		userWithDataTypeStatusPropEnum = append(userWithDataTypeStatusPropEnum, v)
	}
}

const (

	// UserWithDataStatusActive captures enum value "active"
	UserWithDataStatusActive string = "active"

	// UserWithDataStatusInactive captures enum value "inactive"
	UserWithDataStatusInactive string = "inactive"

	// UserWithDataStatusDeleted captures enum value "deleted"
	UserWithDataStatusDeleted string = "deleted"

	// UserWithDataStatusNew captures enum value "new"
	UserWithDataStatusNew string = "new"
)

// prop value enum
func (m *UserWithData) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, userWithDataTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UserWithData) validateStatus(formats strfmt.Registry) error {

	if err := validate.RequiredString("status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateStatusUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.StatusUpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("status_updated_at", "body", "date-time", m.StatusUpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateUserPoolID(formats strfmt.Registry) error {

	if err := validate.RequiredString("user_pool_id", "body", m.UserPoolID); err != nil {
		return err
	}

	return nil
}

func (m *UserWithData) validateVerifiableAddresses(formats strfmt.Registry) error {
	if swag.IsZero(m.VerifiableAddresses) { // not required
		return nil
	}

	for i := 0; i < len(m.VerifiableAddresses); i++ {
		if swag.IsZero(m.VerifiableAddresses[i]) { // not required
			continue
		}

		if m.VerifiableAddresses[i] != nil {
			if err := m.VerifiableAddresses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this user with data based on the context it is used
func (m *UserWithData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIdentifiers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerifiableAddresses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserWithData) contextValidateCredentials(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Credentials); i++ {

		if m.Credentials[i] != nil {
			if err := m.Credentials[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserWithData) contextValidateIdentifiers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Identifiers); i++ {

		if m.Identifiers[i] != nil {
			if err := m.Identifiers[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("identifiers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("identifiers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserWithData) contextValidateVerifiableAddresses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.VerifiableAddresses); i++ {

		if m.VerifiableAddresses[i] != nil {
			if err := m.VerifiableAddresses[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserWithData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserWithData) UnmarshalBinary(b []byte) error {
	var res UserWithData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}