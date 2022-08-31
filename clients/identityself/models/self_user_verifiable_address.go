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

// SelfUserVerifiableAddress self user verifiable address
//
// swagger:model SelfUserVerifiableAddress
type SelfUserVerifiableAddress struct {

	// address
	// Required: true
	Address string `json:"address"`

	// created at
	// Required: true
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at"`

	// preferred contact method
	// Example: sms
	// Enum: [sms voice]
	PreferredContactMethod string `json:"preferred_contact_method,omitempty"`

	// status
	// Example: active
	// Required: true
	// Enum: [active inactive]
	Status string `json:"status"`

	// type
	// Example: mobile
	// Required: true
	// Enum: [email mobile]
	Type string `json:"type"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at"`

	// verified
	// Required: true
	Verified bool `json:"verified"`

	// verified at
	// Format: date-time
	VerifiedAt strfmt.DateTime `json:"verified_at,omitempty"`
}

// Validate validates this self user verifiable address
func (m *SelfUserVerifiableAddress) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreferredContactMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerified(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerifiedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfUserVerifiableAddress) validateAddress(formats strfmt.Registry) error {

	if err := validate.RequiredString("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserVerifiableAddress) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", strfmt.DateTime(m.CreatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

var selfUserVerifiableAddressTypePreferredContactMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","voice"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserVerifiableAddressTypePreferredContactMethodPropEnum = append(selfUserVerifiableAddressTypePreferredContactMethodPropEnum, v)
	}
}

const (

	// SelfUserVerifiableAddressPreferredContactMethodSms captures enum value "sms"
	SelfUserVerifiableAddressPreferredContactMethodSms string = "sms"

	// SelfUserVerifiableAddressPreferredContactMethodVoice captures enum value "voice"
	SelfUserVerifiableAddressPreferredContactMethodVoice string = "voice"
)

// prop value enum
func (m *SelfUserVerifiableAddress) validatePreferredContactMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserVerifiableAddressTypePreferredContactMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserVerifiableAddress) validatePreferredContactMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.PreferredContactMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validatePreferredContactMethodEnum("preferred_contact_method", "body", m.PreferredContactMethod); err != nil {
		return err
	}

	return nil
}

var selfUserVerifiableAddressTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["active","inactive"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserVerifiableAddressTypeStatusPropEnum = append(selfUserVerifiableAddressTypeStatusPropEnum, v)
	}
}

const (

	// SelfUserVerifiableAddressStatusActive captures enum value "active"
	SelfUserVerifiableAddressStatusActive string = "active"

	// SelfUserVerifiableAddressStatusInactive captures enum value "inactive"
	SelfUserVerifiableAddressStatusInactive string = "inactive"
)

// prop value enum
func (m *SelfUserVerifiableAddress) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserVerifiableAddressTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserVerifiableAddress) validateStatus(formats strfmt.Registry) error {

	if err := validate.RequiredString("status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

var selfUserVerifiableAddressTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["email","mobile"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		selfUserVerifiableAddressTypeTypePropEnum = append(selfUserVerifiableAddressTypeTypePropEnum, v)
	}
}

const (

	// SelfUserVerifiableAddressTypeEmail captures enum value "email"
	SelfUserVerifiableAddressTypeEmail string = "email"

	// SelfUserVerifiableAddressTypeMobile captures enum value "mobile"
	SelfUserVerifiableAddressTypeMobile string = "mobile"
)

// prop value enum
func (m *SelfUserVerifiableAddress) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, selfUserVerifiableAddressTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SelfUserVerifiableAddress) validateType(formats strfmt.Registry) error {

	if err := validate.RequiredString("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserVerifiableAddress) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updated_at", "body", strfmt.DateTime(m.UpdatedAt)); err != nil {
		return err
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserVerifiableAddress) validateVerified(formats strfmt.Registry) error {

	if err := validate.Required("verified", "body", bool(m.Verified)); err != nil {
		return err
	}

	return nil
}

func (m *SelfUserVerifiableAddress) validateVerifiedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.VerifiedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("verified_at", "body", "date-time", m.VerifiedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this self user verifiable address based on context it is used
func (m *SelfUserVerifiableAddress) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SelfUserVerifiableAddress) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelfUserVerifiableAddress) UnmarshalBinary(b []byte) error {
	var res SelfUserVerifiableAddress
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}