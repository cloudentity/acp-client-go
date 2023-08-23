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

// UpdateUserVerifiableAddress update user verifiable address
//
// swagger:model UpdateUserVerifiableAddress
type UpdateUserVerifiableAddress struct {

	// address
	// Required: true
	Address string `json:"address"`

	// preferred contact method
	// Example: sms
	// Enum: [sms voice]
	PreferredContactMethod string `json:"preferred_contact_method,omitempty"`

	// status
	// Example: active
	// Required: true
	// Enum: [active inactive]
	Status string `json:"status"`

	// verified
	// Example: false
	// Required: true
	Verified bool `json:"verified"`
}

// Validate validates this update user verifiable address
func (m *UpdateUserVerifiableAddress) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreferredContactMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerified(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateUserVerifiableAddress) validateAddress(formats strfmt.Registry) error {

	if err := validate.RequiredString("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

var updateUserVerifiableAddressTypePreferredContactMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["sms","voice"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateUserVerifiableAddressTypePreferredContactMethodPropEnum = append(updateUserVerifiableAddressTypePreferredContactMethodPropEnum, v)
	}
}

const (

	// UpdateUserVerifiableAddressPreferredContactMethodSms captures enum value "sms"
	UpdateUserVerifiableAddressPreferredContactMethodSms string = "sms"

	// UpdateUserVerifiableAddressPreferredContactMethodVoice captures enum value "voice"
	UpdateUserVerifiableAddressPreferredContactMethodVoice string = "voice"
)

// prop value enum
func (m *UpdateUserVerifiableAddress) validatePreferredContactMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateUserVerifiableAddressTypePreferredContactMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateUserVerifiableAddress) validatePreferredContactMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.PreferredContactMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validatePreferredContactMethodEnum("preferred_contact_method", "body", m.PreferredContactMethod); err != nil {
		return err
	}

	return nil
}

var updateUserVerifiableAddressTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["active","inactive"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateUserVerifiableAddressTypeStatusPropEnum = append(updateUserVerifiableAddressTypeStatusPropEnum, v)
	}
}

const (

	// UpdateUserVerifiableAddressStatusActive captures enum value "active"
	UpdateUserVerifiableAddressStatusActive string = "active"

	// UpdateUserVerifiableAddressStatusInactive captures enum value "inactive"
	UpdateUserVerifiableAddressStatusInactive string = "inactive"
)

// prop value enum
func (m *UpdateUserVerifiableAddress) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateUserVerifiableAddressTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateUserVerifiableAddress) validateStatus(formats strfmt.Registry) error {

	if err := validate.RequiredString("status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *UpdateUserVerifiableAddress) validateVerified(formats strfmt.Registry) error {

	if err := validate.Required("verified", "body", bool(m.Verified)); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update user verifiable address based on context it is used
func (m *UpdateUserVerifiableAddress) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateUserVerifiableAddress) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateUserVerifiableAddress) UnmarshalBinary(b []byte) error {
	var res UpdateUserVerifiableAddress
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}