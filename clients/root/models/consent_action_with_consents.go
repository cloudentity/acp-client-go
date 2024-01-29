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
)

// ConsentActionWithConsents consent action with consents
//
// swagger:model ConsentActionWithConsents
type ConsentActionWithConsents struct {

	// consents
	Consents []*ConsentActionToConsent `json:"consents" yaml:"consents"`

	// consent description
	// Example: Consents required by application X
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// unique consent action id
	// Example: 1
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// consent action name
	// Example: application_x
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
}

// Validate validates this consent action with consents
func (m *ConsentActionWithConsents) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConsents(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentActionWithConsents) validateConsents(formats strfmt.Registry) error {
	if swag.IsZero(m.Consents) { // not required
		return nil
	}

	for i := 0; i < len(m.Consents); i++ {
		if swag.IsZero(m.Consents[i]) { // not required
			continue
		}

		if m.Consents[i] != nil {
			if err := m.Consents[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("consents" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("consents" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this consent action with consents based on the context it is used
func (m *ConsentActionWithConsents) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateConsents(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentActionWithConsents) contextValidateConsents(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Consents); i++ {

		if m.Consents[i] != nil {

			if swag.IsZero(m.Consents[i]) { // not required
				return nil
			}

			if err := m.Consents[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("consents" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("consents" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConsentActionWithConsents) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentActionWithConsents) UnmarshalBinary(b []byte) error {
	var res ConsentActionWithConsents
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
