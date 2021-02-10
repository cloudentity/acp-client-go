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

// RecentActivity recent activity
//
// swagger:model RecentActivity
type RecentActivity struct {

	// date
	// Format: date-time
	Date strfmt.DateTime `json:"date,omitempty"`

	// ID
	ID string `json:"id,omitempty"`

	// server ID
	ServerID string `json:"server_id,omitempty"`

	// tenant ID
	TenantID string `json:"tenant_id,omitempty"`

	// payload
	Payload *RecentActivityPayload `json:"payload,omitempty"`
}

// Validate validates this recent activity
func (m *RecentActivity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayload(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RecentActivity) validateDate(formats strfmt.Registry) error {
	if swag.IsZero(m.Date) { // not required
		return nil
	}

	if err := validate.FormatOf("date", "body", "date-time", m.Date.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RecentActivity) validatePayload(formats strfmt.Registry) error {
	if swag.IsZero(m.Payload) { // not required
		return nil
	}

	if m.Payload != nil {
		if err := m.Payload.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this recent activity based on the context it is used
func (m *RecentActivity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePayload(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RecentActivity) contextValidatePayload(ctx context.Context, formats strfmt.Registry) error {

	if m.Payload != nil {
		if err := m.Payload.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RecentActivity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RecentActivity) UnmarshalBinary(b []byte) error {
	var res RecentActivity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}