// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Meta Meta MetaData
//
// # Meta Data relevant to the payload
//
// swagger:model Meta
type Meta struct {

	// first available date time
	// Format: date-time
	FirstAvailableDateTime ISODateTime `json:"FirstAvailableDateTime,omitempty"`

	// last available date time
	// Format: date-time
	LastAvailableDateTime ISODateTime `json:"LastAvailableDateTime,omitempty"`

	// total pages
	TotalPages int32 `json:"TotalPages,omitempty"`
}

// Validate validates this meta
func (m *Meta) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFirstAvailableDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastAvailableDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Meta) validateFirstAvailableDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.FirstAvailableDateTime) { // not required
		return nil
	}

	if err := m.FirstAvailableDateTime.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("FirstAvailableDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("FirstAvailableDateTime")
		}
		return err
	}

	return nil
}

func (m *Meta) validateLastAvailableDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.LastAvailableDateTime) { // not required
		return nil
	}

	if err := m.LastAvailableDateTime.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LastAvailableDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LastAvailableDateTime")
		}
		return err
	}

	return nil
}

// ContextValidate validate this meta based on the context it is used
func (m *Meta) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFirstAvailableDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLastAvailableDateTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Meta) contextValidateFirstAvailableDateTime(ctx context.Context, formats strfmt.Registry) error {

	if err := m.FirstAvailableDateTime.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("FirstAvailableDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("FirstAvailableDateTime")
		}
		return err
	}

	return nil
}

func (m *Meta) contextValidateLastAvailableDateTime(ctx context.Context, formats strfmt.Registry) error {

	if err := m.LastAvailableDateTime.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("LastAvailableDateTime")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("LastAvailableDateTime")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Meta) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Meta) UnmarshalBinary(b []byte) error {
	var res Meta
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
