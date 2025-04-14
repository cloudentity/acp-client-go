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

// License license
//
// swagger:model License
type License struct {

	// License end date
	// Example: 2023-03-01T09:02:27.127932Z
	// Format: date-time
	EndDate strfmt.DateTime `json:"end_date,omitempty" yaml:"end_date,omitempty"`

	// Is enforcement enabled
	EnforcementEnabled bool `json:"enforcement_enabled,omitempty" yaml:"enforcement_enabled,omitempty"`

	// Is enterprise IDPs capability enabled
	HasEnterpriseIdpsCapability bool `json:"has_enterprise_idps_capability,omitempty" yaml:"has_enterprise_idps_capability,omitempty"`

	// License start date
	// Example: 2023-03-01T09:02:27.127932Z
	// Format: date-time
	StartDate strfmt.DateTime `json:"start_date,omitempty" yaml:"start_date,omitempty"`
}

// Validate validates this license
func (m *License) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEndDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *License) validateEndDate(formats strfmt.Registry) error {
	if swag.IsZero(m.EndDate) { // not required
		return nil
	}

	if err := validate.FormatOf("end_date", "body", "date-time", m.EndDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *License) validateStartDate(formats strfmt.Registry) error {
	if swag.IsZero(m.StartDate) { // not required
		return nil
	}

	if err := validate.FormatOf("start_date", "body", "date-time", m.StartDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this license based on context it is used
func (m *License) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *License) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *License) UnmarshalBinary(b []byte) error {
	var res License
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
