// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CDRArrangementsAutoRemoval c d r arrangements auto removal
//
// swagger:model CDRArrangementsAutoRemoval
type CDRArrangementsAutoRemoval struct {

	// enable auto removal
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// Period in days after which arrangements in Expired status will be removed
	RemoveAfterDays int64 `json:"remove_after_days,omitempty" yaml:"remove_after_days,omitempty"`
}

// Validate validates this c d r arrangements auto removal
func (m *CDRArrangementsAutoRemoval) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this c d r arrangements auto removal based on context it is used
func (m *CDRArrangementsAutoRemoval) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CDRArrangementsAutoRemoval) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CDRArrangementsAutoRemoval) UnmarshalBinary(b []byte) error {
	var res CDRArrangementsAutoRemoval
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
