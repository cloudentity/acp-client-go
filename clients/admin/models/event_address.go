// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// EventAddress EventAddress event address
//
// swagger:model EventAddress
type EventAddress struct {

	// address value
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// Validate validates this event address
func (m *EventAddress) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this event address based on context it is used
func (m *EventAddress) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EventAddress) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EventAddress) UnmarshalBinary(b []byte) error {
	var res EventAddress
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
