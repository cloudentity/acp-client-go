// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// InitialAccessTokenSettings initial access token settings
//
// swagger:model InitialAccessTokenSettings
type InitialAccessTokenSettings struct {

	// required
	Required bool `json:"required,omitempty"`
}

// Validate validates this initial access token settings
func (m *InitialAccessTokenSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *InitialAccessTokenSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InitialAccessTokenSettings) UnmarshalBinary(b []byte) error {
	var res InitialAccessTokenSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
