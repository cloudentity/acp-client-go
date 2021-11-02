// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OpenbankingServerConsent openbanking server consent
//
// swagger:model OpenbankingServerConsent
type OpenbankingServerConsent struct {

	// If empty it defaults to demo bank embedded in acp
	BankURL string `json:"bank_url,omitempty"`
}

// Validate validates this openbanking server consent
func (m *OpenbankingServerConsent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking server consent based on context it is used
func (m *OpenbankingServerConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingServerConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingServerConsent) UnmarshalBinary(b []byte) error {
	var res OpenbankingServerConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}