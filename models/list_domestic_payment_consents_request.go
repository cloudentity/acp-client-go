// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ListDomesticPaymentConsentsRequest list domestic payment consents request
//
// swagger:model ListDomesticPaymentConsentsRequest
type ListDomesticPaymentConsentsRequest struct {

	// optional client ID
	ClientID string `json:"client_id,omitempty"`
}

// Validate validates this list domestic payment consents request
func (m *ListDomesticPaymentConsentsRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this list domestic payment consents request based on context it is used
func (m *ListDomesticPaymentConsentsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ListDomesticPaymentConsentsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ListDomesticPaymentConsentsRequest) UnmarshalBinary(b []byte) error {
	var res ListDomesticPaymentConsentsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
