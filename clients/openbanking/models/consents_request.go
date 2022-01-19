// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ConsentsRequest consents request
//
// swagger:model ConsentsRequest
type ConsentsRequest struct {

	// Optional list of accounts
	// Accounts
	Accounts []string `json:"accounts"`

	// optional list consents after given id
	// AfterConsentID
	AfterConsentID string `json:"after_consent_id,omitempty"`

	// optional list consents before given id
	// BeforeConsentID
	BeforeConsentID string `json:"before_consent_id,omitempty"`

	// Optional client id
	// ClientID
	ClientID string `json:"client_id,omitempty"`

	// optional limit results
	// Limit
	Limit int64 `json:"limit,omitempty"`

	// optional sort consents by given fields
	// Order
	Order string `json:"order,omitempty"`

	// optional sort consents by given fields
	// Sort
	Sort string `json:"sort,omitempty"`

	// Optional status
	// Status
	Status []string `json:"status"`

	// Optional type
	// Types
	// in:query
	Types []string `json:"types"`
}

// Validate validates this consents request
func (m *ConsentsRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this consents request based on context it is used
func (m *ConsentsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ConsentsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentsRequest) UnmarshalBinary(b []byte) error {
	var res ConsentsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
