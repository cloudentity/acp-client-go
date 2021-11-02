// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FilePaymentConsentFileResource file payment consent file resource
//
// swagger:model FilePaymentConsentFileResource
type FilePaymentConsentFileResource struct {

	// client id
	ClientID string `json:"client_id,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty"`

	// file
	File []uint8 `json:"file"`

	// server id
	ServerID string `json:"server_id,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`
}

// Validate validates this file payment consent file resource
func (m *FilePaymentConsentFileResource) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this file payment consent file resource based on context it is used
func (m *FilePaymentConsentFileResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FilePaymentConsentFileResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FilePaymentConsentFileResource) UnmarshalBinary(b []byte) error {
	var res FilePaymentConsentFileResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}