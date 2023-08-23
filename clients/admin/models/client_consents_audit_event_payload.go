// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ClientConsentsAuditEventPayload client consents audit event payload
//
// swagger:model ClientConsentsAuditEventPayload
type ClientConsentsAuditEventPayload struct {

	// client id
	ClientID string `json:"client_id,omitempty"`

	// number of consents revoked
	NumberRevoked int64 `json:"number_revoked,omitempty"`
}

// Validate validates this client consents audit event payload
func (m *ClientConsentsAuditEventPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this client consents audit event payload based on context it is used
func (m *ClientConsentsAuditEventPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ClientConsentsAuditEventPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClientConsentsAuditEventPayload) UnmarshalBinary(b []byte) error {
	var res ClientConsentsAuditEventPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}