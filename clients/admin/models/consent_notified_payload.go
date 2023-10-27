// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ConsentNotifiedPayload consent notified payload
//
// swagger:model ConsentNotifiedPayload
type ConsentNotifiedPayload struct {

	// Type of notification, specifies what the client was notified of , e.g.: revocation
	NotificationType string `json:"notification_type,omitempty"`

	// payload of the request sent to the notification endpoint
	Payload string `json:"payload,omitempty"`

	// uri that was notified of the revocation
	URI string `json:"uri,omitempty"`
}

// Validate validates this consent notified payload
func (m *ConsentNotifiedPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this consent notified payload based on context it is used
func (m *ConsentNotifiedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ConsentNotifiedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentNotifiedPayload) UnmarshalBinary(b []byte) error {
	var res ConsentNotifiedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
