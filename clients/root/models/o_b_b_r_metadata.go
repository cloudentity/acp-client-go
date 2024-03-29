// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OBBRMetadata o b b r metadata
//
// swagger:model OBBRMetadata
type OBBRMetadata struct {

	// An array of hosts subscribed to Open Finance Webhook Notifications
	WebhookUris []string `json:"webhook_uris" yaml:"webhook_uris"`
}

// Validate validates this o b b r metadata
func (m *OBBRMetadata) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this o b b r metadata based on context it is used
func (m *OBBRMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBBRMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBBRMetadata) UnmarshalBinary(b []byte) error {
	var res OBBRMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
