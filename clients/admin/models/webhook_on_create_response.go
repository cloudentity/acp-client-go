// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// WebhookOnCreateResponse Wevhook object on create
//
// swagger:model WebhookOnCreateResponse
type WebhookOnCreateResponse struct {

	// Active
	Active bool `json:"active,omitempty"`

	// API Key
	APIKey string `json:"api_key,omitempty"`

	// events
	Events map[string][]string `json:"events,omitempty"`

	// Insecure
	Insecure bool `json:"insecure,omitempty"`

	// url of the Webhook
	URL string `json:"url,omitempty"`

	// ID to the Webhook
	WebhookID string `json:"webhook_id,omitempty"`
}

// Validate validates this webhook on create response
func (m *WebhookOnCreateResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this webhook on create response based on context it is used
func (m *WebhookOnCreateResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *WebhookOnCreateResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WebhookOnCreateResponse) UnmarshalBinary(b []byte) error {
	var res WebhookOnCreateResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
