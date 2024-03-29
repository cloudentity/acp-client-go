// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TreeWebhook tree webhook
//
// swagger:model TreeWebhook
type TreeWebhook struct {

	// Active
	Active bool `json:"active,omitempty" yaml:"active,omitempty"`

	// API Key
	APIKey string `json:"api_key,omitempty" yaml:"api_key,omitempty"`

	// events
	Events map[string][]string `json:"events,omitempty" yaml:"events,omitempty"`

	// Insecure
	Insecure bool `json:"insecure,omitempty" yaml:"insecure,omitempty"`

	// url of the Webhook
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
}

// Validate validates this tree webhook
func (m *TreeWebhook) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this tree webhook based on context it is used
func (m *TreeWebhook) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TreeWebhook) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeWebhook) UnmarshalBinary(b []byte) error {
	var res TreeWebhook
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
