// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ScopeWithServicePublicResponse scope with service public response
//
// swagger:model ScopeWithServicePublicResponse
type ScopeWithServicePublicResponse struct {

	// scope description
	// Example: This scope value requests offline access using refresh token
	ScopeDescription string `json:"scope_description,omitempty"`

	// scope display name
	// Example: Offline access
	ScopeDisplayName string `json:"scope_display_name,omitempty"`

	// scope id
	// Example: 1
	ScopeID string `json:"scope_id,omitempty"`

	// scope name
	// Example: offline_access
	ScopeName string `json:"scope_name,omitempty"`

	// service description
	// Example: service description
	ServiceDescription string `json:"service_description,omitempty"`

	// service id
	// Example: 1
	ServiceID string `json:"service_id,omitempty"`

	// service name
	// Example: service
	ServiceName string `json:"service_name,omitempty"`

	// is scope assigned to a service
	// Example: false
	WithService bool `json:"with_service,omitempty"`
}

// Validate validates this scope with service public response
func (m *ScopeWithServicePublicResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this scope with service public response based on context it is used
func (m *ScopeWithServicePublicResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ScopeWithServicePublicResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScopeWithServicePublicResponse) UnmarshalBinary(b []byte) error {
	var res ScopeWithServicePublicResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}