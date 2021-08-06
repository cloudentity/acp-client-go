// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CreateGatewayRequest create gateway request
//
// swagger:model CreateGatewayRequest
type CreateGatewayRequest struct {

	// if true a services is created automatically for each new discovered api group
	CreateAndBindServicesAutomatically bool `json:"create_and_bind_services_automatically,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// gateway name
	// Example: Cloudentity Pyron
	Name string `json:"name,omitempty"`

	// ServerID that this gateway should protect
	ServerID string `json:"server_id,omitempty"`

	// gateway type, one of: pyron, aws, azure, istio, kong, apigee
	// Example: pyron
	Type string `json:"type,omitempty"`
}

// Validate validates this create gateway request
func (m *CreateGatewayRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this create gateway request based on context it is used
func (m *CreateGatewayRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CreateGatewayRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreateGatewayRequest) UnmarshalBinary(b []byte) error {
	var res CreateGatewayRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
