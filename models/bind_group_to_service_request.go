// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// BindGroupToServiceRequest bind group to service request
//
// swagger:model BindGroupToServiceRequest
type BindGroupToServiceRequest struct {

	// service ID
	ServiceID string `json:"service_id,omitempty"`
}

// Validate validates this bind group to service request
func (m *BindGroupToServiceRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this bind group to service request based on context it is used
func (m *BindGroupToServiceRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *BindGroupToServiceRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BindGroupToServiceRequest) UnmarshalBinary(b []byte) error {
	var res BindGroupToServiceRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
