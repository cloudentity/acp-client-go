// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FDXResource FDX specific resource
//
// swagger:model FDXResource
type FDXResource struct {

	// The names of clusters with data elements permitted.
	DataClusters []string `json:"dataClusters" yaml:"dataClusters"`

	// Resource identifier.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// A type of resource that holds the permitted data elements. This parameter can be extended to support additional resource types.
	ResouceType string `json:"resouceType,omitempty" yaml:"resouceType,omitempty"`
}

// Validate validates this f d x resource
func (m *FDXResource) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this f d x resource based on context it is used
func (m *FDXResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FDXResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FDXResource) UnmarshalBinary(b []byte) error {
	var res FDXResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
