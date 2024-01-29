// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Intermediary intermediary
//
// swagger:model Intermediary
type Intermediary struct {

	// Array of strings representing ways to contact people responsible for this intermediary
	Contacts []string `json:"contacts" yaml:"contacts"`

	// A short description of the intermediary
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// A URL string that references a logo for this intermediary
	LogoURI string `json:"logo_uri,omitempty" yaml:"logo_uri,omitempty"`

	// Name of intermediary party
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Registry references for this intermediary
	RegistryReferences []*RegistryReference `json:"registry_references" yaml:"registry_references"`

	// A URL string of a web page providing information about the intermediary
	URI string `json:"uri,omitempty" yaml:"uri,omitempty"`
}

// Validate validates this intermediary
func (m *Intermediary) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRegistryReferences(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Intermediary) validateRegistryReferences(formats strfmt.Registry) error {
	if swag.IsZero(m.RegistryReferences) { // not required
		return nil
	}

	for i := 0; i < len(m.RegistryReferences); i++ {
		if swag.IsZero(m.RegistryReferences[i]) { // not required
			continue
		}

		if m.RegistryReferences[i] != nil {
			if err := m.RegistryReferences[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("registry_references" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("registry_references" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this intermediary based on the context it is used
func (m *Intermediary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRegistryReferences(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Intermediary) contextValidateRegistryReferences(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RegistryReferences); i++ {

		if m.RegistryReferences[i] != nil {

			if swag.IsZero(m.RegistryReferences[i]) { // not required
				return nil
			}

			if err := m.RegistryReferences[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("registry_references" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("registry_references" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Intermediary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Intermediary) UnmarshalBinary(b []byte) error {
	var res Intermediary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
