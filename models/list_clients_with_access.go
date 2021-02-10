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

// ListClientsWithAccess list clients with access
//
// swagger:model ListClientsWithAccess
type ListClientsWithAccess struct {

	// clients
	Clients []*ClientWithAccess `json:"clients"`

	// scopes
	Scopes []*ScopeWithServicePublicResponse `json:"scopes"`
}

// Validate validates this list clients with access
func (m *ListClientsWithAccess) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClients(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScopes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ListClientsWithAccess) validateClients(formats strfmt.Registry) error {
	if swag.IsZero(m.Clients) { // not required
		return nil
	}

	for i := 0; i < len(m.Clients); i++ {
		if swag.IsZero(m.Clients[i]) { // not required
			continue
		}

		if m.Clients[i] != nil {
			if err := m.Clients[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("clients" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ListClientsWithAccess) validateScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.Scopes) { // not required
		return nil
	}

	for i := 0; i < len(m.Scopes); i++ {
		if swag.IsZero(m.Scopes[i]) { // not required
			continue
		}

		if m.Scopes[i] != nil {
			if err := m.Scopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this list clients with access based on the context it is used
func (m *ListClientsWithAccess) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClients(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ListClientsWithAccess) contextValidateClients(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Clients); i++ {

		if m.Clients[i] != nil {
			if err := m.Clients[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("clients" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ListClientsWithAccess) contextValidateScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Scopes); i++ {

		if m.Scopes[i] != nil {
			if err := m.Scopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ListClientsWithAccess) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ListClientsWithAccess) UnmarshalBinary(b []byte) error {
	var res ListClientsWithAccess
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
