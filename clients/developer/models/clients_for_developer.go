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

// ClientsForDeveloper OAuth clients owned by developer
//
// swagger:model ClientsForDeveloper
type ClientsForDeveloper struct {

	// clients
	Clients []*ClientDeveloperResponse `json:"clients"`
}

// Validate validates this clients for developer
func (m *ClientsForDeveloper) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClients(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClientsForDeveloper) validateClients(formats strfmt.Registry) error {
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
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("clients" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this clients for developer based on the context it is used
func (m *ClientsForDeveloper) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClients(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClientsForDeveloper) contextValidateClients(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Clients); i++ {

		if m.Clients[i] != nil {

			if swag.IsZero(m.Clients[i]) { // not required
				return nil
			}

			if err := m.Clients[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("clients" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("clients" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ClientsForDeveloper) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClientsForDeveloper) UnmarshalBinary(b []byte) error {
	var res ClientsForDeveloper
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
