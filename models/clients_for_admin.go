// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ClientsForAdmin clients for admin
//
// swagger:model ClientsForAdmin
type ClientsForAdmin struct {

	// clients
	Clients []*ClientAdminResponse `json:"clients"`
}

// Validate validates this clients for admin
func (m *ClientsForAdmin) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClients(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClientsForAdmin) validateClients(formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *ClientsForAdmin) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClientsForAdmin) UnmarshalBinary(b []byte) error {
	var res ClientsForAdmin
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
