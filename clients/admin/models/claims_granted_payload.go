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

// ClaimsGrantedPayload claims granted payload
//
// swagger:model ClaimsGrantedPayload
type ClaimsGrantedPayload struct {

	// List of claims to grant.
	NewClaimGrants []*ClaimGrant `json:"new_claim_grants" yaml:"new_claim_grants"`
}

// Validate validates this claims granted payload
func (m *ClaimsGrantedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNewClaimGrants(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClaimsGrantedPayload) validateNewClaimGrants(formats strfmt.Registry) error {
	if swag.IsZero(m.NewClaimGrants) { // not required
		return nil
	}

	for i := 0; i < len(m.NewClaimGrants); i++ {
		if swag.IsZero(m.NewClaimGrants[i]) { // not required
			continue
		}

		if m.NewClaimGrants[i] != nil {
			if err := m.NewClaimGrants[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("new_claim_grants" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("new_claim_grants" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this claims granted payload based on the context it is used
func (m *ClaimsGrantedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateNewClaimGrants(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClaimsGrantedPayload) contextValidateNewClaimGrants(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NewClaimGrants); i++ {

		if m.NewClaimGrants[i] != nil {

			if swag.IsZero(m.NewClaimGrants[i]) { // not required
				return nil
			}

			if err := m.NewClaimGrants[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("new_claim_grants" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("new_claim_grants" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ClaimsGrantedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClaimsGrantedPayload) UnmarshalBinary(b []byte) error {
	var res ClaimsGrantedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
