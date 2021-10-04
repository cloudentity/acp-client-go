// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ConsentRevokedEvent consent revoked event
//
// swagger:model ConsentRevokedEvent
type ConsentRevokedEvent struct {

	// time when the grant occurred
	// Example: 1257894000000000000
	CollectionTimestamp int64 `json:"collection_timestamp,omitempty"`

	// consent
	Consent *Consent `json:"consent,omitempty"`

	// consent grant id
	// Example: 27fa83a8-d0a6-48da-8529-42105bfa0ede
	ConsentGrantActID string `json:"consent_grant_act_id,omitempty"`

	// consent id
	// Example: 1
	ConsentID string `json:"consent_id,omitempty"`

	// context
	Context *ConsentGrantContext `json:"context,omitempty"`

	// given at timestamp
	// Format: date-time
	GivenAt strfmt.DateTime `json:"given_at,omitempty"`

	// grant type, one of: implicit, explicit
	// Example: implicit
	GrantType string `json:"grant_type,omitempty"`

	// language in which the consent was obtained [ISO 639]
	// Example: en
	Language string `json:"language,omitempty"`

	// subject
	// Example: peter
	Subject string `json:"subject,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// optional string with action_id - can be set if the consent grant/withdraw request was caused when an app asked the user for consent required for a specific action
	// Example: 1
	TriggeredByAction string `json:"triggered_by_action,omitempty"`

	// version
	// Example: 1
	Version int64 `json:"version,omitempty"`
}

// Validate validates this consent revoked event
func (m *ConsentRevokedEvent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGivenAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentRevokedEvent) validateConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.Consent) { // not required
		return nil
	}

	if m.Consent != nil {
		if err := m.Consent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("consent")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentRevokedEvent) validateContext(formats strfmt.Registry) error {
	if swag.IsZero(m.Context) { // not required
		return nil
	}

	if m.Context != nil {
		if err := m.Context.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("context")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentRevokedEvent) validateGivenAt(formats strfmt.Registry) error {
	if swag.IsZero(m.GivenAt) { // not required
		return nil
	}

	if err := validate.FormatOf("given_at", "body", "date-time", m.GivenAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this consent revoked event based on the context it is used
func (m *ConsentRevokedEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentRevokedEvent) contextValidateConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.Consent != nil {
		if err := m.Consent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("consent")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentRevokedEvent) contextValidateContext(ctx context.Context, formats strfmt.Registry) error {

	if m.Context != nil {
		if err := m.Context.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("context")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConsentRevokedEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentRevokedEvent) UnmarshalBinary(b []byte) error {
	var res ConsentRevokedEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
