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

// OBBRConsentWithClient o b b r consent with client
//
// swagger:model OBBRConsentWithClient
type OBBRConsentWithClient struct {

	// client
	Client *OpenbankingClient `json:"Client,omitempty"`

	// customer data access consent
	CustomerDataAccessConsent *OBBRCustomerDataAccessConsent `json:"CustomerDataAccessConsent,omitempty"`

	// customer payment consent
	CustomerPaymentConsent *OBBRCustomerPaymentConsent `json:"CustomerPaymentConsent,omitempty"`

	// account ids
	AccountIds []string `json:"account_ids"`

	// client id
	ClientID string `json:"client_id,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// idempotency key
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// request hash
	RequestHash string `json:"request_hash,omitempty"`

	// server id
	ServerID string `json:"server_id,omitempty"`

	// spec
	Spec string `json:"spec,omitempty"`

	// spec version
	SpecVersion string `json:"spec_version,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty"`
}

// Validate validates this o b b r consent with client
func (m *OBBRConsentWithClient) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClient(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerDataAccessConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBBRConsentWithClient) validateClient(formats strfmt.Registry) error {
	if swag.IsZero(m.Client) { // not required
		return nil
	}

	if m.Client != nil {
		if err := m.Client.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Client")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) validateCustomerDataAccessConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerDataAccessConsent) { // not required
		return nil
	}

	if m.CustomerDataAccessConsent != nil {
		if err := m.CustomerDataAccessConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CustomerDataAccessConsent")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) validateCustomerPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsent) { // not required
		return nil
	}

	if m.CustomerPaymentConsent != nil {
		if err := m.CustomerPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CustomerPaymentConsent")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OBBRConsentWithClient) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// ContextValidate validate this o b b r consent with client based on the context it is used
func (m *OBBRConsentWithClient) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClient(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerDataAccessConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBBRConsentWithClient) contextValidateClient(ctx context.Context, formats strfmt.Registry) error {

	if m.Client != nil {
		if err := m.Client.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Client")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) contextValidateCustomerDataAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerDataAccessConsent != nil {
		if err := m.CustomerDataAccessConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CustomerDataAccessConsent")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) contextValidateCustomerPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsent != nil {
		if err := m.CustomerPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CustomerPaymentConsent")
			}
			return err
		}
	}

	return nil
}

func (m *OBBRConsentWithClient) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Type.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OBBRConsentWithClient) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBBRConsentWithClient) UnmarshalBinary(b []byte) error {
	var res OBBRConsentWithClient
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
