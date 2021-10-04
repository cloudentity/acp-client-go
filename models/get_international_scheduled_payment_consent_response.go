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
	"github.com/go-openapi/validate"
)

// GetInternationalScheduledPaymentConsentResponse get international scheduled payment consent response
//
// swagger:model GetInternationalScheduledPaymentConsentResponse
type GetInternationalScheduledPaymentConsentResponse struct {

	// account ids
	AccountIds []string `json:"account_ids"`

	// authentication context
	AuthenticationContext AuthenticationContext `json:"authentication_context,omitempty"`

	// client id
	ClientID string `json:"client_id,omitempty"`

	// client info
	ClientInfo *ClientInfo `json:"client_info,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// international scheduled payment consent
	InternationalScheduledPaymentConsent *InternationalScheduledPaymentConsent `json:"international_scheduled_payment_consent,omitempty"`

	// requested scopes
	RequestedScopes []*RequestedScope `json:"requested_scopes"`

	// server id
	ServerID string `json:"server_id,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// subject
	Subject string `json:"subject,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty"`
}

// Validate validates this get international scheduled payment consent response
func (m *GetInternationalScheduledPaymentConsentResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInternationalScheduledPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedScopes(formats); err != nil {
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

func (m *GetInternationalScheduledPaymentConsentResponse) validateAuthenticationContext(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if m.AuthenticationContext != nil {
		if err := m.AuthenticationContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context")
			}
			return err
		}
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) validateClientInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.ClientInfo) { // not required
		return nil
	}

	if m.ClientInfo != nil {
		if err := m.ClientInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) validateInternationalScheduledPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.InternationalScheduledPaymentConsent) { // not required
		return nil
	}

	if m.InternationalScheduledPaymentConsent != nil {
		if err := m.InternationalScheduledPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) validateRequestedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedScopes) { // not required
		return nil
	}

	for i := 0; i < len(m.RequestedScopes); i++ {
		if swag.IsZero(m.RequestedScopes[i]) { // not required
			continue
		}

		if m.RequestedScopes[i] != nil {
			if err := m.RequestedScopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) validateType(formats strfmt.Registry) error {
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

// ContextValidate validate this get international scheduled payment consent response based on the context it is used
func (m *GetInternationalScheduledPaymentConsentResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClientInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInternationalScheduledPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestedScopes(ctx, formats); err != nil {
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

func (m *GetInternationalScheduledPaymentConsentResponse) contextValidateAuthenticationContext(ctx context.Context, formats strfmt.Registry) error {

	if err := m.AuthenticationContext.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_context")
		}
		return err
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) contextValidateClientInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.ClientInfo != nil {
		if err := m.ClientInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) contextValidateInternationalScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalScheduledPaymentConsent != nil {
		if err := m.InternationalScheduledPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) contextValidateRequestedScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RequestedScopes); i++ {

		if m.RequestedScopes[i] != nil {
			if err := m.RequestedScopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GetInternationalScheduledPaymentConsentResponse) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Type.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GetInternationalScheduledPaymentConsentResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetInternationalScheduledPaymentConsentResponse) UnmarshalBinary(b []byte) error {
	var res GetInternationalScheduledPaymentConsentResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
