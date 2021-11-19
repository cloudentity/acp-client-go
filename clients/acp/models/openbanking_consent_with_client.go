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

// OpenbankingConsentWithClient openbanking consent with client
//
// swagger:model OpenbankingConsentWithClient
type OpenbankingConsentWithClient struct {

	// client
	Client *OpenbankingClient `json:"Client,omitempty"`

	// account access consent
	AccountAccessConsent *AccountAccessConsent `json:"account_access_consent,omitempty"`

	// account ids
	AccountIds []string `json:"account_ids"`

	// client id
	ClientID string `json:"client_id,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// domestic payment consent
	DomesticPaymentConsent *DomesticPaymentConsent `json:"domestic_payment_consent,omitempty"`

	// domestic scheduled payment consent
	DomesticScheduledPaymentConsent *DomesticScheduledPaymentConsent `json:"domestic_scheduled_payment_consent,omitempty"`

	// domestic standing order consent
	DomesticStandingOrderConsent *DomesticStandingOrderConsent `json:"domestic_standing_order_consent,omitempty"`

	// file payment consent
	FilePaymentConsent *FilePaymentConsent `json:"file_payment_consent,omitempty"`

	// idempotency key
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// international payment consent
	InternationalPaymentConsent *InternationalPaymentConsent `json:"international_payment_consent,omitempty"`

	// international scheduled payment consent
	InternationalScheduledPaymentConsent *InternationalScheduledPaymentConsent `json:"international_scheduled_payment_consent,omitempty"`

	// international standing order consent
	InternationalStandingOrderConsent *InternationalStandingOrderConsent `json:"international_standing_order_consent,omitempty"`

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

// Validate validates this openbanking consent with client
func (m *OpenbankingConsentWithClient) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClient(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountAccessConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomesticPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomesticScheduledPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomesticStandingOrderConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilePaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInternationalPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInternationalScheduledPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInternationalStandingOrderConsent(formats); err != nil {
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

func (m *OpenbankingConsentWithClient) validateClient(formats strfmt.Registry) error {
	if swag.IsZero(m.Client) { // not required
		return nil
	}

	if m.Client != nil {
		if err := m.Client.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Client")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Client")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateAccountAccessConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.AccountAccessConsent) { // not required
		return nil
	}

	if m.AccountAccessConsent != nil {
		if err := m.AccountAccessConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("account_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateDomesticPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomesticPaymentConsent) { // not required
		return nil
	}

	if m.DomesticPaymentConsent != nil {
		if err := m.DomesticPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateDomesticScheduledPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomesticScheduledPaymentConsent) { // not required
		return nil
	}

	if m.DomesticScheduledPaymentConsent != nil {
		if err := m.DomesticScheduledPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_scheduled_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateDomesticStandingOrderConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.DomesticStandingOrderConsent) { // not required
		return nil
	}

	if m.DomesticStandingOrderConsent != nil {
		if err := m.DomesticStandingOrderConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_standing_order_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_standing_order_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateFilePaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.FilePaymentConsent) { // not required
		return nil
	}

	if m.FilePaymentConsent != nil {
		if err := m.FilePaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("file_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("file_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateInternationalPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.InternationalPaymentConsent) { // not required
		return nil
	}

	if m.InternationalPaymentConsent != nil {
		if err := m.InternationalPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateInternationalScheduledPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.InternationalScheduledPaymentConsent) { // not required
		return nil
	}

	if m.InternationalScheduledPaymentConsent != nil {
		if err := m.InternationalScheduledPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_scheduled_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateInternationalStandingOrderConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.InternationalStandingOrderConsent) { // not required
		return nil
	}

	if m.InternationalStandingOrderConsent != nil {
		if err := m.InternationalStandingOrderConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_standing_order_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_standing_order_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("type")
		}
		return err
	}

	return nil
}

// ContextValidate validate this openbanking consent with client based on the context it is used
func (m *OpenbankingConsentWithClient) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClient(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAccountAccessConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDomesticPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDomesticScheduledPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDomesticStandingOrderConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFilePaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInternationalPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInternationalScheduledPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInternationalStandingOrderConsent(ctx, formats); err != nil {
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

func (m *OpenbankingConsentWithClient) contextValidateClient(ctx context.Context, formats strfmt.Registry) error {

	if m.Client != nil {
		if err := m.Client.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Client")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Client")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateAccountAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountAccessConsent != nil {
		if err := m.AccountAccessConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("account_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("account_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateDomesticPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticPaymentConsent != nil {
		if err := m.DomesticPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateDomesticScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticScheduledPaymentConsent != nil {
		if err := m.DomesticScheduledPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_scheduled_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateDomesticStandingOrderConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticStandingOrderConsent != nil {
		if err := m.DomesticStandingOrderConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domestic_standing_order_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("domestic_standing_order_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateFilePaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.FilePaymentConsent != nil {
		if err := m.FilePaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("file_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("file_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateInternationalPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalPaymentConsent != nil {
		if err := m.InternationalPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateInternationalScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalScheduledPaymentConsent != nil {
		if err := m.InternationalScheduledPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_scheduled_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_scheduled_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateInternationalStandingOrderConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalStandingOrderConsent != nil {
		if err := m.InternationalStandingOrderConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("international_standing_order_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("international_standing_order_consent")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingConsentWithClient) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Type.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingConsentWithClient) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingConsentWithClient) UnmarshalBinary(b []byte) error {
	var res OpenbankingConsentWithClient
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}