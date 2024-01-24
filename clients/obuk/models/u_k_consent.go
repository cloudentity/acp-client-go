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

// UKConsent u k consent
//
// swagger:model UKConsent
type UKConsent struct {

	// account access consent
	AccountAccessConsent *AccountAccessConsent `json:"account_access_consent,omitempty" yaml:"account_access_consent,omitempty"`

	// account ids
	AccountIds []string `json:"account_ids" yaml:"account_ids"`

	// Client application identifier.
	// Example: \"cauqo9c9vpbs0aj2b2v0\
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty" yaml:"consent_id,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty" yaml:"created_at,omitempty"`

	// domestic payment consent
	DomesticPaymentConsent *DomesticPaymentConsent `json:"domestic_payment_consent,omitempty" yaml:"domestic_payment_consent,omitempty"`

	// domestic scheduled payment consent
	DomesticScheduledPaymentConsent *DomesticScheduledPaymentConsent `json:"domestic_scheduled_payment_consent,omitempty" yaml:"domestic_scheduled_payment_consent,omitempty"`

	// domestic standing order consent
	DomesticStandingOrderConsent *DomesticStandingOrderConsent `json:"domestic_standing_order_consent,omitempty" yaml:"domestic_standing_order_consent,omitempty"`

	// file payment consent
	FilePaymentConsent *FilePaymentConsent `json:"file_payment_consent,omitempty" yaml:"file_payment_consent,omitempty"`

	// idempotency key
	IdempotencyKey string `json:"idempotency_key,omitempty" yaml:"idempotency_key,omitempty"`

	// international payment consent
	InternationalPaymentConsent *InternationalPaymentConsent `json:"international_payment_consent,omitempty" yaml:"international_payment_consent,omitempty"`

	// international scheduled payment consent
	InternationalScheduledPaymentConsent *InternationalScheduledPaymentConsent `json:"international_scheduled_payment_consent,omitempty" yaml:"international_scheduled_payment_consent,omitempty"`

	// international standing order consent
	InternationalStandingOrderConsent *InternationalStandingOrderConsent `json:"international_standing_order_consent,omitempty" yaml:"international_standing_order_consent,omitempty"`

	// request hash
	RequestHash string `json:"request_hash,omitempty" yaml:"request_hash,omitempty"`

	// Server / Workspace identifier.
	// Example: \"server\
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// spec
	Spec string `json:"spec,omitempty" yaml:"spec,omitempty"`

	// spec version
	SpecVersion SpecVersion `json:"spec_version,omitempty" yaml:"spec_version,omitempty"`

	// status
	Status string `json:"status,omitempty" yaml:"status,omitempty"`

	// Tenant identifier.
	// Example: \"tenant\
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this u k consent
func (m *UKConsent) Validate(formats strfmt.Registry) error {
	var res []error

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

	if err := m.validateSpecVersion(formats); err != nil {
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

func (m *UKConsent) validateAccountAccessConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UKConsent) validateDomesticPaymentConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateDomesticScheduledPaymentConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateDomesticStandingOrderConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateFilePaymentConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateInternationalPaymentConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateInternationalScheduledPaymentConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateInternationalStandingOrderConsent(formats strfmt.Registry) error {
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

func (m *UKConsent) validateSpecVersion(formats strfmt.Registry) error {
	if swag.IsZero(m.SpecVersion) { // not required
		return nil
	}

	if err := m.SpecVersion.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("spec_version")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("spec_version")
		}
		return err
	}

	return nil
}

func (m *UKConsent) validateType(formats strfmt.Registry) error {
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

// ContextValidate validate this u k consent based on the context it is used
func (m *UKConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

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

	if err := m.contextValidateSpecVersion(ctx, formats); err != nil {
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

func (m *UKConsent) contextValidateAccountAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountAccessConsent != nil {

		if swag.IsZero(m.AccountAccessConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateDomesticPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticPaymentConsent != nil {

		if swag.IsZero(m.DomesticPaymentConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateDomesticScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticScheduledPaymentConsent != nil {

		if swag.IsZero(m.DomesticScheduledPaymentConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateDomesticStandingOrderConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.DomesticStandingOrderConsent != nil {

		if swag.IsZero(m.DomesticStandingOrderConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateFilePaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.FilePaymentConsent != nil {

		if swag.IsZero(m.FilePaymentConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateInternationalPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalPaymentConsent != nil {

		if swag.IsZero(m.InternationalPaymentConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateInternationalScheduledPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalScheduledPaymentConsent != nil {

		if swag.IsZero(m.InternationalScheduledPaymentConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateInternationalStandingOrderConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.InternationalStandingOrderConsent != nil {

		if swag.IsZero(m.InternationalStandingOrderConsent) { // not required
			return nil
		}

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

func (m *UKConsent) contextValidateSpecVersion(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.SpecVersion) { // not required
		return nil
	}

	if err := m.SpecVersion.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("spec_version")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("spec_version")
		}
		return err
	}

	return nil
}

func (m *UKConsent) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

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
func (m *UKConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UKConsent) UnmarshalBinary(b []byte) error {
	var res UKConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
