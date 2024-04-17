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

// BrazilConsent brazil consent
//
// swagger:model BrazilConsent
type BrazilConsent struct {

	// account ids
	AccountIds []string `json:"account_ids" yaml:"account_ids"`

	// Client application identifier.
	// Example: \"cauqo9c9vpbs0aj2b2v0\
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// cnpj
	Cnpj string `json:"cnpj,omitempty" yaml:"cnpj,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty" yaml:"consent_id,omitempty"`

	// cpf
	Cpf string `json:"cpf,omitempty" yaml:"cpf,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty" yaml:"created_at,omitempty"`

	// customer data access consent
	CustomerDataAccessConsent *BrazilCustomerDataAccessConsentV1 `json:"customer_data_access_consent,omitempty" yaml:"customer_data_access_consent,omitempty"`

	// customer data access consent v2
	CustomerDataAccessConsentV2 *BrazilCustomerDataAccessConsentV2 `json:"customer_data_access_consent_v2,omitempty" yaml:"customer_data_access_consent_v2,omitempty"`

	// customer insurance data access consent
	CustomerInsuranceDataAccessConsent *BrazilInsuranceCustomerDataAccessConsent `json:"customer_insurance_data_access_consent,omitempty" yaml:"customer_insurance_data_access_consent,omitempty"`

	// customer payment consent
	CustomerPaymentConsent *BrazilCustomerPaymentConsent `json:"customer_payment_consent,omitempty" yaml:"customer_payment_consent,omitempty"`

	// customer payment consent v2
	CustomerPaymentConsentV2 *BrazilCustomerPaymentConsentV2 `json:"customer_payment_consent_v2,omitempty" yaml:"customer_payment_consent_v2,omitempty"`

	// customer payment consent v3
	CustomerPaymentConsentV3 *BrazilCustomerPaymentConsentV3 `json:"customer_payment_consent_v3,omitempty" yaml:"customer_payment_consent_v3,omitempty"`

	// customer payment consent v4
	CustomerPaymentConsentV4 *BrazilCustomerPaymentConsentV4 `json:"customer_payment_consent_v4,omitempty" yaml:"customer_payment_consent_v4,omitempty"`

	// customer recurring payment consent v1
	CustomerRecurringPaymentConsentV1 *BrazilCustomerRecurringPaymentConsentV1 `json:"customer_recurring_payment_consent_v1,omitempty" yaml:"customer_recurring_payment_consent_v1,omitempty"`

	// idempotency key
	IdempotencyKey string `json:"idempotency_key,omitempty" yaml:"idempotency_key,omitempty"`

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

// Validate validates this brazil consent
func (m *BrazilConsent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerDataAccessConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerDataAccessConsentV2(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerInsuranceDataAccessConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsentV2(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsentV3(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsentV4(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerRecurringPaymentConsentV1(formats); err != nil {
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

func (m *BrazilConsent) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *BrazilConsent) validateCustomerDataAccessConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerDataAccessConsent) { // not required
		return nil
	}

	if m.CustomerDataAccessConsent != nil {
		if err := m.CustomerDataAccessConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_data_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_data_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerDataAccessConsentV2(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerDataAccessConsentV2) { // not required
		return nil
	}

	if m.CustomerDataAccessConsentV2 != nil {
		if err := m.CustomerDataAccessConsentV2.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_data_access_consent_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_data_access_consent_v2")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerInsuranceDataAccessConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerInsuranceDataAccessConsent) { // not required
		return nil
	}

	if m.CustomerInsuranceDataAccessConsent != nil {
		if err := m.CustomerInsuranceDataAccessConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_insurance_data_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_insurance_data_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerPaymentConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsent) { // not required
		return nil
	}

	if m.CustomerPaymentConsent != nil {
		if err := m.CustomerPaymentConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerPaymentConsentV2(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsentV2) { // not required
		return nil
	}

	if m.CustomerPaymentConsentV2 != nil {
		if err := m.CustomerPaymentConsentV2.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v2")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerPaymentConsentV3(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsentV3) { // not required
		return nil
	}

	if m.CustomerPaymentConsentV3 != nil {
		if err := m.CustomerPaymentConsentV3.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v3")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v3")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerPaymentConsentV4(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsentV4) { // not required
		return nil
	}

	if m.CustomerPaymentConsentV4 != nil {
		if err := m.CustomerPaymentConsentV4.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v4")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v4")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateCustomerRecurringPaymentConsentV1(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerRecurringPaymentConsentV1) { // not required
		return nil
	}

	if m.CustomerRecurringPaymentConsentV1 != nil {
		if err := m.CustomerRecurringPaymentConsentV1.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_recurring_payment_consent_v1")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_recurring_payment_consent_v1")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) validateSpecVersion(formats strfmt.Registry) error {
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

func (m *BrazilConsent) validateType(formats strfmt.Registry) error {
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

// ContextValidate validate this brazil consent based on the context it is used
func (m *BrazilConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCustomerDataAccessConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerDataAccessConsentV2(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerInsuranceDataAccessConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsentV2(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsentV3(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsentV4(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerRecurringPaymentConsentV1(ctx, formats); err != nil {
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

func (m *BrazilConsent) contextValidateCustomerDataAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerDataAccessConsent != nil {

		if swag.IsZero(m.CustomerDataAccessConsent) { // not required
			return nil
		}

		if err := m.CustomerDataAccessConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_data_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_data_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerDataAccessConsentV2(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerDataAccessConsentV2 != nil {

		if swag.IsZero(m.CustomerDataAccessConsentV2) { // not required
			return nil
		}

		if err := m.CustomerDataAccessConsentV2.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_data_access_consent_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_data_access_consent_v2")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerInsuranceDataAccessConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerInsuranceDataAccessConsent != nil {

		if swag.IsZero(m.CustomerInsuranceDataAccessConsent) { // not required
			return nil
		}

		if err := m.CustomerInsuranceDataAccessConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_insurance_data_access_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_insurance_data_access_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerPaymentConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsent != nil {

		if swag.IsZero(m.CustomerPaymentConsent) { // not required
			return nil
		}

		if err := m.CustomerPaymentConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerPaymentConsentV2(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsentV2 != nil {

		if swag.IsZero(m.CustomerPaymentConsentV2) { // not required
			return nil
		}

		if err := m.CustomerPaymentConsentV2.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v2")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerPaymentConsentV3(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsentV3 != nil {

		if swag.IsZero(m.CustomerPaymentConsentV3) { // not required
			return nil
		}

		if err := m.CustomerPaymentConsentV3.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v3")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v3")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerPaymentConsentV4(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsentV4 != nil {

		if swag.IsZero(m.CustomerPaymentConsentV4) { // not required
			return nil
		}

		if err := m.CustomerPaymentConsentV4.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v4")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v4")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateCustomerRecurringPaymentConsentV1(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerRecurringPaymentConsentV1 != nil {

		if swag.IsZero(m.CustomerRecurringPaymentConsentV1) { // not required
			return nil
		}

		if err := m.CustomerRecurringPaymentConsentV1.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_recurring_payment_consent_v1")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_recurring_payment_consent_v1")
			}
			return err
		}
	}

	return nil
}

func (m *BrazilConsent) contextValidateSpecVersion(ctx context.Context, formats strfmt.Registry) error {

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

func (m *BrazilConsent) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

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
func (m *BrazilConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BrazilConsent) UnmarshalBinary(b []byte) error {
	var res BrazilConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
