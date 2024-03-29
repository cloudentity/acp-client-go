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

// SelfUserWithDataV2 self user with data v2
//
// swagger:model SelfUserWithDataV2
type SelfUserWithDataV2 struct {

	// credentials
	Credentials []*SelfUserCredentials `json:"credentials" yaml:"credentials"`

	// federated accounts
	FederatedAccounts []*FederatedAccount `json:"federated_accounts" yaml:"federated_accounts"`

	// id
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// identifiers
	Identifiers []*SelfUserIdentifier `json:"identifiers" yaml:"identifiers"`

	// metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// payload
	Payload map[string]interface{} `json:"payload,omitempty" yaml:"payload,omitempty"`

	// payload schema
	PayloadSchema *SupportedJSONSchema `json:"payload_schema,omitempty" yaml:"payload_schema,omitempty"`

	// verifiable addresses
	VerifiableAddresses []*SelfUserVerifiableAddress `json:"verifiable_addresses" yaml:"verifiable_addresses"`
}

// Validate validates this self user with data v2
func (m *SelfUserWithDataV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCredentials(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFederatedAccounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentifiers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayloadSchema(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerifiableAddresses(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfUserWithDataV2) validateCredentials(formats strfmt.Registry) error {
	if swag.IsZero(m.Credentials) { // not required
		return nil
	}

	for i := 0; i < len(m.Credentials); i++ {
		if swag.IsZero(m.Credentials[i]) { // not required
			continue
		}

		if m.Credentials[i] != nil {
			if err := m.Credentials[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) validateFederatedAccounts(formats strfmt.Registry) error {
	if swag.IsZero(m.FederatedAccounts) { // not required
		return nil
	}

	for i := 0; i < len(m.FederatedAccounts); i++ {
		if swag.IsZero(m.FederatedAccounts[i]) { // not required
			continue
		}

		if m.FederatedAccounts[i] != nil {
			if err := m.FederatedAccounts[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("federated_accounts" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("federated_accounts" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) validateIdentifiers(formats strfmt.Registry) error {
	if swag.IsZero(m.Identifiers) { // not required
		return nil
	}

	for i := 0; i < len(m.Identifiers); i++ {
		if swag.IsZero(m.Identifiers[i]) { // not required
			continue
		}

		if m.Identifiers[i] != nil {
			if err := m.Identifiers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("identifiers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("identifiers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) validatePayloadSchema(formats strfmt.Registry) error {
	if swag.IsZero(m.PayloadSchema) { // not required
		return nil
	}

	if m.PayloadSchema != nil {
		if err := m.PayloadSchema.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload_schema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payload_schema")
			}
			return err
		}
	}

	return nil
}

func (m *SelfUserWithDataV2) validateVerifiableAddresses(formats strfmt.Registry) error {
	if swag.IsZero(m.VerifiableAddresses) { // not required
		return nil
	}

	for i := 0; i < len(m.VerifiableAddresses); i++ {
		if swag.IsZero(m.VerifiableAddresses[i]) { // not required
			continue
		}

		if m.VerifiableAddresses[i] != nil {
			if err := m.VerifiableAddresses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this self user with data v2 based on the context it is used
func (m *SelfUserWithDataV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFederatedAccounts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIdentifiers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePayloadSchema(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerifiableAddresses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelfUserWithDataV2) contextValidateCredentials(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Credentials); i++ {

		if m.Credentials[i] != nil {

			if swag.IsZero(m.Credentials[i]) { // not required
				return nil
			}

			if err := m.Credentials[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) contextValidateFederatedAccounts(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.FederatedAccounts); i++ {

		if m.FederatedAccounts[i] != nil {

			if swag.IsZero(m.FederatedAccounts[i]) { // not required
				return nil
			}

			if err := m.FederatedAccounts[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("federated_accounts" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("federated_accounts" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) contextValidateIdentifiers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Identifiers); i++ {

		if m.Identifiers[i] != nil {

			if swag.IsZero(m.Identifiers[i]) { // not required
				return nil
			}

			if err := m.Identifiers[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("identifiers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("identifiers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SelfUserWithDataV2) contextValidatePayloadSchema(ctx context.Context, formats strfmt.Registry) error {

	if m.PayloadSchema != nil {

		if swag.IsZero(m.PayloadSchema) { // not required
			return nil
		}

		if err := m.PayloadSchema.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload_schema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payload_schema")
			}
			return err
		}
	}

	return nil
}

func (m *SelfUserWithDataV2) contextValidateVerifiableAddresses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.VerifiableAddresses); i++ {

		if m.VerifiableAddresses[i] != nil {

			if swag.IsZero(m.VerifiableAddresses[i]) { // not required
				return nil
			}

			if err := m.VerifiableAddresses[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("verifiable_addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *SelfUserWithDataV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelfUserWithDataV2) UnmarshalBinary(b []byte) error {
	var res SelfUserWithDataV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
