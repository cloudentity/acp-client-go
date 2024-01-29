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

// GatewayConfiguration gateway configuration
//
// swagger:model GatewayConfiguration
type GatewayConfiguration struct {

	// List of APIs that this gateway should protect.
	Apis []*API `json:"apis" yaml:"apis"`

	// Used to define how to split dynamic scopes
	DynamicScopeSeparator string `json:"dynamic_scope_separator,omitempty" yaml:"dynamic_scope_separator,omitempty"`

	// events per second limit
	EventsPerSecond int64 `json:"events_per_second,omitempty" yaml:"events_per_second,omitempty"`

	// issuer apis
	IssuerApis []*API `json:"issuer_apis" yaml:"issuer_apis"`

	// issuer policies
	IssuerPolicies []*Policy `json:"issuer_policies" yaml:"issuer_policies"`

	// Authorization server issuer url.
	IssuerURL string `json:"issuer_url,omitempty" yaml:"issuer_url,omitempty"`

	// Authorization server JWKs url.
	JwksURL string `json:"jwks_url,omitempty" yaml:"jwks_url,omitempty"`

	// List of policies that can be used to protect APIs.
	Policies []*Policy `json:"policies" yaml:"policies"`

	// List of scopes available in the server.
	Scopes []*ScopeWithService `json:"scopes" yaml:"scopes"`

	// ServerID that this gateway belongs to.
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// List of services that belongs to the server.
	Services []*ServiceConnectedToGateway `json:"services" yaml:"services"`

	// TenantID that this gateway belongs to.
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// Is token exchange enabled
	TokenExchangeEnabled bool `json:"token_exchange_enabled,omitempty" yaml:"token_exchange_enabled,omitempty"`
}

// Validate validates this gateway configuration
func (m *GatewayConfiguration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuerApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuerPolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServices(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GatewayConfiguration) validateApis(formats strfmt.Registry) error {
	if swag.IsZero(m.Apis) { // not required
		return nil
	}

	for i := 0; i < len(m.Apis); i++ {
		if swag.IsZero(m.Apis[i]) { // not required
			continue
		}

		if m.Apis[i] != nil {
			if err := m.Apis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) validateIssuerApis(formats strfmt.Registry) error {
	if swag.IsZero(m.IssuerApis) { // not required
		return nil
	}

	for i := 0; i < len(m.IssuerApis); i++ {
		if swag.IsZero(m.IssuerApis[i]) { // not required
			continue
		}

		if m.IssuerApis[i] != nil {
			if err := m.IssuerApis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issuer_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issuer_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) validateIssuerPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.IssuerPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.IssuerPolicies); i++ {
		if swag.IsZero(m.IssuerPolicies[i]) { // not required
			continue
		}

		if m.IssuerPolicies[i] != nil {
			if err := m.IssuerPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issuer_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issuer_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) validatePolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.Policies) { // not required
		return nil
	}

	for i := 0; i < len(m.Policies); i++ {
		if swag.IsZero(m.Policies[i]) { // not required
			continue
		}

		if m.Policies[i] != nil {
			if err := m.Policies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) validateScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.Scopes) { // not required
		return nil
	}

	for i := 0; i < len(m.Scopes); i++ {
		if swag.IsZero(m.Scopes[i]) { // not required
			continue
		}

		if m.Scopes[i] != nil {
			if err := m.Scopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) validateServices(formats strfmt.Registry) error {
	if swag.IsZero(m.Services) { // not required
		return nil
	}

	for i := 0; i < len(m.Services); i++ {
		if swag.IsZero(m.Services[i]) { // not required
			continue
		}

		if m.Services[i] != nil {
			if err := m.Services[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("services" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("services" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this gateway configuration based on the context it is used
func (m *GatewayConfiguration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIssuerApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIssuerPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GatewayConfiguration) contextValidateApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Apis); i++ {

		if m.Apis[i] != nil {

			if swag.IsZero(m.Apis[i]) { // not required
				return nil
			}

			if err := m.Apis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) contextValidateIssuerApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.IssuerApis); i++ {

		if m.IssuerApis[i] != nil {

			if swag.IsZero(m.IssuerApis[i]) { // not required
				return nil
			}

			if err := m.IssuerApis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issuer_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issuer_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) contextValidateIssuerPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.IssuerPolicies); i++ {

		if m.IssuerPolicies[i] != nil {

			if swag.IsZero(m.IssuerPolicies[i]) { // not required
				return nil
			}

			if err := m.IssuerPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issuer_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issuer_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) contextValidatePolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Policies); i++ {

		if m.Policies[i] != nil {

			if swag.IsZero(m.Policies[i]) { // not required
				return nil
			}

			if err := m.Policies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) contextValidateScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Scopes); i++ {

		if m.Scopes[i] != nil {

			if swag.IsZero(m.Scopes[i]) { // not required
				return nil
			}

			if err := m.Scopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GatewayConfiguration) contextValidateServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Services); i++ {

		if m.Services[i] != nil {

			if swag.IsZero(m.Services[i]) { // not required
				return nil
			}

			if err := m.Services[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("services" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("services" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *GatewayConfiguration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GatewayConfiguration) UnmarshalBinary(b []byte) error {
	var res GatewayConfiguration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
