// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ServiceWithScopesAndAPIs service with scopes and a p is
//
// swagger:model ServiceWithScopesAndAPIs
type ServiceWithScopesAndAPIs struct {

	// list of apis
	Apis []*API `json:"apis"`

	// Authorization server identifier
	// Example: my-server
	AuthorizationServerID string `json:"authorization_server_id,omitempty"`

	// Custom service audience
	// Example: https://api.example.com
	CustomAudience string `json:"custom_audience,omitempty"`

	// Service description
	// Example: Service description
	Description string `json:"description,omitempty"`

	// Gateway identifier
	// Example: gateway-1
	GatewayID string `json:"gateway_id,omitempty"`

	// A unique identifier of a service
	// Example: service-1
	ID string `json:"id,omitempty"`

	// Service name
	// Example: My service
	Name string `json:"name,omitempty"`

	// list of scopes
	Scopes []*Scope `json:"scopes"`

	// `true` when the service is a system service
	// Example: false
	System bool `json:"system,omitempty"`

	// Tenant identifier
	// Example: my-company
	TenantID string `json:"tenant_id,omitempty"`

	// Service type
	// Enum: [oauth2 oidc system user openbanking]
	Type string `json:"type,omitempty"`

	// The date of service update
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty"`

	// `true` when the service has the OpenAPI 3.0 specification
	WithSpecification bool `json:"with_specification,omitempty"`
}

// Validate validates this service with scopes and a p is
func (m *ServiceWithScopesAndAPIs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServiceWithScopesAndAPIs) validateApis(formats strfmt.Registry) error {
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

func (m *ServiceWithScopesAndAPIs) validateScopes(formats strfmt.Registry) error {
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

var serviceWithScopesAndAPIsTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["oauth2","oidc","system","user","openbanking"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		serviceWithScopesAndAPIsTypeTypePropEnum = append(serviceWithScopesAndAPIsTypeTypePropEnum, v)
	}
}

const (

	// ServiceWithScopesAndAPIsTypeOauth2 captures enum value "oauth2"
	ServiceWithScopesAndAPIsTypeOauth2 string = "oauth2"

	// ServiceWithScopesAndAPIsTypeOidc captures enum value "oidc"
	ServiceWithScopesAndAPIsTypeOidc string = "oidc"

	// ServiceWithScopesAndAPIsTypeSystem captures enum value "system"
	ServiceWithScopesAndAPIsTypeSystem string = "system"

	// ServiceWithScopesAndAPIsTypeUser captures enum value "user"
	ServiceWithScopesAndAPIsTypeUser string = "user"

	// ServiceWithScopesAndAPIsTypeOpenbanking captures enum value "openbanking"
	ServiceWithScopesAndAPIsTypeOpenbanking string = "openbanking"
)

// prop value enum
func (m *ServiceWithScopesAndAPIs) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, serviceWithScopesAndAPIsTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ServiceWithScopesAndAPIs) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *ServiceWithScopesAndAPIs) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this service with scopes and a p is based on the context it is used
func (m *ServiceWithScopesAndAPIs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServiceWithScopesAndAPIs) contextValidateApis(ctx context.Context, formats strfmt.Registry) error {

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

func (m *ServiceWithScopesAndAPIs) contextValidateScopes(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *ServiceWithScopesAndAPIs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServiceWithScopesAndAPIs) UnmarshalBinary(b []byte) error {
	var res ServiceWithScopesAndAPIs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
