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

// ImportServiceConfigurationResult import service configuration result
//
// swagger:model ImportServiceConfigurationResult
type ImportServiceConfigurationResult struct {

	// server id
	// Example: default
	AuthorizationServerID string `json:"authorization_server_id,omitempty"`

	// created apis
	CreatedApis []*API `json:"created_apis"`

	// created policies
	CreatedPolicies []*Policy `json:"created_policies"`

	// created scopes
	CreatedScopes []*Scope `json:"created_scopes"`

	// custom service audience
	// Example: https://api.example.com
	CustomAudience string `json:"custom_audience,omitempty"`

	// service description
	// Example: Service description
	Description string `json:"description,omitempty"`

	// gateway id
	GatewayID string `json:"gateway_id,omitempty"`

	// unique service id
	// Example: 1
	ID string `json:"id,omitempty"`

	// service name
	// Example: Sample service
	Name string `json:"name,omitempty"`

	// not removed policies
	NotRemovedPolicies []*Policy `json:"not_removed_policies"`

	// removed apis
	RemovedApis []*API `json:"removed_apis"`

	// removed policies
	RemovedPolicies []*Policy `json:"removed_policies"`

	// Is service a system service
	// Example: false
	System bool `json:"system,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// service type
	// Enum: [oauth2 oidc system user openbanking]
	Type string `json:"type,omitempty"`

	// Updated at date
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty"`

	// true if service has openapi 3 specification
	WithSpecification bool `json:"with_specification,omitempty"`
}

// Validate validates this import service configuration result
func (m *ImportServiceConfigurationResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedPolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNotRemovedPolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemovedApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemovedPolicies(formats); err != nil {
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

func (m *ImportServiceConfigurationResult) validateCreatedApis(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedApis) { // not required
		return nil
	}

	for i := 0; i < len(m.CreatedApis); i++ {
		if swag.IsZero(m.CreatedApis[i]) { // not required
			continue
		}

		if m.CreatedApis[i] != nil {
			if err := m.CreatedApis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateCreatedPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.CreatedPolicies); i++ {
		if swag.IsZero(m.CreatedPolicies[i]) { // not required
			continue
		}

		if m.CreatedPolicies[i] != nil {
			if err := m.CreatedPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateCreatedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedScopes) { // not required
		return nil
	}

	for i := 0; i < len(m.CreatedScopes); i++ {
		if swag.IsZero(m.CreatedScopes[i]) { // not required
			continue
		}

		if m.CreatedScopes[i] != nil {
			if err := m.CreatedScopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateNotRemovedPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.NotRemovedPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.NotRemovedPolicies); i++ {
		if swag.IsZero(m.NotRemovedPolicies[i]) { // not required
			continue
		}

		if m.NotRemovedPolicies[i] != nil {
			if err := m.NotRemovedPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateRemovedApis(formats strfmt.Registry) error {
	if swag.IsZero(m.RemovedApis) { // not required
		return nil
	}

	for i := 0; i < len(m.RemovedApis); i++ {
		if swag.IsZero(m.RemovedApis[i]) { // not required
			continue
		}

		if m.RemovedApis[i] != nil {
			if err := m.RemovedApis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateRemovedPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.RemovedPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.RemovedPolicies); i++ {
		if swag.IsZero(m.RemovedPolicies[i]) { // not required
			continue
		}

		if m.RemovedPolicies[i] != nil {
			if err := m.RemovedPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var importServiceConfigurationResultTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["oauth2","oidc","system","user","openbanking"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		importServiceConfigurationResultTypeTypePropEnum = append(importServiceConfigurationResultTypeTypePropEnum, v)
	}
}

const (

	// ImportServiceConfigurationResultTypeOauth2 captures enum value "oauth2"
	ImportServiceConfigurationResultTypeOauth2 string = "oauth2"

	// ImportServiceConfigurationResultTypeOidc captures enum value "oidc"
	ImportServiceConfigurationResultTypeOidc string = "oidc"

	// ImportServiceConfigurationResultTypeSystem captures enum value "system"
	ImportServiceConfigurationResultTypeSystem string = "system"

	// ImportServiceConfigurationResultTypeUser captures enum value "user"
	ImportServiceConfigurationResultTypeUser string = "user"

	// ImportServiceConfigurationResultTypeOpenbanking captures enum value "openbanking"
	ImportServiceConfigurationResultTypeOpenbanking string = "openbanking"
)

// prop value enum
func (m *ImportServiceConfigurationResult) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, importServiceConfigurationResultTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ImportServiceConfigurationResult) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *ImportServiceConfigurationResult) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this import service configuration result based on the context it is used
func (m *ImportServiceConfigurationResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreatedApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreatedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreatedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNotRemovedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemovedApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemovedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateCreatedApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CreatedApis); i++ {

		if m.CreatedApis[i] != nil {
			if err := m.CreatedApis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateCreatedPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CreatedPolicies); i++ {

		if m.CreatedPolicies[i] != nil {
			if err := m.CreatedPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateCreatedScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CreatedScopes); i++ {

		if m.CreatedScopes[i] != nil {
			if err := m.CreatedScopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("created_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("created_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateNotRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NotRemovedPolicies); i++ {

		if m.NotRemovedPolicies[i] != nil {
			if err := m.NotRemovedPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateRemovedApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RemovedApis); i++ {

		if m.RemovedApis[i] != nil {
			if err := m.RemovedApis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ImportServiceConfigurationResult) contextValidateRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RemovedPolicies); i++ {

		if m.RemovedPolicies[i] != nil {
			if err := m.RemovedPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ImportServiceConfigurationResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ImportServiceConfigurationResult) UnmarshalBinary(b []byte) error {
	var res ImportServiceConfigurationResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
