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

// Authentication Authentication method definition
//
// ID is unique identifier across authentication methods.
// One of the following authentication method should be set: oidc, static, custom.
// Depending on chosen method, you need to provide oidc, static, custom settings accordingly.
//
// swagger:model Authentication
type Authentication struct {

	// static authentication method references
	//
	// if set overwrites amr obtained from this authentication method
	AMR []string `json:"amr"`

	// flag to disable authentication method
	// Example: false
	Disabled bool `json:"disabled,omitempty"`

	// authentication method identifier
	// Example: oidc
	// Required: true
	ID *string `json:"id"`

	// human readable name which will be displayed to user in case of multiple authentication methods
	// Example: OIDC
	// Required: true
	Name *string `json:"name"`

	// attributes
	Attributes Attributes `json:"attributes,omitempty"`

	// azure
	Azure *AzureAuthentication `json:"azure,omitempty"`

	// azureb2c
	Azureb2c *AzureB2CAuthentication `json:"azureb2c,omitempty"`

	// cognito
	Cognito *CognitoAuthentication `json:"cognito,omitempty"`

	// custom
	Custom *CustomAuthentication `json:"custom,omitempty"`

	// github
	Github *GithubAuthentication `json:"github,omitempty"`

	// intelli trust
	IntelliTrust *IntelliTrustAuthentication `json:"intelli_trust,omitempty"`

	// mappings
	Mappings Mappings `json:"mappings,omitempty"`

	// method
	// Required: true
	Method *AuthenticationMethod `json:"method"`

	// oidc
	Oidc *OIDCAuthentication `json:"oidc,omitempty"`

	// okta
	Okta *OktaAuthentication `json:"okta,omitempty"`

	// saml
	Saml *SAMLAuthentication `json:"saml,omitempty"`

	// static
	Static *StaticAuthentication `json:"static,omitempty"`
}

// Validate validates this authentication
func (m *Authentication) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAzure(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAzureb2c(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCognito(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustom(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGithub(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntelliTrust(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMappings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOidc(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOkta(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSaml(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatic(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authentication) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *Authentication) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *Authentication) validateAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.Attributes) { // not required
		return nil
	}

	if err := m.Attributes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attributes")
		}
		return err
	}

	return nil
}

func (m *Authentication) validateAzure(formats strfmt.Registry) error {
	if swag.IsZero(m.Azure) { // not required
		return nil
	}

	if m.Azure != nil {
		if err := m.Azure.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateAzureb2c(formats strfmt.Registry) error {
	if swag.IsZero(m.Azureb2c) { // not required
		return nil
	}

	if m.Azureb2c != nil {
		if err := m.Azureb2c.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azureb2c")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateCognito(formats strfmt.Registry) error {
	if swag.IsZero(m.Cognito) { // not required
		return nil
	}

	if m.Cognito != nil {
		if err := m.Cognito.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cognito")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateCustom(formats strfmt.Registry) error {
	if swag.IsZero(m.Custom) { // not required
		return nil
	}

	if m.Custom != nil {
		if err := m.Custom.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("custom")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateGithub(formats strfmt.Registry) error {
	if swag.IsZero(m.Github) { // not required
		return nil
	}

	if m.Github != nil {
		if err := m.Github.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("github")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateIntelliTrust(formats strfmt.Registry) error {
	if swag.IsZero(m.IntelliTrust) { // not required
		return nil
	}

	if m.IntelliTrust != nil {
		if err := m.IntelliTrust.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("intelli_trust")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateMappings(formats strfmt.Registry) error {
	if swag.IsZero(m.Mappings) { // not required
		return nil
	}

	if err := m.Mappings.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *Authentication) validateMethod(formats strfmt.Registry) error {

	if err := validate.Required("method", "body", m.Method); err != nil {
		return err
	}

	if err := validate.Required("method", "body", m.Method); err != nil {
		return err
	}

	if m.Method != nil {
		if err := m.Method.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("method")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateOidc(formats strfmt.Registry) error {
	if swag.IsZero(m.Oidc) { // not required
		return nil
	}

	if m.Oidc != nil {
		if err := m.Oidc.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("oidc")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateOkta(formats strfmt.Registry) error {
	if swag.IsZero(m.Okta) { // not required
		return nil
	}

	if m.Okta != nil {
		if err := m.Okta.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("okta")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateSaml(formats strfmt.Registry) error {
	if swag.IsZero(m.Saml) { // not required
		return nil
	}

	if m.Saml != nil {
		if err := m.Saml.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) validateStatic(formats strfmt.Registry) error {
	if swag.IsZero(m.Static) { // not required
		return nil
	}

	if m.Static != nil {
		if err := m.Static.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("static")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this authentication based on the context it is used
func (m *Authentication) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAzure(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAzureb2c(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCognito(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustom(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGithub(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIntelliTrust(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMappings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMethod(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOidc(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOkta(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSaml(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStatic(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authentication) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Attributes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attributes")
		}
		return err
	}

	return nil
}

func (m *Authentication) contextValidateAzure(ctx context.Context, formats strfmt.Registry) error {

	if m.Azure != nil {
		if err := m.Azure.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateAzureb2c(ctx context.Context, formats strfmt.Registry) error {

	if m.Azureb2c != nil {
		if err := m.Azureb2c.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azureb2c")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateCognito(ctx context.Context, formats strfmt.Registry) error {

	if m.Cognito != nil {
		if err := m.Cognito.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cognito")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateCustom(ctx context.Context, formats strfmt.Registry) error {

	if m.Custom != nil {
		if err := m.Custom.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("custom")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateGithub(ctx context.Context, formats strfmt.Registry) error {

	if m.Github != nil {
		if err := m.Github.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("github")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateIntelliTrust(ctx context.Context, formats strfmt.Registry) error {

	if m.IntelliTrust != nil {
		if err := m.IntelliTrust.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("intelli_trust")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateMappings(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Mappings.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *Authentication) contextValidateMethod(ctx context.Context, formats strfmt.Registry) error {

	if m.Method != nil {
		if err := m.Method.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("method")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateOidc(ctx context.Context, formats strfmt.Registry) error {

	if m.Oidc != nil {
		if err := m.Oidc.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("oidc")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateOkta(ctx context.Context, formats strfmt.Registry) error {

	if m.Okta != nil {
		if err := m.Okta.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("okta")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateSaml(ctx context.Context, formats strfmt.Registry) error {

	if m.Saml != nil {
		if err := m.Saml.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml")
			}
			return err
		}
	}

	return nil
}

func (m *Authentication) contextValidateStatic(ctx context.Context, formats strfmt.Registry) error {

	if m.Static != nil {
		if err := m.Static.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("static")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Authentication) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Authentication) UnmarshalBinary(b []byte) error {
	var res Authentication
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
