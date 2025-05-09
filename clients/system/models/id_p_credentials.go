// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// IDPCredentials ID p credentials
//
// swagger:model IDPCredentials
type IDPCredentials struct {

	// apple
	Apple *AppleCredentials `json:"apple,omitempty" yaml:"apple,omitempty"`

	// auth0
	Auth0 *Auth0Credentials `json:"auth0,omitempty" yaml:"auth0,omitempty"`

	// azure
	Azure *AzureCredentials `json:"azure,omitempty" yaml:"azure,omitempty"`

	// azureb2c
	Azureb2c *AzureB2CCredentials `json:"azureb2c,omitempty" yaml:"azureb2c,omitempty"`

	// cognito
	Cognito *CognitoCredentials `json:"cognito,omitempty" yaml:"cognito,omitempty"`

	// custom
	Custom CustomCredentials `json:"custom,omitempty" yaml:"custom,omitempty"`

	// external
	External *ExternalCredentials `json:"external,omitempty" yaml:"external,omitempty"`

	// github
	Github *GithubCredentials `json:"github,omitempty" yaml:"github,omitempty"`

	// google
	Google *GoogleCredentials `json:"google,omitempty" yaml:"google,omitempty"`

	// google workspace
	GoogleWorkspace *GoogleWorkspaceCredentials `json:"google_workspace,omitempty" yaml:"google_workspace,omitempty"`

	// intelli trust
	IntelliTrust *IntelliTrustCredentials `json:"intelli_trust,omitempty" yaml:"intelli_trust,omitempty"`

	// linkedin
	Linkedin *LinkedInCredentials `json:"linkedin,omitempty" yaml:"linkedin,omitempty"`

	// meta
	Meta *MetaCredentials `json:"meta,omitempty" yaml:"meta,omitempty"`

	// microsoft
	Microsoft *MicrosoftCredentials `json:"microsoft,omitempty" yaml:"microsoft,omitempty"`

	// oidc
	Oidc *OIDCCredentials `json:"oidc,omitempty" yaml:"oidc,omitempty"`

	// okta
	Okta *OktaCredentials `json:"okta,omitempty" yaml:"okta,omitempty"`

	// saml
	Saml *SAMLCredentials `json:"saml,omitempty" yaml:"saml,omitempty"`

	// saml v2
	SamlV2 *SAMLV2Credentials `json:"saml_v2,omitempty" yaml:"saml_v2,omitempty"`

	// static
	Static *StaticCredentials `json:"static,omitempty" yaml:"static,omitempty"`

	// x
	X XCredentials `json:"x,omitempty" yaml:"x,omitempty"`
}

// Validate validates this ID p credentials
func (m *IDPCredentials) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApple(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuth0(formats); err != nil {
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

	if err := m.validateExternal(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGithub(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGoogle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGoogleWorkspace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntelliTrust(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLinkedin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMeta(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMicrosoft(formats); err != nil {
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

	if err := m.validateSamlV2(formats); err != nil {
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

func (m *IDPCredentials) validateApple(formats strfmt.Registry) error {
	if swag.IsZero(m.Apple) { // not required
		return nil
	}

	if m.Apple != nil {
		if err := m.Apple.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("apple")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("apple")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateAuth0(formats strfmt.Registry) error {
	if swag.IsZero(m.Auth0) { // not required
		return nil
	}

	if m.Auth0 != nil {
		if err := m.Auth0.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("auth0")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("auth0")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateAzure(formats strfmt.Registry) error {
	if swag.IsZero(m.Azure) { // not required
		return nil
	}

	if m.Azure != nil {
		if err := m.Azure.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateAzureb2c(formats strfmt.Registry) error {
	if swag.IsZero(m.Azureb2c) { // not required
		return nil
	}

	if m.Azureb2c != nil {
		if err := m.Azureb2c.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azureb2c")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azureb2c")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateCognito(formats strfmt.Registry) error {
	if swag.IsZero(m.Cognito) { // not required
		return nil
	}

	if m.Cognito != nil {
		if err := m.Cognito.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cognito")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cognito")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateExternal(formats strfmt.Registry) error {
	if swag.IsZero(m.External) { // not required
		return nil
	}

	if m.External != nil {
		if err := m.External.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("external")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("external")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateGithub(formats strfmt.Registry) error {
	if swag.IsZero(m.Github) { // not required
		return nil
	}

	if m.Github != nil {
		if err := m.Github.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("github")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("github")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateGoogle(formats strfmt.Registry) error {
	if swag.IsZero(m.Google) { // not required
		return nil
	}

	if m.Google != nil {
		if err := m.Google.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("google")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("google")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateGoogleWorkspace(formats strfmt.Registry) error {
	if swag.IsZero(m.GoogleWorkspace) { // not required
		return nil
	}

	if m.GoogleWorkspace != nil {
		if err := m.GoogleWorkspace.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("google_workspace")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("google_workspace")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateIntelliTrust(formats strfmt.Registry) error {
	if swag.IsZero(m.IntelliTrust) { // not required
		return nil
	}

	if m.IntelliTrust != nil {
		if err := m.IntelliTrust.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("intelli_trust")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("intelli_trust")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateLinkedin(formats strfmt.Registry) error {
	if swag.IsZero(m.Linkedin) { // not required
		return nil
	}

	if m.Linkedin != nil {
		if err := m.Linkedin.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("linkedin")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("linkedin")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateMeta(formats strfmt.Registry) error {
	if swag.IsZero(m.Meta) { // not required
		return nil
	}

	if m.Meta != nil {
		if err := m.Meta.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("meta")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateMicrosoft(formats strfmt.Registry) error {
	if swag.IsZero(m.Microsoft) { // not required
		return nil
	}

	if m.Microsoft != nil {
		if err := m.Microsoft.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("microsoft")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("microsoft")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateOidc(formats strfmt.Registry) error {
	if swag.IsZero(m.Oidc) { // not required
		return nil
	}

	if m.Oidc != nil {
		if err := m.Oidc.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("oidc")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("oidc")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateOkta(formats strfmt.Registry) error {
	if swag.IsZero(m.Okta) { // not required
		return nil
	}

	if m.Okta != nil {
		if err := m.Okta.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("okta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("okta")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateSaml(formats strfmt.Registry) error {
	if swag.IsZero(m.Saml) { // not required
		return nil
	}

	if m.Saml != nil {
		if err := m.Saml.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("saml")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateSamlV2(formats strfmt.Registry) error {
	if swag.IsZero(m.SamlV2) { // not required
		return nil
	}

	if m.SamlV2 != nil {
		if err := m.SamlV2.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("saml_v2")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) validateStatic(formats strfmt.Registry) error {
	if swag.IsZero(m.Static) { // not required
		return nil
	}

	if m.Static != nil {
		if err := m.Static.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("static")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("static")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this ID p credentials based on the context it is used
func (m *IDPCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApple(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAuth0(ctx, formats); err != nil {
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

	if err := m.contextValidateExternal(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGithub(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGoogle(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGoogleWorkspace(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIntelliTrust(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLinkedin(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMeta(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMicrosoft(ctx, formats); err != nil {
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

	if err := m.contextValidateSamlV2(ctx, formats); err != nil {
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

func (m *IDPCredentials) contextValidateApple(ctx context.Context, formats strfmt.Registry) error {

	if m.Apple != nil {

		if swag.IsZero(m.Apple) { // not required
			return nil
		}

		if err := m.Apple.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("apple")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("apple")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateAuth0(ctx context.Context, formats strfmt.Registry) error {

	if m.Auth0 != nil {

		if swag.IsZero(m.Auth0) { // not required
			return nil
		}

		if err := m.Auth0.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("auth0")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("auth0")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateAzure(ctx context.Context, formats strfmt.Registry) error {

	if m.Azure != nil {

		if swag.IsZero(m.Azure) { // not required
			return nil
		}

		if err := m.Azure.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateAzureb2c(ctx context.Context, formats strfmt.Registry) error {

	if m.Azureb2c != nil {

		if swag.IsZero(m.Azureb2c) { // not required
			return nil
		}

		if err := m.Azureb2c.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azureb2c")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azureb2c")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateCognito(ctx context.Context, formats strfmt.Registry) error {

	if m.Cognito != nil {

		if swag.IsZero(m.Cognito) { // not required
			return nil
		}

		if err := m.Cognito.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cognito")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cognito")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateExternal(ctx context.Context, formats strfmt.Registry) error {

	if m.External != nil {

		if swag.IsZero(m.External) { // not required
			return nil
		}

		if err := m.External.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("external")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("external")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateGithub(ctx context.Context, formats strfmt.Registry) error {

	if m.Github != nil {

		if swag.IsZero(m.Github) { // not required
			return nil
		}

		if err := m.Github.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("github")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("github")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateGoogle(ctx context.Context, formats strfmt.Registry) error {

	if m.Google != nil {

		if swag.IsZero(m.Google) { // not required
			return nil
		}

		if err := m.Google.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("google")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("google")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateGoogleWorkspace(ctx context.Context, formats strfmt.Registry) error {

	if m.GoogleWorkspace != nil {

		if swag.IsZero(m.GoogleWorkspace) { // not required
			return nil
		}

		if err := m.GoogleWorkspace.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("google_workspace")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("google_workspace")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateIntelliTrust(ctx context.Context, formats strfmt.Registry) error {

	if m.IntelliTrust != nil {

		if swag.IsZero(m.IntelliTrust) { // not required
			return nil
		}

		if err := m.IntelliTrust.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("intelli_trust")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("intelli_trust")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateLinkedin(ctx context.Context, formats strfmt.Registry) error {

	if m.Linkedin != nil {

		if swag.IsZero(m.Linkedin) { // not required
			return nil
		}

		if err := m.Linkedin.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("linkedin")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("linkedin")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateMeta(ctx context.Context, formats strfmt.Registry) error {

	if m.Meta != nil {

		if swag.IsZero(m.Meta) { // not required
			return nil
		}

		if err := m.Meta.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("meta")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateMicrosoft(ctx context.Context, formats strfmt.Registry) error {

	if m.Microsoft != nil {

		if swag.IsZero(m.Microsoft) { // not required
			return nil
		}

		if err := m.Microsoft.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("microsoft")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("microsoft")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateOidc(ctx context.Context, formats strfmt.Registry) error {

	if m.Oidc != nil {

		if swag.IsZero(m.Oidc) { // not required
			return nil
		}

		if err := m.Oidc.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("oidc")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("oidc")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateOkta(ctx context.Context, formats strfmt.Registry) error {

	if m.Okta != nil {

		if swag.IsZero(m.Okta) { // not required
			return nil
		}

		if err := m.Okta.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("okta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("okta")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateSaml(ctx context.Context, formats strfmt.Registry) error {

	if m.Saml != nil {

		if swag.IsZero(m.Saml) { // not required
			return nil
		}

		if err := m.Saml.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("saml")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateSamlV2(ctx context.Context, formats strfmt.Registry) error {

	if m.SamlV2 != nil {

		if swag.IsZero(m.SamlV2) { // not required
			return nil
		}

		if err := m.SamlV2.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("saml_v2")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("saml_v2")
			}
			return err
		}
	}

	return nil
}

func (m *IDPCredentials) contextValidateStatic(ctx context.Context, formats strfmt.Registry) error {

	if m.Static != nil {

		if swag.IsZero(m.Static) { // not required
			return nil
		}

		if err := m.Static.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("static")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("static")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IDPCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IDPCredentials) UnmarshalBinary(b []byte) error {
	var res IDPCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
