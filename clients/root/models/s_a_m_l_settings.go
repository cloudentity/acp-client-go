// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SAMLSettings SAML IDP specific settings
//
// swagger:model SAMLSettings
type SAMLSettings struct {

	// Unique id of a service provider
	// Example: https://localhost:8443/default/default/login
	EntityIssuer string `json:"entity_issuer,omitempty" yaml:"entity_issuer,omitempty"`

	// The attribute name from the `AttributeStatement` SAML response which is used as an identifier in ACP
	//
	// Applies only when `identifierSource` parameter is set to `attribute`.
	IdentifierAttribute string `json:"identifier_attribute,omitempty" yaml:"identifier_attribute,omitempty"`

	// The source for an identifier
	//
	// The `identifierSource` parameter can have either the `subject` or the `attribute` value.
	//
	// It is used to provide an unique user attribute that is used as an identifier in ACP.
	//
	// Depending on which identifier source you choose, you must define either the
	// `identifierAttribute` or the `subjectNameIDFormat` parameter.
	IdentifierSource string `json:"identifier_source,omitempty" yaml:"identifier_source,omitempty"`

	// IDP metadata URL
	MetadataURL string `json:"metadata_url,omitempty" yaml:"metadata_url,omitempty"`

	// IDP metadata xml
	MetadataXML string `json:"metadata_xml,omitempty" yaml:"metadata_xml,omitempty"`

	// If enabled, the verification, if the `InResponseTo` parameter matches the original ID attribute
	// sent from ACP, is skipped.
	//
	// Enable the `skipInResponseToVerification` flag when the `InResponseTo` parameter is not
	// returned by your IDP.
	SkipInResponseToVerification bool `json:"skip_in_response_to_verification,omitempty" yaml:"skip_in_response_to_verification,omitempty"`

	// String represented SSO URL (endpoint) where the SAML request is sent
	// Example: https://test-dev-ed.my.salesforce.com/idp/endpoint/HttpPost
	SsoURL string `json:"sso_url,omitempty" yaml:"sso_url,omitempty"`

	// Name ID format of a SAML subject
	//
	// It applies only when the `identifierSource` parameter is set to `subject`.
	//
	// Allowed values:
	//
	// `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
	//
	// `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
	//
	// `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName`
	//
	// `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName`
	//
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted`
	//
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:entity`
	//
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos`
	//
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
	//
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
	//
	// default value:
	// `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
	SubjectNameIDFormat string `json:"subject_name_id_format,omitempty" yaml:"subject_name_id_format,omitempty"`
}

// Validate validates this s a m l settings
func (m *SAMLSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this s a m l settings based on context it is used
func (m *SAMLSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLSettings) UnmarshalBinary(b []byte) error {
	var res SAMLSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
