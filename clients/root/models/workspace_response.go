// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// WorkspaceResponse workspace response
//
// swagger:model WorkspaceResponse
type WorkspaceResponse struct {

	// Your server's label color in a HEX format.
	// Example: #007FFF
	Color string `json:"color,omitempty" yaml:"color,omitempty"`

	// Display description of the workspace
	// Example: Server description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Unique identifier of an workspace
	// Example: default
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// issuer url
	IssuerURL string `json:"issuer_url,omitempty" yaml:"issuer_url,omitempty"`

	// Logo URI
	LogoURI string `json:"logo_uri,omitempty" yaml:"logo_uri,omitempty"`

	// metadata
	Metadata *ServerMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Display name of the workspace
	//
	// If not provided, a random ID is generated.
	// Example: default
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// number of child organizations
	NumberOfChildOrganizations int64 `json:"number_of_child_organizations,omitempty" yaml:"number_of_child_organizations,omitempty"`

	// The profile of a server
	//
	// ACP is delivered with preconfigured workspace templates that enable quick and easy setup for
	// specific configuration patterns. For example, you can instantly create an Open Banking
	// compliant workspace that has all of the required mechanisms and settings already in place.
	// Example: default
	// Enum: [default demo workforce consumer partners third_party fapi_advanced fapi_rw fapi_ro openbanking_uk_fapi_advanced openbanking_uk openbanking_br openbanking_br_unico cdr_australia cdr_australia_fapi_rw fdx openbanking_ksa fapi_20_security fapi_20_message_signing connect_id]
	Profile string `json:"profile,omitempty" yaml:"profile,omitempty"`

	// Subject format
	// Enum: [hash legacy]
	SubjectFormat string `json:"subject_format,omitempty" yaml:"subject_format,omitempty"`

	// Subject identifier algorithm salt
	SubjectIdentifierAlgorithmSalt string `json:"subject_identifier_algorithm_salt,omitempty" yaml:"subject_identifier_algorithm_salt,omitempty"`

	// template
	Template bool `json:"template,omitempty" yaml:"template,omitempty"`

	// optional theme id
	ThemeID string `json:"theme_id,omitempty" yaml:"theme_id,omitempty"`

	// Server type
	//
	// It is an internal property used to recognize if the server is created for an admin portal,
	// a developer portal, or if it is a system or a regular workspace.
	// Example: regular
	// Enum: [admin developer system regular organization]
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this workspace response
func (m *WorkspaceResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjectFormat(formats); err != nil {
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

func (m *WorkspaceResponse) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

var workspaceResponseTypeProfilePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["default","demo","workforce","consumer","partners","third_party","fapi_advanced","fapi_rw","fapi_ro","openbanking_uk_fapi_advanced","openbanking_uk","openbanking_br","openbanking_br_unico","cdr_australia","cdr_australia_fapi_rw","fdx","openbanking_ksa","fapi_20_security","fapi_20_message_signing","connect_id"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		workspaceResponseTypeProfilePropEnum = append(workspaceResponseTypeProfilePropEnum, v)
	}
}

const (

	// WorkspaceResponseProfileDefault captures enum value "default"
	WorkspaceResponseProfileDefault string = "default"

	// WorkspaceResponseProfileDemo captures enum value "demo"
	WorkspaceResponseProfileDemo string = "demo"

	// WorkspaceResponseProfileWorkforce captures enum value "workforce"
	WorkspaceResponseProfileWorkforce string = "workforce"

	// WorkspaceResponseProfileConsumer captures enum value "consumer"
	WorkspaceResponseProfileConsumer string = "consumer"

	// WorkspaceResponseProfilePartners captures enum value "partners"
	WorkspaceResponseProfilePartners string = "partners"

	// WorkspaceResponseProfileThirdParty captures enum value "third_party"
	WorkspaceResponseProfileThirdParty string = "third_party"

	// WorkspaceResponseProfileFapiAdvanced captures enum value "fapi_advanced"
	WorkspaceResponseProfileFapiAdvanced string = "fapi_advanced"

	// WorkspaceResponseProfileFapiRw captures enum value "fapi_rw"
	WorkspaceResponseProfileFapiRw string = "fapi_rw"

	// WorkspaceResponseProfileFapiRo captures enum value "fapi_ro"
	WorkspaceResponseProfileFapiRo string = "fapi_ro"

	// WorkspaceResponseProfileOpenbankingUkFapiAdvanced captures enum value "openbanking_uk_fapi_advanced"
	WorkspaceResponseProfileOpenbankingUkFapiAdvanced string = "openbanking_uk_fapi_advanced"

	// WorkspaceResponseProfileOpenbankingUk captures enum value "openbanking_uk"
	WorkspaceResponseProfileOpenbankingUk string = "openbanking_uk"

	// WorkspaceResponseProfileOpenbankingBr captures enum value "openbanking_br"
	WorkspaceResponseProfileOpenbankingBr string = "openbanking_br"

	// WorkspaceResponseProfileOpenbankingBrUnico captures enum value "openbanking_br_unico"
	WorkspaceResponseProfileOpenbankingBrUnico string = "openbanking_br_unico"

	// WorkspaceResponseProfileCdrAustralia captures enum value "cdr_australia"
	WorkspaceResponseProfileCdrAustralia string = "cdr_australia"

	// WorkspaceResponseProfileCdrAustraliaFapiRw captures enum value "cdr_australia_fapi_rw"
	WorkspaceResponseProfileCdrAustraliaFapiRw string = "cdr_australia_fapi_rw"

	// WorkspaceResponseProfileFdx captures enum value "fdx"
	WorkspaceResponseProfileFdx string = "fdx"

	// WorkspaceResponseProfileOpenbankingKsa captures enum value "openbanking_ksa"
	WorkspaceResponseProfileOpenbankingKsa string = "openbanking_ksa"

	// WorkspaceResponseProfileFapi20Security captures enum value "fapi_20_security"
	WorkspaceResponseProfileFapi20Security string = "fapi_20_security"

	// WorkspaceResponseProfileFapi20MessageSigning captures enum value "fapi_20_message_signing"
	WorkspaceResponseProfileFapi20MessageSigning string = "fapi_20_message_signing"

	// WorkspaceResponseProfileConnectID captures enum value "connect_id"
	WorkspaceResponseProfileConnectID string = "connect_id"
)

// prop value enum
func (m *WorkspaceResponse) validateProfileEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, workspaceResponseTypeProfilePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WorkspaceResponse) validateProfile(formats strfmt.Registry) error {
	if swag.IsZero(m.Profile) { // not required
		return nil
	}

	// value enum
	if err := m.validateProfileEnum("profile", "body", m.Profile); err != nil {
		return err
	}

	return nil
}

var workspaceResponseTypeSubjectFormatPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["hash","legacy"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		workspaceResponseTypeSubjectFormatPropEnum = append(workspaceResponseTypeSubjectFormatPropEnum, v)
	}
}

const (

	// WorkspaceResponseSubjectFormatHash captures enum value "hash"
	WorkspaceResponseSubjectFormatHash string = "hash"

	// WorkspaceResponseSubjectFormatLegacy captures enum value "legacy"
	WorkspaceResponseSubjectFormatLegacy string = "legacy"
)

// prop value enum
func (m *WorkspaceResponse) validateSubjectFormatEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, workspaceResponseTypeSubjectFormatPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WorkspaceResponse) validateSubjectFormat(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjectFormat) { // not required
		return nil
	}

	// value enum
	if err := m.validateSubjectFormatEnum("subject_format", "body", m.SubjectFormat); err != nil {
		return err
	}

	return nil
}

var workspaceResponseTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["admin","developer","system","regular","organization"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		workspaceResponseTypeTypePropEnum = append(workspaceResponseTypeTypePropEnum, v)
	}
}

const (

	// WorkspaceResponseTypeAdmin captures enum value "admin"
	WorkspaceResponseTypeAdmin string = "admin"

	// WorkspaceResponseTypeDeveloper captures enum value "developer"
	WorkspaceResponseTypeDeveloper string = "developer"

	// WorkspaceResponseTypeSystem captures enum value "system"
	WorkspaceResponseTypeSystem string = "system"

	// WorkspaceResponseTypeRegular captures enum value "regular"
	WorkspaceResponseTypeRegular string = "regular"

	// WorkspaceResponseTypeOrganization captures enum value "organization"
	WorkspaceResponseTypeOrganization string = "organization"
)

// prop value enum
func (m *WorkspaceResponse) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, workspaceResponseTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WorkspaceResponse) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this workspace response based on the context it is used
func (m *WorkspaceResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WorkspaceResponse) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.Metadata != nil {

		if swag.IsZero(m.Metadata) { // not required
			return nil
		}

		if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *WorkspaceResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WorkspaceResponse) UnmarshalBinary(b []byte) error {
	var res WorkspaceResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}