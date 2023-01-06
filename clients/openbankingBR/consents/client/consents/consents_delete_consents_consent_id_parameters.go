// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewConsentsDeleteConsentsConsentIDParams creates a new ConsentsDeleteConsentsConsentIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConsentsDeleteConsentsConsentIDParams() *ConsentsDeleteConsentsConsentIDParams {
	return &ConsentsDeleteConsentsConsentIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConsentsDeleteConsentsConsentIDParamsWithTimeout creates a new ConsentsDeleteConsentsConsentIDParams object
// with the ability to set a timeout on a request.
func NewConsentsDeleteConsentsConsentIDParamsWithTimeout(timeout time.Duration) *ConsentsDeleteConsentsConsentIDParams {
	return &ConsentsDeleteConsentsConsentIDParams{
		timeout: timeout,
	}
}

// NewConsentsDeleteConsentsConsentIDParamsWithContext creates a new ConsentsDeleteConsentsConsentIDParams object
// with the ability to set a context for a request.
func NewConsentsDeleteConsentsConsentIDParamsWithContext(ctx context.Context) *ConsentsDeleteConsentsConsentIDParams {
	return &ConsentsDeleteConsentsConsentIDParams{
		Context: ctx,
	}
}

// NewConsentsDeleteConsentsConsentIDParamsWithHTTPClient creates a new ConsentsDeleteConsentsConsentIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewConsentsDeleteConsentsConsentIDParamsWithHTTPClient(client *http.Client) *ConsentsDeleteConsentsConsentIDParams {
	return &ConsentsDeleteConsentsConsentIDParams{
		HTTPClient: client,
	}
}

/*
ConsentsDeleteConsentsConsentIDParams contains all the parameters to send to the API endpoint

	for the consents delete consents consent Id operation.

	Typically these are written to a http.Request.
*/
type ConsentsDeleteConsentsConsentIDParams struct {

	/* Authorization.

	   Cabealho HTTP padro. Permite que as credenciais sejam fornecidas dependendo do tipo de recurso solicitado
	*/
	Authorization string

	/* ConsentID.

	     O consentId  o identificador nico do consentimento e dever ser um URN - Uniform Resource Name.
	Um URN, conforme definido na [RFC8141](https://tools.ietf.org/html/rfc8141)  um Uniform Resource
	Identifier - URI - que  atribudo sob o URI scheme "urn" e um namespace URN especfico, com a inteno de que o URN
	seja um identificador de recurso persistente e independente da localizao.
	Considerando a string urn:bancoex:C1DD33123 como exemplo para consentId temos:
	- o namespace(urn)
	- o identificador associado ao namespace da instituio transnmissora (bancoex)
	- o identificador especfico dentro do namespace (C1DD33123).
	Informaes mais detalhadas sobre a construo de namespaces devem ser consultadas na [RFC8141](https://tools.ietf.org/html/rfc8141).
	*/
	ConsentID string

	/* XCustomerUserAgent.

	   Indica o user-agent que o usurio utiliza.
	*/
	XCustomerUserAgent *string

	/* XFapiAuthDate.

	   Data em que o usurio logou pela ltima vez com o receptor. Representada de acordo com a [RFC7231](https://tools.ietf.org/html/rfc7231).Exemplo: Sun, 10 Sep 2017 19:43:31 UTC
	*/
	XFapiAuthDate *string

	/* XFapiCustomerIPAddress.

	   O endereo IP do usurio se estiver atualmente logado com o receptor.
	*/
	XFapiCustomerIPAddress *string

	/* XFapiInteractionID.

	   Um UID [RFC4122](https://tools.ietf.org/html/rfc4122) usado como um ID de correlao. Se fornecido, o transmissor deve "reproduzir" esse valor no cabealho de resposta.
	*/
	XFapiInteractionID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the consents delete consents consent Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConsentsDeleteConsentsConsentIDParams) WithDefaults() *ConsentsDeleteConsentsConsentIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the consents delete consents consent Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConsentsDeleteConsentsConsentIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithTimeout(timeout time.Duration) *ConsentsDeleteConsentsConsentIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithContext(ctx context.Context) *ConsentsDeleteConsentsConsentIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithHTTPClient(client *http.Client) *ConsentsDeleteConsentsConsentIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithAuthorization(authorization string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithConsentID adds the consentID to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithConsentID(consentID string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithXFapiAuthDate(xFapiAuthDate *string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) WithXFapiInteractionID(xFapiInteractionID *string) *ConsentsDeleteConsentsConsentIDParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the consents delete consents consent Id params
func (o *ConsentsDeleteConsentsConsentIDParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WriteToRequest writes these params to a swagger request
func (o *ConsentsDeleteConsentsConsentIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	// path param consentId
	if err := r.SetPathParam("consentId", o.ConsentID); err != nil {
		return err
	}

	if o.XCustomerUserAgent != nil {

		// header param x-customer-user-agent
		if err := r.SetHeaderParam("x-customer-user-agent", *o.XCustomerUserAgent); err != nil {
			return err
		}
	}

	if o.XFapiAuthDate != nil {

		// header param x-fapi-auth-date
		if err := r.SetHeaderParam("x-fapi-auth-date", *o.XFapiAuthDate); err != nil {
			return err
		}
	}

	if o.XFapiCustomerIPAddress != nil {

		// header param x-fapi-customer-ip-address
		if err := r.SetHeaderParam("x-fapi-customer-ip-address", *o.XFapiCustomerIPAddress); err != nil {
			return err
		}
	}

	if o.XFapiInteractionID != nil {

		// header param x-fapi-interaction-id
		if err := r.SetHeaderParam("x-fapi-interaction-id", *o.XFapiInteractionID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
