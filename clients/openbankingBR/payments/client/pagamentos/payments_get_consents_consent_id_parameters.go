// Code generated by go-swagger; DO NOT EDIT.

package pagamentos

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

// NewPaymentsGetConsentsConsentIDParams creates a new PaymentsGetConsentsConsentIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentsGetConsentsConsentIDParams() *PaymentsGetConsentsConsentIDParams {
	return &PaymentsGetConsentsConsentIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentsGetConsentsConsentIDParamsWithTimeout creates a new PaymentsGetConsentsConsentIDParams object
// with the ability to set a timeout on a request.
func NewPaymentsGetConsentsConsentIDParamsWithTimeout(timeout time.Duration) *PaymentsGetConsentsConsentIDParams {
	return &PaymentsGetConsentsConsentIDParams{
		timeout: timeout,
	}
}

// NewPaymentsGetConsentsConsentIDParamsWithContext creates a new PaymentsGetConsentsConsentIDParams object
// with the ability to set a context for a request.
func NewPaymentsGetConsentsConsentIDParamsWithContext(ctx context.Context) *PaymentsGetConsentsConsentIDParams {
	return &PaymentsGetConsentsConsentIDParams{
		Context: ctx,
	}
}

// NewPaymentsGetConsentsConsentIDParamsWithHTTPClient creates a new PaymentsGetConsentsConsentIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentsGetConsentsConsentIDParamsWithHTTPClient(client *http.Client) *PaymentsGetConsentsConsentIDParams {
	return &PaymentsGetConsentsConsentIDParams{
		HTTPClient: client,
	}
}

/*
PaymentsGetConsentsConsentIDParams contains all the parameters to send to the API endpoint

	for the payments get consents consent Id operation.

	Typically these are written to a http.Request.
*/
type PaymentsGetConsentsConsentIDParams struct {

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

// WithDefaults hydrates default values in the payments get consents consent Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentsGetConsentsConsentIDParams) WithDefaults() *PaymentsGetConsentsConsentIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payments get consents consent Id params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentsGetConsentsConsentIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithTimeout(timeout time.Duration) *PaymentsGetConsentsConsentIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithContext(ctx context.Context) *PaymentsGetConsentsConsentIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithHTTPClient(client *http.Client) *PaymentsGetConsentsConsentIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithAuthorization(authorization string) *PaymentsGetConsentsConsentIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithConsentID adds the consentID to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithConsentID(consentID string) *PaymentsGetConsentsConsentIDParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *PaymentsGetConsentsConsentIDParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithXFapiAuthDate(xFapiAuthDate *string) *PaymentsGetConsentsConsentIDParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *PaymentsGetConsentsConsentIDParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) WithXFapiInteractionID(xFapiInteractionID *string) *PaymentsGetConsentsConsentIDParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the payments get consents consent Id params
func (o *PaymentsGetConsentsConsentIDParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentsGetConsentsConsentIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
