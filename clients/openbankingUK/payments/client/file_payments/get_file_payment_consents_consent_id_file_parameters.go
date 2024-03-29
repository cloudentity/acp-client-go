// Code generated by go-swagger; DO NOT EDIT.

package file_payments

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

// NewGetFilePaymentConsentsConsentIDFileParams creates a new GetFilePaymentConsentsConsentIDFileParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetFilePaymentConsentsConsentIDFileParams() *GetFilePaymentConsentsConsentIDFileParams {
	return &GetFilePaymentConsentsConsentIDFileParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetFilePaymentConsentsConsentIDFileParamsWithTimeout creates a new GetFilePaymentConsentsConsentIDFileParams object
// with the ability to set a timeout on a request.
func NewGetFilePaymentConsentsConsentIDFileParamsWithTimeout(timeout time.Duration) *GetFilePaymentConsentsConsentIDFileParams {
	return &GetFilePaymentConsentsConsentIDFileParams{
		timeout: timeout,
	}
}

// NewGetFilePaymentConsentsConsentIDFileParamsWithContext creates a new GetFilePaymentConsentsConsentIDFileParams object
// with the ability to set a context for a request.
func NewGetFilePaymentConsentsConsentIDFileParamsWithContext(ctx context.Context) *GetFilePaymentConsentsConsentIDFileParams {
	return &GetFilePaymentConsentsConsentIDFileParams{
		Context: ctx,
	}
}

// NewGetFilePaymentConsentsConsentIDFileParamsWithHTTPClient creates a new GetFilePaymentConsentsConsentIDFileParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetFilePaymentConsentsConsentIDFileParamsWithHTTPClient(client *http.Client) *GetFilePaymentConsentsConsentIDFileParams {
	return &GetFilePaymentConsentsConsentIDFileParams{
		HTTPClient: client,
	}
}

/*
GetFilePaymentConsentsConsentIDFileParams contains all the parameters to send to the API endpoint

	for the get file payment consents consent Id file operation.

	Typically these are written to a http.Request.
*/
type GetFilePaymentConsentsConsentIDFileParams struct {

	/* Authorization.

	   An Authorisation Token as per https://tools.ietf.org/html/rfc6750
	*/
	Authorization string

	/* ConsentID.

	   ConsentId
	*/
	ConsentID string

	/* XCustomerUserAgent.

	   Indicates the user-agent that the PSU is using.
	*/
	XCustomerUserAgent *string

	/* XFapiAuthDate.

	     The time when the PSU last logged in with the TPP.
	All dates in the HTTP headers are represented as RFC 7231 Full Dates. An example is below:
	Sun, 10 Sep 2017 19:43:31 UTC
	*/
	XFapiAuthDate *string

	/* XFapiCustomerIPAddress.

	   The PSU's IP address if the PSU is currently logged in with the TPP.
	*/
	XFapiCustomerIPAddress *string

	/* XFapiInteractionID.

	   An RFC4122 UID used as a correlation id.
	*/
	XFapiInteractionID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get file payment consents consent Id file params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentsConsentIDFileParams) WithDefaults() *GetFilePaymentConsentsConsentIDFileParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get file payment consents consent Id file params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentsConsentIDFileParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithTimeout(timeout time.Duration) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithContext(ctx context.Context) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithHTTPClient(client *http.Client) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithAuthorization(authorization string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithConsentID adds the consentID to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithConsentID(consentID string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithXFapiAuthDate(xFapiAuthDate *string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) WithXFapiInteractionID(xFapiInteractionID *string) *GetFilePaymentConsentsConsentIDFileParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the get file payment consents consent Id file params
func (o *GetFilePaymentConsentsConsentIDFileParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WriteToRequest writes these params to a swagger request
func (o *GetFilePaymentConsentsConsentIDFileParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	// path param ConsentId
	if err := r.SetPathParam("ConsentId", o.ConsentID); err != nil {
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
