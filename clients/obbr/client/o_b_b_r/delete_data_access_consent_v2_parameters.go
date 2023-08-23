// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

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

// NewDeleteDataAccessConsentV2Params creates a new DeleteDataAccessConsentV2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteDataAccessConsentV2Params() *DeleteDataAccessConsentV2Params {
	return &DeleteDataAccessConsentV2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteDataAccessConsentV2ParamsWithTimeout creates a new DeleteDataAccessConsentV2Params object
// with the ability to set a timeout on a request.
func NewDeleteDataAccessConsentV2ParamsWithTimeout(timeout time.Duration) *DeleteDataAccessConsentV2Params {
	return &DeleteDataAccessConsentV2Params{
		timeout: timeout,
	}
}

// NewDeleteDataAccessConsentV2ParamsWithContext creates a new DeleteDataAccessConsentV2Params object
// with the ability to set a context for a request.
func NewDeleteDataAccessConsentV2ParamsWithContext(ctx context.Context) *DeleteDataAccessConsentV2Params {
	return &DeleteDataAccessConsentV2Params{
		Context: ctx,
	}
}

// NewDeleteDataAccessConsentV2ParamsWithHTTPClient creates a new DeleteDataAccessConsentV2Params object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteDataAccessConsentV2ParamsWithHTTPClient(client *http.Client) *DeleteDataAccessConsentV2Params {
	return &DeleteDataAccessConsentV2Params{
		HTTPClient: client,
	}
}

/*
DeleteDataAccessConsentV2Params contains all the parameters to send to the API endpoint

	for the delete data access consent v2 operation.

	Typically these are written to a http.Request.
*/
type DeleteDataAccessConsentV2Params struct {

	/* ConsentID.

	   Consent id

	   Format: consentID
	*/
	ConsentID string

	/* XCustomerUserAgent.

	     The header indicates the user-agent that the PSU is using.

	The TPP may populate this field with the user-agent indicated by the PSU.
	If the PSU is using a TPP mobile app, the TPP must ensure that the user-agent string
	is different from browser based user-agent strings.
	*/
	XCustomerUserAgent *string

	/* XFapiAuthDate.

	     The time when the PSU last logged in with the TPP.

	The value is supplied as a HTTP-date as in section 7.1.1.1 of [RFC7231]
	*/
	XFapiAuthDate *string

	/* XFapiCustomerIPAddress.

	   The PSU's IP address if the PSU is currently logged in with the TPP.
	*/
	XFapiCustomerIPAddress *string

	/* XFapiInteractionID.

	     An RFC4122 UID used as a correlation Id.

	If provided, the ASPSP must "play back" this value
	in the x-fapi-interaction-id response header.
	*/
	XFapiInteractionID *string

	/* XJwsSignature.

	     Header containing a detached JWS signature of the body of the payload.

	Refer to resource specific documentation on when this header must be specified.
	*/
	XJwsSignature *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete data access consent v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteDataAccessConsentV2Params) WithDefaults() *DeleteDataAccessConsentV2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete data access consent v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteDataAccessConsentV2Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithTimeout(timeout time.Duration) *DeleteDataAccessConsentV2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithContext(ctx context.Context) *DeleteDataAccessConsentV2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithHTTPClient(client *http.Client) *DeleteDataAccessConsentV2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentID adds the consentID to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithConsentID(consentID string) *DeleteDataAccessConsentV2Params {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithXCustomerUserAgent(xCustomerUserAgent *string) *DeleteDataAccessConsentV2Params {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithXFapiAuthDate(xFapiAuthDate *string) *DeleteDataAccessConsentV2Params {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *DeleteDataAccessConsentV2Params {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithXFapiInteractionID(xFapiInteractionID *string) *DeleteDataAccessConsentV2Params {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXJwsSignature adds the xJwsSignature to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) WithXJwsSignature(xJwsSignature *string) *DeleteDataAccessConsentV2Params {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the delete data access consent v2 params
func (o *DeleteDataAccessConsentV2Params) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteDataAccessConsentV2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param consentID
	if err := r.SetPathParam("consentID", o.ConsentID); err != nil {
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

	if o.XJwsSignature != nil {

		// header param x-jws-signature
		if err := r.SetHeaderParam("x-jws-signature", *o.XJwsSignature); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}