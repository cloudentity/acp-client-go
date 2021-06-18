// Code generated by go-swagger; DO NOT EDIT.

package openbanking

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

// NewGetFilePaymentConsentRequestParams creates a new GetFilePaymentConsentRequestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetFilePaymentConsentRequestParams() *GetFilePaymentConsentRequestParams {
	return &GetFilePaymentConsentRequestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetFilePaymentConsentRequestParamsWithTimeout creates a new GetFilePaymentConsentRequestParams object
// with the ability to set a timeout on a request.
func NewGetFilePaymentConsentRequestParamsWithTimeout(timeout time.Duration) *GetFilePaymentConsentRequestParams {
	return &GetFilePaymentConsentRequestParams{
		timeout: timeout,
	}
}

// NewGetFilePaymentConsentRequestParamsWithContext creates a new GetFilePaymentConsentRequestParams object
// with the ability to set a context for a request.
func NewGetFilePaymentConsentRequestParamsWithContext(ctx context.Context) *GetFilePaymentConsentRequestParams {
	return &GetFilePaymentConsentRequestParams{
		Context: ctx,
	}
}

// NewGetFilePaymentConsentRequestParamsWithHTTPClient creates a new GetFilePaymentConsentRequestParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetFilePaymentConsentRequestParamsWithHTTPClient(client *http.Client) *GetFilePaymentConsentRequestParams {
	return &GetFilePaymentConsentRequestParams{
		HTTPClient: client,
	}
}

/* GetFilePaymentConsentRequestParams contains all the parameters to send to the API endpoint
   for the get file payment consent request operation.

   Typically these are written to a http.Request.
*/
type GetFilePaymentConsentRequestParams struct {

	/* Aid.

	   Server ID

	   Default: "default"
	*/
	Aid string

	/* ConsentID.

	   Consent id

	   Format: consentID
	*/
	ConsentID string

	/* Tid.

	   Tenant ID

	   Default: "default"
	*/
	Tid string

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

// WithDefaults hydrates default values in the get file payment consent request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentRequestParams) WithDefaults() *GetFilePaymentConsentRequestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get file payment consent request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentRequestParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := GetFilePaymentConsentRequestParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithTimeout(timeout time.Duration) *GetFilePaymentConsentRequestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithContext(ctx context.Context) *GetFilePaymentConsentRequestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithHTTPClient(client *http.Client) *GetFilePaymentConsentRequestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithAid(aid string) *GetFilePaymentConsentRequestParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetAid(aid string) {
	o.Aid = aid
}

// WithConsentID adds the consentID to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithConsentID(consentID string) *GetFilePaymentConsentRequestParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithTid adds the tid to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithTid(tid string) *GetFilePaymentConsentRequestParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetTid(tid string) {
	o.Tid = tid
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *GetFilePaymentConsentRequestParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithXFapiAuthDate(xFapiAuthDate *string) *GetFilePaymentConsentRequestParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *GetFilePaymentConsentRequestParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithXFapiInteractionID(xFapiInteractionID *string) *GetFilePaymentConsentRequestParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXJwsSignature adds the xJwsSignature to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) WithXJwsSignature(xJwsSignature *string) *GetFilePaymentConsentRequestParams {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the get file payment consent request params
func (o *GetFilePaymentConsentRequestParams) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *GetFilePaymentConsentRequestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param consentID
	if err := r.SetPathParam("consentID", o.ConsentID); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
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
