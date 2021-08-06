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

	"github.com/cloudentity/acp-client-go/models"
)

// NewCreatePaymentConsentParams creates a new CreatePaymentConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreatePaymentConsentParams() *CreatePaymentConsentParams {
	return &CreatePaymentConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreatePaymentConsentParamsWithTimeout creates a new CreatePaymentConsentParams object
// with the ability to set a timeout on a request.
func NewCreatePaymentConsentParamsWithTimeout(timeout time.Duration) *CreatePaymentConsentParams {
	return &CreatePaymentConsentParams{
		timeout: timeout,
	}
}

// NewCreatePaymentConsentParamsWithContext creates a new CreatePaymentConsentParams object
// with the ability to set a context for a request.
func NewCreatePaymentConsentParamsWithContext(ctx context.Context) *CreatePaymentConsentParams {
	return &CreatePaymentConsentParams{
		Context: ctx,
	}
}

// NewCreatePaymentConsentParamsWithHTTPClient creates a new CreatePaymentConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreatePaymentConsentParamsWithHTTPClient(client *http.Client) *CreatePaymentConsentParams {
	return &CreatePaymentConsentParams{
		HTTPClient: client,
	}
}

/* CreatePaymentConsentParams contains all the parameters to send to the API endpoint
   for the create payment consent operation.

   Typically these are written to a http.Request.
*/
type CreatePaymentConsentParams struct {

	/* Request.

	   Request
	*/
	Request *models.OBBRCustomerPaymentConsentRequest

	/* Aid.

	   Server ID

	   Default: "default"
	*/
	Aid string

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

	/* XIdempotencyKey.

	     Every request will be processed only once per x-idempotency-key.
	The Idempotency Key will be valid for 24 hours
	*/
	XIdempotencyKey *string

	/* XJwsSignature.

	     Header containing a detached JWS signature of the body of the payload.

	Refer to resource specific documentation on when this header must be specified.
	*/
	XJwsSignature *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create payment consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreatePaymentConsentParams) WithDefaults() *CreatePaymentConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create payment consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreatePaymentConsentParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := CreatePaymentConsentParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create payment consent params
func (o *CreatePaymentConsentParams) WithTimeout(timeout time.Duration) *CreatePaymentConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create payment consent params
func (o *CreatePaymentConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create payment consent params
func (o *CreatePaymentConsentParams) WithContext(ctx context.Context) *CreatePaymentConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create payment consent params
func (o *CreatePaymentConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create payment consent params
func (o *CreatePaymentConsentParams) WithHTTPClient(client *http.Client) *CreatePaymentConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create payment consent params
func (o *CreatePaymentConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the create payment consent params
func (o *CreatePaymentConsentParams) WithRequest(request *models.OBBRCustomerPaymentConsentRequest) *CreatePaymentConsentParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the create payment consent params
func (o *CreatePaymentConsentParams) SetRequest(request *models.OBBRCustomerPaymentConsentRequest) {
	o.Request = request
}

// WithAid adds the aid to the create payment consent params
func (o *CreatePaymentConsentParams) WithAid(aid string) *CreatePaymentConsentParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the create payment consent params
func (o *CreatePaymentConsentParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the create payment consent params
func (o *CreatePaymentConsentParams) WithTid(tid string) *CreatePaymentConsentParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the create payment consent params
func (o *CreatePaymentConsentParams) SetTid(tid string) {
	o.Tid = tid
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the create payment consent params
func (o *CreatePaymentConsentParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *CreatePaymentConsentParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the create payment consent params
func (o *CreatePaymentConsentParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the create payment consent params
func (o *CreatePaymentConsentParams) WithXFapiAuthDate(xFapiAuthDate *string) *CreatePaymentConsentParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the create payment consent params
func (o *CreatePaymentConsentParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the create payment consent params
func (o *CreatePaymentConsentParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *CreatePaymentConsentParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the create payment consent params
func (o *CreatePaymentConsentParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the create payment consent params
func (o *CreatePaymentConsentParams) WithXFapiInteractionID(xFapiInteractionID *string) *CreatePaymentConsentParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the create payment consent params
func (o *CreatePaymentConsentParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXIdempotencyKey adds the xIdempotencyKey to the create payment consent params
func (o *CreatePaymentConsentParams) WithXIdempotencyKey(xIdempotencyKey *string) *CreatePaymentConsentParams {
	o.SetXIdempotencyKey(xIdempotencyKey)
	return o
}

// SetXIdempotencyKey adds the xIdempotencyKey to the create payment consent params
func (o *CreatePaymentConsentParams) SetXIdempotencyKey(xIdempotencyKey *string) {
	o.XIdempotencyKey = xIdempotencyKey
}

// WithXJwsSignature adds the xJwsSignature to the create payment consent params
func (o *CreatePaymentConsentParams) WithXJwsSignature(xJwsSignature *string) *CreatePaymentConsentParams {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the create payment consent params
func (o *CreatePaymentConsentParams) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *CreatePaymentConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
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

	if o.XIdempotencyKey != nil {

		// header param x-idempotency-key
		if err := r.SetHeaderParam("x-idempotency-key", *o.XIdempotencyKey); err != nil {
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
