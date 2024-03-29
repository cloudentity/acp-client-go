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

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// NewCreateDataAccessConsentV2Params creates a new CreateDataAccessConsentV2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateDataAccessConsentV2Params() *CreateDataAccessConsentV2Params {
	return &CreateDataAccessConsentV2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateDataAccessConsentV2ParamsWithTimeout creates a new CreateDataAccessConsentV2Params object
// with the ability to set a timeout on a request.
func NewCreateDataAccessConsentV2ParamsWithTimeout(timeout time.Duration) *CreateDataAccessConsentV2Params {
	return &CreateDataAccessConsentV2Params{
		timeout: timeout,
	}
}

// NewCreateDataAccessConsentV2ParamsWithContext creates a new CreateDataAccessConsentV2Params object
// with the ability to set a context for a request.
func NewCreateDataAccessConsentV2ParamsWithContext(ctx context.Context) *CreateDataAccessConsentV2Params {
	return &CreateDataAccessConsentV2Params{
		Context: ctx,
	}
}

// NewCreateDataAccessConsentV2ParamsWithHTTPClient creates a new CreateDataAccessConsentV2Params object
// with the ability to set a custom HTTPClient for a request.
func NewCreateDataAccessConsentV2ParamsWithHTTPClient(client *http.Client) *CreateDataAccessConsentV2Params {
	return &CreateDataAccessConsentV2Params{
		HTTPClient: client,
	}
}

/*
CreateDataAccessConsentV2Params contains all the parameters to send to the API endpoint

	for the create data access consent v2 operation.

	Typically these are written to a http.Request.
*/
type CreateDataAccessConsentV2Params struct {

	/* Request.

	   Request
	*/
	Request *models.BrazilCustomerDataAccessConsentRequestV2

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

// WithDefaults hydrates default values in the create data access consent v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentV2Params) WithDefaults() *CreateDataAccessConsentV2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create data access consent v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentV2Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithTimeout(timeout time.Duration) *CreateDataAccessConsentV2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithContext(ctx context.Context) *CreateDataAccessConsentV2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithHTTPClient(client *http.Client) *CreateDataAccessConsentV2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithRequest(request *models.BrazilCustomerDataAccessConsentRequestV2) *CreateDataAccessConsentV2Params {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetRequest(request *models.BrazilCustomerDataAccessConsentRequestV2) {
	o.Request = request
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXCustomerUserAgent(xCustomerUserAgent *string) *CreateDataAccessConsentV2Params {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXFapiAuthDate(xFapiAuthDate *string) *CreateDataAccessConsentV2Params {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *CreateDataAccessConsentV2Params {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXFapiInteractionID(xFapiInteractionID *string) *CreateDataAccessConsentV2Params {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXIdempotencyKey adds the xIdempotencyKey to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXIdempotencyKey(xIdempotencyKey *string) *CreateDataAccessConsentV2Params {
	o.SetXIdempotencyKey(xIdempotencyKey)
	return o
}

// SetXIdempotencyKey adds the xIdempotencyKey to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXIdempotencyKey(xIdempotencyKey *string) {
	o.XIdempotencyKey = xIdempotencyKey
}

// WithXJwsSignature adds the xJwsSignature to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) WithXJwsSignature(xJwsSignature *string) *CreateDataAccessConsentV2Params {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the create data access consent v2 params
func (o *CreateDataAccessConsentV2Params) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *CreateDataAccessConsentV2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
			return err
		}
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
