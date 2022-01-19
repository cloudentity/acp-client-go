// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

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

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// NewCreateDataAccessConsentParams creates a new CreateDataAccessConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateDataAccessConsentParams() *CreateDataAccessConsentParams {
	return &CreateDataAccessConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateDataAccessConsentParamsWithTimeout creates a new CreateDataAccessConsentParams object
// with the ability to set a timeout on a request.
func NewCreateDataAccessConsentParamsWithTimeout(timeout time.Duration) *CreateDataAccessConsentParams {
	return &CreateDataAccessConsentParams{
		timeout: timeout,
	}
}

// NewCreateDataAccessConsentParamsWithContext creates a new CreateDataAccessConsentParams object
// with the ability to set a context for a request.
func NewCreateDataAccessConsentParamsWithContext(ctx context.Context) *CreateDataAccessConsentParams {
	return &CreateDataAccessConsentParams{
		Context: ctx,
	}
}

// NewCreateDataAccessConsentParamsWithHTTPClient creates a new CreateDataAccessConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateDataAccessConsentParamsWithHTTPClient(client *http.Client) *CreateDataAccessConsentParams {
	return &CreateDataAccessConsentParams{
		HTTPClient: client,
	}
}

/* CreateDataAccessConsentParams contains all the parameters to send to the API endpoint
   for the create data access consent operation.

   Typically these are written to a http.Request.
*/
type CreateDataAccessConsentParams struct {

	/* Request.

	   Request
	*/
	Request *models.OBBRCustomerDataAccessConsentRequest

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

// WithDefaults hydrates default values in the create data access consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentParams) WithDefaults() *CreateDataAccessConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create data access consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create data access consent params
func (o *CreateDataAccessConsentParams) WithTimeout(timeout time.Duration) *CreateDataAccessConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create data access consent params
func (o *CreateDataAccessConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create data access consent params
func (o *CreateDataAccessConsentParams) WithContext(ctx context.Context) *CreateDataAccessConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create data access consent params
func (o *CreateDataAccessConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create data access consent params
func (o *CreateDataAccessConsentParams) WithHTTPClient(client *http.Client) *CreateDataAccessConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create data access consent params
func (o *CreateDataAccessConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the create data access consent params
func (o *CreateDataAccessConsentParams) WithRequest(request *models.OBBRCustomerDataAccessConsentRequest) *CreateDataAccessConsentParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the create data access consent params
func (o *CreateDataAccessConsentParams) SetRequest(request *models.OBBRCustomerDataAccessConsentRequest) {
	o.Request = request
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *CreateDataAccessConsentParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXFapiAuthDate(xFapiAuthDate *string) *CreateDataAccessConsentParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *CreateDataAccessConsentParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXFapiInteractionID(xFapiInteractionID *string) *CreateDataAccessConsentParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXIdempotencyKey adds the xIdempotencyKey to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXIdempotencyKey(xIdempotencyKey *string) *CreateDataAccessConsentParams {
	o.SetXIdempotencyKey(xIdempotencyKey)
	return o
}

// SetXIdempotencyKey adds the xIdempotencyKey to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXIdempotencyKey(xIdempotencyKey *string) {
	o.XIdempotencyKey = xIdempotencyKey
}

// WithXJwsSignature adds the xJwsSignature to the create data access consent params
func (o *CreateDataAccessConsentParams) WithXJwsSignature(xJwsSignature *string) *CreateDataAccessConsentParams {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the create data access consent params
func (o *CreateDataAccessConsentParams) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *CreateDataAccessConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
