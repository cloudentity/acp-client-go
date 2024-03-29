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

// NewCreateDataAccessConsentExtensionParams creates a new CreateDataAccessConsentExtensionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateDataAccessConsentExtensionParams() *CreateDataAccessConsentExtensionParams {
	return &CreateDataAccessConsentExtensionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateDataAccessConsentExtensionParamsWithTimeout creates a new CreateDataAccessConsentExtensionParams object
// with the ability to set a timeout on a request.
func NewCreateDataAccessConsentExtensionParamsWithTimeout(timeout time.Duration) *CreateDataAccessConsentExtensionParams {
	return &CreateDataAccessConsentExtensionParams{
		timeout: timeout,
	}
}

// NewCreateDataAccessConsentExtensionParamsWithContext creates a new CreateDataAccessConsentExtensionParams object
// with the ability to set a context for a request.
func NewCreateDataAccessConsentExtensionParamsWithContext(ctx context.Context) *CreateDataAccessConsentExtensionParams {
	return &CreateDataAccessConsentExtensionParams{
		Context: ctx,
	}
}

// NewCreateDataAccessConsentExtensionParamsWithHTTPClient creates a new CreateDataAccessConsentExtensionParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateDataAccessConsentExtensionParamsWithHTTPClient(client *http.Client) *CreateDataAccessConsentExtensionParams {
	return &CreateDataAccessConsentExtensionParams{
		HTTPClient: client,
	}
}

/*
CreateDataAccessConsentExtensionParams contains all the parameters to send to the API endpoint

	for the create data access consent extension operation.

	Typically these are written to a http.Request.
*/
type CreateDataAccessConsentExtensionParams struct {

	/* Request.

	   Request
	*/
	Request *models.BrazilExtensionConsentRequest

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

// WithDefaults hydrates default values in the create data access consent extension params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentExtensionParams) WithDefaults() *CreateDataAccessConsentExtensionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create data access consent extension params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateDataAccessConsentExtensionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithTimeout(timeout time.Duration) *CreateDataAccessConsentExtensionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithContext(ctx context.Context) *CreateDataAccessConsentExtensionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithHTTPClient(client *http.Client) *CreateDataAccessConsentExtensionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithRequest(request *models.BrazilExtensionConsentRequest) *CreateDataAccessConsentExtensionParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetRequest(request *models.BrazilExtensionConsentRequest) {
	o.Request = request
}

// WithConsentID adds the consentID to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithConsentID(consentID string) *CreateDataAccessConsentExtensionParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXCustomerUserAgent(xCustomerUserAgent *string) *CreateDataAccessConsentExtensionParams {
	o.SetXCustomerUserAgent(xCustomerUserAgent)
	return o
}

// SetXCustomerUserAgent adds the xCustomerUserAgent to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXCustomerUserAgent(xCustomerUserAgent *string) {
	o.XCustomerUserAgent = xCustomerUserAgent
}

// WithXFapiAuthDate adds the xFapiAuthDate to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXFapiAuthDate(xFapiAuthDate *string) *CreateDataAccessConsentExtensionParams {
	o.SetXFapiAuthDate(xFapiAuthDate)
	return o
}

// SetXFapiAuthDate adds the xFapiAuthDate to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXFapiAuthDate(xFapiAuthDate *string) {
	o.XFapiAuthDate = xFapiAuthDate
}

// WithXFapiCustomerIPAddress adds the xFapiCustomerIPAddress to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) *CreateDataAccessConsentExtensionParams {
	o.SetXFapiCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetXFapiCustomerIPAddress adds the xFapiCustomerIpAddress to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXFapiCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.XFapiCustomerIPAddress = xFapiCustomerIPAddress
}

// WithXFapiInteractionID adds the xFapiInteractionID to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXFapiInteractionID(xFapiInteractionID *string) *CreateDataAccessConsentExtensionParams {
	o.SetXFapiInteractionID(xFapiInteractionID)
	return o
}

// SetXFapiInteractionID adds the xFapiInteractionId to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXFapiInteractionID(xFapiInteractionID *string) {
	o.XFapiInteractionID = xFapiInteractionID
}

// WithXIdempotencyKey adds the xIdempotencyKey to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXIdempotencyKey(xIdempotencyKey *string) *CreateDataAccessConsentExtensionParams {
	o.SetXIdempotencyKey(xIdempotencyKey)
	return o
}

// SetXIdempotencyKey adds the xIdempotencyKey to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXIdempotencyKey(xIdempotencyKey *string) {
	o.XIdempotencyKey = xIdempotencyKey
}

// WithXJwsSignature adds the xJwsSignature to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) WithXJwsSignature(xJwsSignature *string) *CreateDataAccessConsentExtensionParams {
	o.SetXJwsSignature(xJwsSignature)
	return o
}

// SetXJwsSignature adds the xJwsSignature to the create data access consent extension params
func (o *CreateDataAccessConsentExtensionParams) SetXJwsSignature(xJwsSignature *string) {
	o.XJwsSignature = xJwsSignature
}

// WriteToRequest writes these params to a swagger request
func (o *CreateDataAccessConsentExtensionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
			return err
		}
	}

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
