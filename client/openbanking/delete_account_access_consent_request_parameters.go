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

// NewDeleteAccountAccessConsentRequestParams creates a new DeleteAccountAccessConsentRequestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteAccountAccessConsentRequestParams() *DeleteAccountAccessConsentRequestParams {
	return &DeleteAccountAccessConsentRequestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteAccountAccessConsentRequestParamsWithTimeout creates a new DeleteAccountAccessConsentRequestParams object
// with the ability to set a timeout on a request.
func NewDeleteAccountAccessConsentRequestParamsWithTimeout(timeout time.Duration) *DeleteAccountAccessConsentRequestParams {
	return &DeleteAccountAccessConsentRequestParams{
		timeout: timeout,
	}
}

// NewDeleteAccountAccessConsentRequestParamsWithContext creates a new DeleteAccountAccessConsentRequestParams object
// with the ability to set a context for a request.
func NewDeleteAccountAccessConsentRequestParamsWithContext(ctx context.Context) *DeleteAccountAccessConsentRequestParams {
	return &DeleteAccountAccessConsentRequestParams{
		Context: ctx,
	}
}

// NewDeleteAccountAccessConsentRequestParamsWithHTTPClient creates a new DeleteAccountAccessConsentRequestParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteAccountAccessConsentRequestParamsWithHTTPClient(client *http.Client) *DeleteAccountAccessConsentRequestParams {
	return &DeleteAccountAccessConsentRequestParams{
		HTTPClient: client,
	}
}

/* DeleteAccountAccessConsentRequestParams contains all the parameters to send to the API endpoint
   for the delete account access consent request operation.

   Typically these are written to a http.Request.
*/
type DeleteAccountAccessConsentRequestParams struct {

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
	CustomerAgent *string

	/* XFapiAuthDate.

	     The time when the PSU last logged in with the TPP.

	The value is supplied as a HTTP-date as in section 7.1.1.1 of [RFC7231]
	*/
	AuthDate *string

	/* XFapiCustomerIPAddress.

	   The PSU's IP address if the PSU is currently logged in with the TPP.
	*/
	CustomerIPAddress *string

	/* XFapiInteractionID.

	     An RFC4122 UID used as a correlation Id.

	If provided, the ASPSP must "play back" this value
	in the x-fapi-interaction-id response header.
	*/
	InteractionID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete account access consent request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteAccountAccessConsentRequestParams) WithDefaults() *DeleteAccountAccessConsentRequestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete account access consent request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteAccountAccessConsentRequestParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := DeleteAccountAccessConsentRequestParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithTimeout(timeout time.Duration) *DeleteAccountAccessConsentRequestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithContext(ctx context.Context) *DeleteAccountAccessConsentRequestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithHTTPClient(client *http.Client) *DeleteAccountAccessConsentRequestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithAid(aid string) *DeleteAccountAccessConsentRequestParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetAid(aid string) {
	o.Aid = aid
}

// WithConsentID adds the consentID to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithConsentID(consentID string) *DeleteAccountAccessConsentRequestParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithTid adds the tid to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithTid(tid string) *DeleteAccountAccessConsentRequestParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetTid(tid string) {
	o.Tid = tid
}

// WithCustomerAgent adds the xCustomerUserAgent to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithCustomerAgent(xCustomerUserAgent *string) *DeleteAccountAccessConsentRequestParams {
	o.SetCustomerAgent(xCustomerUserAgent)
	return o
}

// SetCustomerAgent adds the xCustomerUserAgent to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetCustomerAgent(xCustomerUserAgent *string) {
	o.CustomerAgent = xCustomerUserAgent
}

// WithAuthDate adds the xFapiAuthDate to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithAuthDate(xFapiAuthDate *string) *DeleteAccountAccessConsentRequestParams {
	o.SetAuthDate(xFapiAuthDate)
	return o
}

// SetAuthDate adds the xFapiAuthDate to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetAuthDate(xFapiAuthDate *string) {
	o.AuthDate = xFapiAuthDate
}

// WithCustomerIPAddress adds the xFapiCustomerIPAddress to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithCustomerIPAddress(xFapiCustomerIPAddress *string) *DeleteAccountAccessConsentRequestParams {
	o.SetCustomerIPAddress(xFapiCustomerIPAddress)
	return o
}

// SetCustomerIPAddress adds the xFapiCustomerIpAddress to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetCustomerIPAddress(xFapiCustomerIPAddress *string) {
	o.CustomerIPAddress = xFapiCustomerIPAddress
}

// WithInteractionID adds the xFapiInteractionID to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) WithInteractionID(xFapiInteractionID *string) *DeleteAccountAccessConsentRequestParams {
	o.SetInteractionID(xFapiInteractionID)
	return o
}

// SetInteractionID adds the xFapiInteractionId to the delete account access consent request params
func (o *DeleteAccountAccessConsentRequestParams) SetInteractionID(xFapiInteractionID *string) {
	o.InteractionID = xFapiInteractionID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteAccountAccessConsentRequestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.CustomerAgent != nil {

		// header param x-customer-user-agent
		if err := r.SetHeaderParam("x-customer-user-agent", *o.CustomerAgent); err != nil {
			return err
		}
	}

	if o.AuthDate != nil {

		// header param x-fapi-auth-date
		if err := r.SetHeaderParam("x-fapi-auth-date", *o.AuthDate); err != nil {
			return err
		}
	}

	if o.CustomerIPAddress != nil {

		// header param x-fapi-customer-ip-address
		if err := r.SetHeaderParam("x-fapi-customer-ip-address", *o.CustomerIPAddress); err != nil {
			return err
		}
	}

	if o.InteractionID != nil {

		// header param x-fapi-interaction-id
		if err := r.SetHeaderParam("x-fapi-interaction-id", *o.InteractionID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
