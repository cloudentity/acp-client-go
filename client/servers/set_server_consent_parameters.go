// Code generated by go-swagger; DO NOT EDIT.

package servers

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

// NewSetServerConsentParams creates a new SetServerConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSetServerConsentParams() *SetServerConsentParams {
	return &SetServerConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSetServerConsentParamsWithTimeout creates a new SetServerConsentParams object
// with the ability to set a timeout on a request.
func NewSetServerConsentParamsWithTimeout(timeout time.Duration) *SetServerConsentParams {
	return &SetServerConsentParams{
		timeout: timeout,
	}
}

// NewSetServerConsentParamsWithContext creates a new SetServerConsentParams object
// with the ability to set a context for a request.
func NewSetServerConsentParamsWithContext(ctx context.Context) *SetServerConsentParams {
	return &SetServerConsentParams{
		Context: ctx,
	}
}

// NewSetServerConsentParamsWithHTTPClient creates a new SetServerConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewSetServerConsentParamsWithHTTPClient(client *http.Client) *SetServerConsentParams {
	return &SetServerConsentParams{
		HTTPClient: client,
	}
}

/* SetServerConsentParams contains all the parameters to send to the API endpoint
   for the set server consent operation.

   Typically these are written to a http.Request.
*/
type SetServerConsentParams struct {

	/* ServerConsent.

	   Server consent
	*/
	ServerConsent *models.ServerConsent

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the set server consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetServerConsentParams) WithDefaults() *SetServerConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the set server consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetServerConsentParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := SetServerConsentParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the set server consent params
func (o *SetServerConsentParams) WithTimeout(timeout time.Duration) *SetServerConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the set server consent params
func (o *SetServerConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the set server consent params
func (o *SetServerConsentParams) WithContext(ctx context.Context) *SetServerConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the set server consent params
func (o *SetServerConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the set server consent params
func (o *SetServerConsentParams) WithHTTPClient(client *http.Client) *SetServerConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the set server consent params
func (o *SetServerConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithServerConsent adds the serverConsent to the set server consent params
func (o *SetServerConsentParams) WithServerConsent(serverConsent *models.ServerConsent) *SetServerConsentParams {
	o.SetServerConsent(serverConsent)
	return o
}

// SetServerConsent adds the serverConsent to the set server consent params
func (o *SetServerConsentParams) SetServerConsent(serverConsent *models.ServerConsent) {
	o.ServerConsent = serverConsent
}

// WithAid adds the aid to the set server consent params
func (o *SetServerConsentParams) WithAid(aid string) *SetServerConsentParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the set server consent params
func (o *SetServerConsentParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the set server consent params
func (o *SetServerConsentParams) WithTid(tid string) *SetServerConsentParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the set server consent params
func (o *SetServerConsentParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *SetServerConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ServerConsent != nil {
		if err := r.SetBodyParam(o.ServerConsent); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
