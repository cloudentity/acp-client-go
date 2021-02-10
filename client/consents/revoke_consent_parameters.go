// Code generated by go-swagger; DO NOT EDIT.

package consents

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

// NewRevokeConsentParams creates a new RevokeConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeConsentParams() *RevokeConsentParams {
	return &RevokeConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeConsentParamsWithTimeout creates a new RevokeConsentParams object
// with the ability to set a timeout on a request.
func NewRevokeConsentParamsWithTimeout(timeout time.Duration) *RevokeConsentParams {
	return &RevokeConsentParams{
		timeout: timeout,
	}
}

// NewRevokeConsentParamsWithContext creates a new RevokeConsentParams object
// with the ability to set a context for a request.
func NewRevokeConsentParamsWithContext(ctx context.Context) *RevokeConsentParams {
	return &RevokeConsentParams{
		Context: ctx,
	}
}

// NewRevokeConsentParamsWithHTTPClient creates a new RevokeConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeConsentParamsWithHTTPClient(client *http.Client) *RevokeConsentParams {
	return &RevokeConsentParams{
		HTTPClient: client,
	}
}

/* RevokeConsentParams contains all the parameters to send to the API endpoint
   for the revoke consent operation.

   Typically these are written to a http.Request.
*/
type RevokeConsentParams struct {

	// ConsentGrant.
	ConsentGrant *models.ConsentGrantRequest

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

// WithDefaults hydrates default values in the revoke consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeConsentParams) WithDefaults() *RevokeConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeConsentParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := RevokeConsentParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the revoke consent params
func (o *RevokeConsentParams) WithTimeout(timeout time.Duration) *RevokeConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke consent params
func (o *RevokeConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke consent params
func (o *RevokeConsentParams) WithContext(ctx context.Context) *RevokeConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke consent params
func (o *RevokeConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke consent params
func (o *RevokeConsentParams) WithHTTPClient(client *http.Client) *RevokeConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke consent params
func (o *RevokeConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentGrant adds the consentGrant to the revoke consent params
func (o *RevokeConsentParams) WithConsentGrant(consentGrant *models.ConsentGrantRequest) *RevokeConsentParams {
	o.SetConsentGrant(consentGrant)
	return o
}

// SetConsentGrant adds the consentGrant to the revoke consent params
func (o *RevokeConsentParams) SetConsentGrant(consentGrant *models.ConsentGrantRequest) {
	o.ConsentGrant = consentGrant
}

// WithAid adds the aid to the revoke consent params
func (o *RevokeConsentParams) WithAid(aid string) *RevokeConsentParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the revoke consent params
func (o *RevokeConsentParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the revoke consent params
func (o *RevokeConsentParams) WithTid(tid string) *RevokeConsentParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the revoke consent params
func (o *RevokeConsentParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ConsentGrant != nil {
		if err := r.SetBodyParam(o.ConsentGrant); err != nil {
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
