// Code generated by go-swagger; DO NOT EDIT.

package oauth2

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

// NewDynamicClientRegistrationOpenbankingUKUpdateClientParams creates a new DynamicClientRegistrationOpenbankingUKUpdateClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDynamicClientRegistrationOpenbankingUKUpdateClientParams() *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithTimeout creates a new DynamicClientRegistrationOpenbankingUKUpdateClientParams object
// with the ability to set a timeout on a request.
func NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithTimeout(timeout time.Duration) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientParams{
		timeout: timeout,
	}
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithContext creates a new DynamicClientRegistrationOpenbankingUKUpdateClientParams object
// with the ability to set a context for a request.
func NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithContext(ctx context.Context) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientParams{
		Context: ctx,
	}
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithHTTPClient creates a new DynamicClientRegistrationOpenbankingUKUpdateClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewDynamicClientRegistrationOpenbankingUKUpdateClientParamsWithHTTPClient(client *http.Client) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientParams{
		HTTPClient: client,
	}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientParams contains all the parameters to send to the API endpoint
   for the dynamic client registration openbanking u k update client operation.

   Typically these are written to a http.Request.
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientParams struct {

	// Client.
	Client *models.OpenbankingUKDynamicClientRegistrationRequest

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the dynamic client registration openbanking u k update client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithDefaults() *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the dynamic client registration openbanking u k update client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetDefaults() {
	var (
		aidDefault = string("default")

		cidDefault = string("default")

		tidDefault = string("default")
	)

	val := DynamicClientRegistrationOpenbankingUKUpdateClientParams{
		Aid: aidDefault,
		Cid: cidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithTimeout(timeout time.Duration) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithContext(ctx context.Context) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithHTTPClient(client *http.Client) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClient adds the client to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithClient(client *models.OpenbankingUKDynamicClientRegistrationRequest) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetClient(client)
	return o
}

// SetClient adds the client to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetClient(client *models.OpenbankingUKDynamicClientRegistrationRequest) {
	o.Client = client
}

// WithAid adds the aid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithAid(aid string) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetAid(aid string) {
	o.Aid = aid
}

// WithCid adds the cid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithCid(cid string) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetCid(cid string) {
	o.Cid = cid
}

// WithTid adds the tid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WithTid(tid string) *DynamicClientRegistrationOpenbankingUKUpdateClientParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the dynamic client registration openbanking u k update client params
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Client != nil {
		if err := r.SetBodyParam(o.Client); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
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
