// Code generated by go-swagger; DO NOT EDIT.

package idps

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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewCreateGoogleIDPParams creates a new CreateGoogleIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateGoogleIDPParams() *CreateGoogleIDPParams {
	return &CreateGoogleIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateGoogleIDPParamsWithTimeout creates a new CreateGoogleIDPParams object
// with the ability to set a timeout on a request.
func NewCreateGoogleIDPParamsWithTimeout(timeout time.Duration) *CreateGoogleIDPParams {
	return &CreateGoogleIDPParams{
		timeout: timeout,
	}
}

// NewCreateGoogleIDPParamsWithContext creates a new CreateGoogleIDPParams object
// with the ability to set a context for a request.
func NewCreateGoogleIDPParamsWithContext(ctx context.Context) *CreateGoogleIDPParams {
	return &CreateGoogleIDPParams{
		Context: ctx,
	}
}

// NewCreateGoogleIDPParamsWithHTTPClient creates a new CreateGoogleIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateGoogleIDPParamsWithHTTPClient(client *http.Client) *CreateGoogleIDPParams {
	return &CreateGoogleIDPParams{
		HTTPClient: client,
	}
}

/*
CreateGoogleIDPParams contains all the parameters to send to the API endpoint

	for the create google ID p operation.

	Typically these are written to a http.Request.
*/
type CreateGoogleIDPParams struct {

	/* GoogleIDP.

	   GoogleIDP
	*/
	GoogleIDP *models.GoogleIDP

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create google ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateGoogleIDPParams) WithDefaults() *CreateGoogleIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create google ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateGoogleIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateGoogleIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create google ID p params
func (o *CreateGoogleIDPParams) WithTimeout(timeout time.Duration) *CreateGoogleIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create google ID p params
func (o *CreateGoogleIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create google ID p params
func (o *CreateGoogleIDPParams) WithContext(ctx context.Context) *CreateGoogleIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create google ID p params
func (o *CreateGoogleIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create google ID p params
func (o *CreateGoogleIDPParams) WithHTTPClient(client *http.Client) *CreateGoogleIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create google ID p params
func (o *CreateGoogleIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGoogleIDP adds the googleIDP to the create google ID p params
func (o *CreateGoogleIDPParams) WithGoogleIDP(googleIDP *models.GoogleIDP) *CreateGoogleIDPParams {
	o.SetGoogleIDP(googleIDP)
	return o
}

// SetGoogleIDP adds the googleIdP to the create google ID p params
func (o *CreateGoogleIDPParams) SetGoogleIDP(googleIDP *models.GoogleIDP) {
	o.GoogleIDP = googleIDP
}

// WithWid adds the wid to the create google ID p params
func (o *CreateGoogleIDPParams) WithWid(wid string) *CreateGoogleIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create google ID p params
func (o *CreateGoogleIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateGoogleIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.GoogleIDP != nil {
		if err := r.SetBodyParam(o.GoogleIDP); err != nil {
			return err
		}
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
