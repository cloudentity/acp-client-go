// Code generated by go-swagger; DO NOT EDIT.

package gateways

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

// NewUpdateGatewayParams creates a new UpdateGatewayParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateGatewayParams() *UpdateGatewayParams {
	return &UpdateGatewayParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateGatewayParamsWithTimeout creates a new UpdateGatewayParams object
// with the ability to set a timeout on a request.
func NewUpdateGatewayParamsWithTimeout(timeout time.Duration) *UpdateGatewayParams {
	return &UpdateGatewayParams{
		timeout: timeout,
	}
}

// NewUpdateGatewayParamsWithContext creates a new UpdateGatewayParams object
// with the ability to set a context for a request.
func NewUpdateGatewayParamsWithContext(ctx context.Context) *UpdateGatewayParams {
	return &UpdateGatewayParams{
		Context: ctx,
	}
}

// NewUpdateGatewayParamsWithHTTPClient creates a new UpdateGatewayParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateGatewayParamsWithHTTPClient(client *http.Client) *UpdateGatewayParams {
	return &UpdateGatewayParams{
		HTTPClient: client,
	}
}

/*
UpdateGatewayParams contains all the parameters to send to the API endpoint

	for the update gateway operation.

	Typically these are written to a http.Request.
*/
type UpdateGatewayParams struct {

	// UpdateGatewayBody.
	UpdateGatewayBody *models.UpdateGatewayRequest

	// Gw.
	Gw string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update gateway params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateGatewayParams) WithDefaults() *UpdateGatewayParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update gateway params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateGatewayParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update gateway params
func (o *UpdateGatewayParams) WithTimeout(timeout time.Duration) *UpdateGatewayParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update gateway params
func (o *UpdateGatewayParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update gateway params
func (o *UpdateGatewayParams) WithContext(ctx context.Context) *UpdateGatewayParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update gateway params
func (o *UpdateGatewayParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update gateway params
func (o *UpdateGatewayParams) WithHTTPClient(client *http.Client) *UpdateGatewayParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update gateway params
func (o *UpdateGatewayParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithUpdateGatewayBody adds the updateGatewayBody to the update gateway params
func (o *UpdateGatewayParams) WithUpdateGatewayBody(updateGatewayBody *models.UpdateGatewayRequest) *UpdateGatewayParams {
	o.SetUpdateGatewayBody(updateGatewayBody)
	return o
}

// SetUpdateGatewayBody adds the updateGatewayBody to the update gateway params
func (o *UpdateGatewayParams) SetUpdateGatewayBody(updateGatewayBody *models.UpdateGatewayRequest) {
	o.UpdateGatewayBody = updateGatewayBody
}

// WithGw adds the gw to the update gateway params
func (o *UpdateGatewayParams) WithGw(gw string) *UpdateGatewayParams {
	o.SetGw(gw)
	return o
}

// SetGw adds the gw to the update gateway params
func (o *UpdateGatewayParams) SetGw(gw string) {
	o.Gw = gw
}

// WithIfMatch adds the ifMatch to the update gateway params
func (o *UpdateGatewayParams) WithIfMatch(ifMatch *string) *UpdateGatewayParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update gateway params
func (o *UpdateGatewayParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateGatewayParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.UpdateGatewayBody != nil {
		if err := r.SetBodyParam(o.UpdateGatewayBody); err != nil {
			return err
		}
	}

	// path param gw
	if err := r.SetPathParam("gw", o.Gw); err != nil {
		return err
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
