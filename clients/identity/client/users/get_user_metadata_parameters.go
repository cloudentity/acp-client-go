// Code generated by go-swagger; DO NOT EDIT.

package users

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

// NewGetUserMetadataParams creates a new GetUserMetadataParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetUserMetadataParams() *GetUserMetadataParams {
	return &GetUserMetadataParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetUserMetadataParamsWithTimeout creates a new GetUserMetadataParams object
// with the ability to set a timeout on a request.
func NewGetUserMetadataParamsWithTimeout(timeout time.Duration) *GetUserMetadataParams {
	return &GetUserMetadataParams{
		timeout: timeout,
	}
}

// NewGetUserMetadataParamsWithContext creates a new GetUserMetadataParams object
// with the ability to set a context for a request.
func NewGetUserMetadataParamsWithContext(ctx context.Context) *GetUserMetadataParams {
	return &GetUserMetadataParams{
		Context: ctx,
	}
}

// NewGetUserMetadataParamsWithHTTPClient creates a new GetUserMetadataParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetUserMetadataParamsWithHTTPClient(client *http.Client) *GetUserMetadataParams {
	return &GetUserMetadataParams{
		HTTPClient: client,
	}
}

/*
GetUserMetadataParams contains all the parameters to send to the API endpoint

	for the get user metadata operation.

	Typically these are written to a http.Request.
*/
type GetUserMetadataParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	// MetadataType.
	MetadataType string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get user metadata params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetUserMetadataParams) WithDefaults() *GetUserMetadataParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get user metadata params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetUserMetadataParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get user metadata params
func (o *GetUserMetadataParams) WithTimeout(timeout time.Duration) *GetUserMetadataParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get user metadata params
func (o *GetUserMetadataParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get user metadata params
func (o *GetUserMetadataParams) WithContext(ctx context.Context) *GetUserMetadataParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get user metadata params
func (o *GetUserMetadataParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get user metadata params
func (o *GetUserMetadataParams) WithHTTPClient(client *http.Client) *GetUserMetadataParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get user metadata params
func (o *GetUserMetadataParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get user metadata params
func (o *GetUserMetadataParams) WithIfMatch(ifMatch *string) *GetUserMetadataParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get user metadata params
func (o *GetUserMetadataParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the get user metadata params
func (o *GetUserMetadataParams) WithIPID(iPID string) *GetUserMetadataParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the get user metadata params
func (o *GetUserMetadataParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithMetadataType adds the metadataType to the get user metadata params
func (o *GetUserMetadataParams) WithMetadataType(metadataType string) *GetUserMetadataParams {
	o.SetMetadataType(metadataType)
	return o
}

// SetMetadataType adds the metadataType to the get user metadata params
func (o *GetUserMetadataParams) SetMetadataType(metadataType string) {
	o.MetadataType = metadataType
}

// WithUserID adds the userID to the get user metadata params
func (o *GetUserMetadataParams) WithUserID(userID string) *GetUserMetadataParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the get user metadata params
func (o *GetUserMetadataParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *GetUserMetadataParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	// path param metadataType
	if err := r.SetPathParam("metadataType", o.MetadataType); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
