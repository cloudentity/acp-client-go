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

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// NewDeleteUserIdentifierParams creates a new DeleteUserIdentifierParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteUserIdentifierParams() *DeleteUserIdentifierParams {
	return &DeleteUserIdentifierParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteUserIdentifierParamsWithTimeout creates a new DeleteUserIdentifierParams object
// with the ability to set a timeout on a request.
func NewDeleteUserIdentifierParamsWithTimeout(timeout time.Duration) *DeleteUserIdentifierParams {
	return &DeleteUserIdentifierParams{
		timeout: timeout,
	}
}

// NewDeleteUserIdentifierParamsWithContext creates a new DeleteUserIdentifierParams object
// with the ability to set a context for a request.
func NewDeleteUserIdentifierParamsWithContext(ctx context.Context) *DeleteUserIdentifierParams {
	return &DeleteUserIdentifierParams{
		Context: ctx,
	}
}

// NewDeleteUserIdentifierParamsWithHTTPClient creates a new DeleteUserIdentifierParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteUserIdentifierParamsWithHTTPClient(client *http.Client) *DeleteUserIdentifierParams {
	return &DeleteUserIdentifierParams{
		HTTPClient: client,
	}
}

/*
DeleteUserIdentifierParams contains all the parameters to send to the API endpoint

	for the delete user identifier operation.

	Typically these are written to a http.Request.
*/
type DeleteUserIdentifierParams struct {

	// Identifier.
	Identifier *models.DeleteUserIdentifier

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete user identifier params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteUserIdentifierParams) WithDefaults() *DeleteUserIdentifierParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete user identifier params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteUserIdentifierParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithTimeout(timeout time.Duration) *DeleteUserIdentifierParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithContext(ctx context.Context) *DeleteUserIdentifierParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithHTTPClient(client *http.Client) *DeleteUserIdentifierParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIdentifier adds the identifier to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithIdentifier(identifier *models.DeleteUserIdentifier) *DeleteUserIdentifierParams {
	o.SetIdentifier(identifier)
	return o
}

// SetIdentifier adds the identifier to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetIdentifier(identifier *models.DeleteUserIdentifier) {
	o.Identifier = identifier
}

// WithIfMatch adds the ifMatch to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithIfMatch(ifMatch *string) *DeleteUserIdentifierParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithIPID(iPID string) *DeleteUserIdentifierParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the delete user identifier params
func (o *DeleteUserIdentifierParams) WithUserID(userID string) *DeleteUserIdentifierParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the delete user identifier params
func (o *DeleteUserIdentifierParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteUserIdentifierParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Identifier != nil {
		if err := r.SetBodyParam(o.Identifier); err != nil {
			return err
		}
	}

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

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
