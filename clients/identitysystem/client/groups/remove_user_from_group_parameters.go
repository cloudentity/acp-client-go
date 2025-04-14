// Code generated by go-swagger; DO NOT EDIT.

package groups

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

// NewRemoveUserFromGroupParams creates a new RemoveUserFromGroupParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRemoveUserFromGroupParams() *RemoveUserFromGroupParams {
	return &RemoveUserFromGroupParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRemoveUserFromGroupParamsWithTimeout creates a new RemoveUserFromGroupParams object
// with the ability to set a timeout on a request.
func NewRemoveUserFromGroupParamsWithTimeout(timeout time.Duration) *RemoveUserFromGroupParams {
	return &RemoveUserFromGroupParams{
		timeout: timeout,
	}
}

// NewRemoveUserFromGroupParamsWithContext creates a new RemoveUserFromGroupParams object
// with the ability to set a context for a request.
func NewRemoveUserFromGroupParamsWithContext(ctx context.Context) *RemoveUserFromGroupParams {
	return &RemoveUserFromGroupParams{
		Context: ctx,
	}
}

// NewRemoveUserFromGroupParamsWithHTTPClient creates a new RemoveUserFromGroupParams object
// with the ability to set a custom HTTPClient for a request.
func NewRemoveUserFromGroupParamsWithHTTPClient(client *http.Client) *RemoveUserFromGroupParams {
	return &RemoveUserFromGroupParams{
		HTTPClient: client,
	}
}

/*
RemoveUserFromGroupParams contains all the parameters to send to the API endpoint

	for the remove user from group operation.

	Typically these are written to a http.Request.
*/
type RemoveUserFromGroupParams struct {

	// GroupID.
	GroupID string

	// IPID.
	IPID string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the remove user from group params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RemoveUserFromGroupParams) WithDefaults() *RemoveUserFromGroupParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the remove user from group params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RemoveUserFromGroupParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the remove user from group params
func (o *RemoveUserFromGroupParams) WithTimeout(timeout time.Duration) *RemoveUserFromGroupParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the remove user from group params
func (o *RemoveUserFromGroupParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the remove user from group params
func (o *RemoveUserFromGroupParams) WithContext(ctx context.Context) *RemoveUserFromGroupParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the remove user from group params
func (o *RemoveUserFromGroupParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the remove user from group params
func (o *RemoveUserFromGroupParams) WithHTTPClient(client *http.Client) *RemoveUserFromGroupParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the remove user from group params
func (o *RemoveUserFromGroupParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGroupID adds the groupID to the remove user from group params
func (o *RemoveUserFromGroupParams) WithGroupID(groupID string) *RemoveUserFromGroupParams {
	o.SetGroupID(groupID)
	return o
}

// SetGroupID adds the groupId to the remove user from group params
func (o *RemoveUserFromGroupParams) SetGroupID(groupID string) {
	o.GroupID = groupID
}

// WithIPID adds the iPID to the remove user from group params
func (o *RemoveUserFromGroupParams) WithIPID(iPID string) *RemoveUserFromGroupParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the remove user from group params
func (o *RemoveUserFromGroupParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the remove user from group params
func (o *RemoveUserFromGroupParams) WithUserID(userID string) *RemoveUserFromGroupParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the remove user from group params
func (o *RemoveUserFromGroupParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *RemoveUserFromGroupParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param groupID
	if err := r.SetPathParam("groupID", o.GroupID); err != nil {
		return err
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
