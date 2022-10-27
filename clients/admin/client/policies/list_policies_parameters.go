// Code generated by go-swagger; DO NOT EDIT.

package policies

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
	"github.com/go-openapi/swag"
)

// NewListPoliciesParams creates a new ListPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListPoliciesParams() *ListPoliciesParams {
	return &ListPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListPoliciesParamsWithTimeout creates a new ListPoliciesParams object
// with the ability to set a timeout on a request.
func NewListPoliciesParamsWithTimeout(timeout time.Duration) *ListPoliciesParams {
	return &ListPoliciesParams{
		timeout: timeout,
	}
}

// NewListPoliciesParamsWithContext creates a new ListPoliciesParams object
// with the ability to set a context for a request.
func NewListPoliciesParamsWithContext(ctx context.Context) *ListPoliciesParams {
	return &ListPoliciesParams{
		Context: ctx,
	}
}

// NewListPoliciesParamsWithHTTPClient creates a new ListPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListPoliciesParamsWithHTTPClient(client *http.Client) *ListPoliciesParams {
	return &ListPoliciesParams{
		HTTPClient: client,
	}
}

/*
ListPoliciesParams contains all the parameters to send to the API endpoint

	for the list policies operation.

	Typically these are written to a http.Request.
*/
type ListPoliciesParams struct {

	/* AfterPolicyID.

	     String represented policy ID

	The `AfterPolicyID` parameter defines the ID of the last displayed policy on a page.
	For example, if there are 20 policies and only 10 are displayed per page, in
	order to jump to the next page, you need to provide the ID of the last policy on that page as
	the value of the `AfterPolicyID` parameter.
	AfterPolicyID
	*/
	AfterPolicyID *string

	/* BeforePolicyID.

	     String represented policy ID

	The `BeforePolicyID` parameter defines the ID of the last displayed policy on a page.
	For example, if there are 20 policies and only 10 are displayed per page, in
	order to jump to the previous page, you need to provide the ID of the first policy on that page as
	the value of the `Before PolicyID` parameter.
	BeforePolicyID
	*/
	BeforePolicyID *string

	/* Limit.

	     A limit of displayed results per page for listed policies
	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     An ascending or descending order of sorting the policies
	Order
	*/
	Order *string

	/* PolicyTypes.

	   An array of policy types that are to be filtered out

	   Default: "api"
	*/
	PolicyTypes *string

	/* SearchPhrase.

	     An optional and case insensitive search phrase that contains either a policy ID or a policy
	name substring
	SearchPhrase
	*/
	SearchPhrase *string

	/* Sort.

	     Defines the method of sorting the results by a given field
	Sort
	*/
	Sort *string

	/* Wid.

	   Id of your authorization server (workspace)

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListPoliciesParams) WithDefaults() *ListPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListPoliciesParams) SetDefaults() {
	var (
		limitDefault = int64(20)

		policyTypesDefault = string("api")

		widDefault = string("default")
	)

	val := ListPoliciesParams{
		Limit:       &limitDefault,
		PolicyTypes: &policyTypesDefault,
		Wid:         widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list policies params
func (o *ListPoliciesParams) WithTimeout(timeout time.Duration) *ListPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list policies params
func (o *ListPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list policies params
func (o *ListPoliciesParams) WithContext(ctx context.Context) *ListPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list policies params
func (o *ListPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list policies params
func (o *ListPoliciesParams) WithHTTPClient(client *http.Client) *ListPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list policies params
func (o *ListPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterPolicyID adds the afterPolicyID to the list policies params
func (o *ListPoliciesParams) WithAfterPolicyID(afterPolicyID *string) *ListPoliciesParams {
	o.SetAfterPolicyID(afterPolicyID)
	return o
}

// SetAfterPolicyID adds the afterPolicyId to the list policies params
func (o *ListPoliciesParams) SetAfterPolicyID(afterPolicyID *string) {
	o.AfterPolicyID = afterPolicyID
}

// WithBeforePolicyID adds the beforePolicyID to the list policies params
func (o *ListPoliciesParams) WithBeforePolicyID(beforePolicyID *string) *ListPoliciesParams {
	o.SetBeforePolicyID(beforePolicyID)
	return o
}

// SetBeforePolicyID adds the beforePolicyId to the list policies params
func (o *ListPoliciesParams) SetBeforePolicyID(beforePolicyID *string) {
	o.BeforePolicyID = beforePolicyID
}

// WithLimit adds the limit to the list policies params
func (o *ListPoliciesParams) WithLimit(limit *int64) *ListPoliciesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list policies params
func (o *ListPoliciesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list policies params
func (o *ListPoliciesParams) WithOrder(order *string) *ListPoliciesParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list policies params
func (o *ListPoliciesParams) SetOrder(order *string) {
	o.Order = order
}

// WithPolicyTypes adds the policyTypes to the list policies params
func (o *ListPoliciesParams) WithPolicyTypes(policyTypes *string) *ListPoliciesParams {
	o.SetPolicyTypes(policyTypes)
	return o
}

// SetPolicyTypes adds the policyTypes to the list policies params
func (o *ListPoliciesParams) SetPolicyTypes(policyTypes *string) {
	o.PolicyTypes = policyTypes
}

// WithSearchPhrase adds the searchPhrase to the list policies params
func (o *ListPoliciesParams) WithSearchPhrase(searchPhrase *string) *ListPoliciesParams {
	o.SetSearchPhrase(searchPhrase)
	return o
}

// SetSearchPhrase adds the searchPhrase to the list policies params
func (o *ListPoliciesParams) SetSearchPhrase(searchPhrase *string) {
	o.SearchPhrase = searchPhrase
}

// WithSort adds the sort to the list policies params
func (o *ListPoliciesParams) WithSort(sort *string) *ListPoliciesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list policies params
func (o *ListPoliciesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithWid adds the wid to the list policies params
func (o *ListPoliciesParams) WithWid(wid string) *ListPoliciesParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list policies params
func (o *ListPoliciesParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterPolicyID != nil {

		// query param after_policy_id
		var qrAfterPolicyID string

		if o.AfterPolicyID != nil {
			qrAfterPolicyID = *o.AfterPolicyID
		}
		qAfterPolicyID := qrAfterPolicyID
		if qAfterPolicyID != "" {

			if err := r.SetQueryParam("after_policy_id", qAfterPolicyID); err != nil {
				return err
			}
		}
	}

	if o.BeforePolicyID != nil {

		// query param before_policy_id
		var qrBeforePolicyID string

		if o.BeforePolicyID != nil {
			qrBeforePolicyID = *o.BeforePolicyID
		}
		qBeforePolicyID := qrBeforePolicyID
		if qBeforePolicyID != "" {

			if err := r.SetQueryParam("before_policy_id", qBeforePolicyID); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Order != nil {

		// query param order
		var qrOrder string

		if o.Order != nil {
			qrOrder = *o.Order
		}
		qOrder := qrOrder
		if qOrder != "" {

			if err := r.SetQueryParam("order", qOrder); err != nil {
				return err
			}
		}
	}

	if o.PolicyTypes != nil {

		// query param policy_types
		var qrPolicyTypes string

		if o.PolicyTypes != nil {
			qrPolicyTypes = *o.PolicyTypes
		}
		qPolicyTypes := qrPolicyTypes
		if qPolicyTypes != "" {

			if err := r.SetQueryParam("policy_types", qPolicyTypes); err != nil {
				return err
			}
		}
	}

	if o.SearchPhrase != nil {

		// query param search_phrase
		var qrSearchPhrase string

		if o.SearchPhrase != nil {
			qrSearchPhrase = *o.SearchPhrase
		}
		qSearchPhrase := qrSearchPhrase
		if qSearchPhrase != "" {

			if err := r.SetQueryParam("search_phrase", qSearchPhrase); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
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
