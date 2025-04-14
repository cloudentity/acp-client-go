// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListIDPsForIdentityPoolReader is a Reader for the ListIDPsForIdentityPool structure.
type ListIDPsForIdentityPoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListIDPsForIdentityPoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListIDPsForIdentityPoolOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListIDPsForIdentityPoolBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListIDPsForIdentityPoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListIDPsForIdentityPoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListIDPsForIdentityPoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListIDPsForIdentityPoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /pools/{ipID}/idps] listIDPsForIdentityPool", response, response.Code())
	}
}

// NewListIDPsForIdentityPoolOK creates a ListIDPsForIdentityPoolOK with default headers values
func NewListIDPsForIdentityPoolOK() *ListIDPsForIdentityPoolOK {
	return &ListIDPsForIdentityPoolOK{}
}

/*
ListIDPsForIdentityPoolOK describes a response with status code 200, with default header values.

IDP
*/
type ListIDPsForIdentityPoolOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.IDPsResponse
}

// IsSuccess returns true when this list Id ps for identity pool o k response has a 2xx status code
func (o *ListIDPsForIdentityPoolOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list Id ps for identity pool o k response has a 3xx status code
func (o *ListIDPsForIdentityPoolOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool o k response has a 4xx status code
func (o *ListIDPsForIdentityPoolOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list Id ps for identity pool o k response has a 5xx status code
func (o *ListIDPsForIdentityPoolOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool o k response a status code equal to that given
func (o *ListIDPsForIdentityPoolOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list Id ps for identity pool o k response
func (o *ListIDPsForIdentityPoolOK) Code() int {
	return 200
}

func (o *ListIDPsForIdentityPoolOK) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolOK  %+v", 200, o.Payload)
}

func (o *ListIDPsForIdentityPoolOK) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolOK  %+v", 200, o.Payload)
}

func (o *ListIDPsForIdentityPoolOK) GetPayload() *models.IDPsResponse {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.IDPsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForIdentityPoolBadRequest creates a ListIDPsForIdentityPoolBadRequest with default headers values
func NewListIDPsForIdentityPoolBadRequest() *ListIDPsForIdentityPoolBadRequest {
	return &ListIDPsForIdentityPoolBadRequest{}
}

/*
ListIDPsForIdentityPoolBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ListIDPsForIdentityPoolBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps for identity pool bad request response has a 2xx status code
func (o *ListIDPsForIdentityPoolBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps for identity pool bad request response has a 3xx status code
func (o *ListIDPsForIdentityPoolBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool bad request response has a 4xx status code
func (o *ListIDPsForIdentityPoolBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps for identity pool bad request response has a 5xx status code
func (o *ListIDPsForIdentityPoolBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool bad request response a status code equal to that given
func (o *ListIDPsForIdentityPoolBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list Id ps for identity pool bad request response
func (o *ListIDPsForIdentityPoolBadRequest) Code() int {
	return 400
}

func (o *ListIDPsForIdentityPoolBadRequest) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolBadRequest  %+v", 400, o.Payload)
}

func (o *ListIDPsForIdentityPoolBadRequest) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolBadRequest  %+v", 400, o.Payload)
}

func (o *ListIDPsForIdentityPoolBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForIdentityPoolUnauthorized creates a ListIDPsForIdentityPoolUnauthorized with default headers values
func NewListIDPsForIdentityPoolUnauthorized() *ListIDPsForIdentityPoolUnauthorized {
	return &ListIDPsForIdentityPoolUnauthorized{}
}

/*
ListIDPsForIdentityPoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListIDPsForIdentityPoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps for identity pool unauthorized response has a 2xx status code
func (o *ListIDPsForIdentityPoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps for identity pool unauthorized response has a 3xx status code
func (o *ListIDPsForIdentityPoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool unauthorized response has a 4xx status code
func (o *ListIDPsForIdentityPoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps for identity pool unauthorized response has a 5xx status code
func (o *ListIDPsForIdentityPoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool unauthorized response a status code equal to that given
func (o *ListIDPsForIdentityPoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list Id ps for identity pool unauthorized response
func (o *ListIDPsForIdentityPoolUnauthorized) Code() int {
	return 401
}

func (o *ListIDPsForIdentityPoolUnauthorized) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIDPsForIdentityPoolUnauthorized) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIDPsForIdentityPoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForIdentityPoolForbidden creates a ListIDPsForIdentityPoolForbidden with default headers values
func NewListIDPsForIdentityPoolForbidden() *ListIDPsForIdentityPoolForbidden {
	return &ListIDPsForIdentityPoolForbidden{}
}

/*
ListIDPsForIdentityPoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListIDPsForIdentityPoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps for identity pool forbidden response has a 2xx status code
func (o *ListIDPsForIdentityPoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps for identity pool forbidden response has a 3xx status code
func (o *ListIDPsForIdentityPoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool forbidden response has a 4xx status code
func (o *ListIDPsForIdentityPoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps for identity pool forbidden response has a 5xx status code
func (o *ListIDPsForIdentityPoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool forbidden response a status code equal to that given
func (o *ListIDPsForIdentityPoolForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list Id ps for identity pool forbidden response
func (o *ListIDPsForIdentityPoolForbidden) Code() int {
	return 403
}

func (o *ListIDPsForIdentityPoolForbidden) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolForbidden  %+v", 403, o.Payload)
}

func (o *ListIDPsForIdentityPoolForbidden) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolForbidden  %+v", 403, o.Payload)
}

func (o *ListIDPsForIdentityPoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForIdentityPoolNotFound creates a ListIDPsForIdentityPoolNotFound with default headers values
func NewListIDPsForIdentityPoolNotFound() *ListIDPsForIdentityPoolNotFound {
	return &ListIDPsForIdentityPoolNotFound{}
}

/*
ListIDPsForIdentityPoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListIDPsForIdentityPoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps for identity pool not found response has a 2xx status code
func (o *ListIDPsForIdentityPoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps for identity pool not found response has a 3xx status code
func (o *ListIDPsForIdentityPoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool not found response has a 4xx status code
func (o *ListIDPsForIdentityPoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps for identity pool not found response has a 5xx status code
func (o *ListIDPsForIdentityPoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool not found response a status code equal to that given
func (o *ListIDPsForIdentityPoolNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list Id ps for identity pool not found response
func (o *ListIDPsForIdentityPoolNotFound) Code() int {
	return 404
}

func (o *ListIDPsForIdentityPoolNotFound) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolNotFound  %+v", 404, o.Payload)
}

func (o *ListIDPsForIdentityPoolNotFound) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolNotFound  %+v", 404, o.Payload)
}

func (o *ListIDPsForIdentityPoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForIdentityPoolTooManyRequests creates a ListIDPsForIdentityPoolTooManyRequests with default headers values
func NewListIDPsForIdentityPoolTooManyRequests() *ListIDPsForIdentityPoolTooManyRequests {
	return &ListIDPsForIdentityPoolTooManyRequests{}
}

/*
ListIDPsForIdentityPoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListIDPsForIdentityPoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps for identity pool too many requests response has a 2xx status code
func (o *ListIDPsForIdentityPoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps for identity pool too many requests response has a 3xx status code
func (o *ListIDPsForIdentityPoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps for identity pool too many requests response has a 4xx status code
func (o *ListIDPsForIdentityPoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps for identity pool too many requests response has a 5xx status code
func (o *ListIDPsForIdentityPoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps for identity pool too many requests response a status code equal to that given
func (o *ListIDPsForIdentityPoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list Id ps for identity pool too many requests response
func (o *ListIDPsForIdentityPoolTooManyRequests) Code() int {
	return 429
}

func (o *ListIDPsForIdentityPoolTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIDPsForIdentityPoolTooManyRequests) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/idps][%d] listIdPsForIdentityPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIDPsForIdentityPoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForIdentityPoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
