// Code generated by go-swagger; DO NOT EDIT.

package system

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListSystemAPIsReader is a Reader for the ListSystemAPIs structure.
type ListSystemAPIsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListSystemAPIsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListSystemAPIsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListSystemAPIsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListSystemAPIsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListSystemAPIsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /system/apis] listSystemAPIs", response, response.Code())
	}
}

// NewListSystemAPIsOK creates a ListSystemAPIsOK with default headers values
func NewListSystemAPIsOK() *ListSystemAPIsOK {
	return &ListSystemAPIsOK{}
}

/*
ListSystemAPIsOK describes a response with status code 200, with default header values.

APIs grouped by service ids
*/
type ListSystemAPIsOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServerAPIs
}

// IsSuccess returns true when this list system a p is o k response has a 2xx status code
func (o *ListSystemAPIsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list system a p is o k response has a 3xx status code
func (o *ListSystemAPIsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list system a p is o k response has a 4xx status code
func (o *ListSystemAPIsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list system a p is o k response has a 5xx status code
func (o *ListSystemAPIsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list system a p is o k response a status code equal to that given
func (o *ListSystemAPIsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list system a p is o k response
func (o *ListSystemAPIsOK) Code() int {
	return 200
}

func (o *ListSystemAPIsOK) Error() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsOK  %+v", 200, o.Payload)
}

func (o *ListSystemAPIsOK) String() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsOK  %+v", 200, o.Payload)
}

func (o *ListSystemAPIsOK) GetPayload() *models.ServerAPIs {
	return o.Payload
}

func (o *ListSystemAPIsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServerAPIs)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSystemAPIsUnauthorized creates a ListSystemAPIsUnauthorized with default headers values
func NewListSystemAPIsUnauthorized() *ListSystemAPIsUnauthorized {
	return &ListSystemAPIsUnauthorized{}
}

/*
ListSystemAPIsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListSystemAPIsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list system a p is unauthorized response has a 2xx status code
func (o *ListSystemAPIsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list system a p is unauthorized response has a 3xx status code
func (o *ListSystemAPIsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list system a p is unauthorized response has a 4xx status code
func (o *ListSystemAPIsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list system a p is unauthorized response has a 5xx status code
func (o *ListSystemAPIsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list system a p is unauthorized response a status code equal to that given
func (o *ListSystemAPIsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list system a p is unauthorized response
func (o *ListSystemAPIsUnauthorized) Code() int {
	return 401
}

func (o *ListSystemAPIsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListSystemAPIsUnauthorized) String() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListSystemAPIsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSystemAPIsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSystemAPIsForbidden creates a ListSystemAPIsForbidden with default headers values
func NewListSystemAPIsForbidden() *ListSystemAPIsForbidden {
	return &ListSystemAPIsForbidden{}
}

/*
ListSystemAPIsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListSystemAPIsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list system a p is forbidden response has a 2xx status code
func (o *ListSystemAPIsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list system a p is forbidden response has a 3xx status code
func (o *ListSystemAPIsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list system a p is forbidden response has a 4xx status code
func (o *ListSystemAPIsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list system a p is forbidden response has a 5xx status code
func (o *ListSystemAPIsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list system a p is forbidden response a status code equal to that given
func (o *ListSystemAPIsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list system a p is forbidden response
func (o *ListSystemAPIsForbidden) Code() int {
	return 403
}

func (o *ListSystemAPIsForbidden) Error() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsForbidden  %+v", 403, o.Payload)
}

func (o *ListSystemAPIsForbidden) String() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsForbidden  %+v", 403, o.Payload)
}

func (o *ListSystemAPIsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSystemAPIsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSystemAPIsTooManyRequests creates a ListSystemAPIsTooManyRequests with default headers values
func NewListSystemAPIsTooManyRequests() *ListSystemAPIsTooManyRequests {
	return &ListSystemAPIsTooManyRequests{}
}

/*
ListSystemAPIsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListSystemAPIsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list system a p is too many requests response has a 2xx status code
func (o *ListSystemAPIsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list system a p is too many requests response has a 3xx status code
func (o *ListSystemAPIsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list system a p is too many requests response has a 4xx status code
func (o *ListSystemAPIsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list system a p is too many requests response has a 5xx status code
func (o *ListSystemAPIsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list system a p is too many requests response a status code equal to that given
func (o *ListSystemAPIsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list system a p is too many requests response
func (o *ListSystemAPIsTooManyRequests) Code() int {
	return 429
}

func (o *ListSystemAPIsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListSystemAPIsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /system/apis][%d] listSystemAPIsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListSystemAPIsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSystemAPIsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
