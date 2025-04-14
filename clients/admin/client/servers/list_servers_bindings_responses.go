// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListServersBindingsReader is a Reader for the ListServersBindings structure.
type ListServersBindingsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServersBindingsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServersBindingsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListServersBindingsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListServersBindingsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListServersBindingsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListServersBindingsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers-bindings] listServersBindings", response, response.Code())
	}
}

// NewListServersBindingsOK creates a ListServersBindingsOK with default headers values
func NewListServersBindingsOK() *ListServersBindingsOK {
	return &ListServersBindingsOK{}
}

/*
ListServersBindingsOK describes a response with status code 200, with default header values.

Server bindings
*/
type ListServersBindingsOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServersBindingsResponse
}

// IsSuccess returns true when this list servers bindings o k response has a 2xx status code
func (o *ListServersBindingsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list servers bindings o k response has a 3xx status code
func (o *ListServersBindingsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers bindings o k response has a 4xx status code
func (o *ListServersBindingsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list servers bindings o k response has a 5xx status code
func (o *ListServersBindingsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers bindings o k response a status code equal to that given
func (o *ListServersBindingsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list servers bindings o k response
func (o *ListServersBindingsOK) Code() int {
	return 200
}

func (o *ListServersBindingsOK) Error() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsOK  %+v", 200, o.Payload)
}

func (o *ListServersBindingsOK) String() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsOK  %+v", 200, o.Payload)
}

func (o *ListServersBindingsOK) GetPayload() *models.ServersBindingsResponse {
	return o.Payload
}

func (o *ListServersBindingsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServersBindingsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersBindingsUnauthorized creates a ListServersBindingsUnauthorized with default headers values
func NewListServersBindingsUnauthorized() *ListServersBindingsUnauthorized {
	return &ListServersBindingsUnauthorized{}
}

/*
ListServersBindingsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListServersBindingsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers bindings unauthorized response has a 2xx status code
func (o *ListServersBindingsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers bindings unauthorized response has a 3xx status code
func (o *ListServersBindingsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers bindings unauthorized response has a 4xx status code
func (o *ListServersBindingsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers bindings unauthorized response has a 5xx status code
func (o *ListServersBindingsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers bindings unauthorized response a status code equal to that given
func (o *ListServersBindingsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list servers bindings unauthorized response
func (o *ListServersBindingsUnauthorized) Code() int {
	return 401
}

func (o *ListServersBindingsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServersBindingsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServersBindingsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersBindingsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersBindingsForbidden creates a ListServersBindingsForbidden with default headers values
func NewListServersBindingsForbidden() *ListServersBindingsForbidden {
	return &ListServersBindingsForbidden{}
}

/*
ListServersBindingsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListServersBindingsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers bindings forbidden response has a 2xx status code
func (o *ListServersBindingsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers bindings forbidden response has a 3xx status code
func (o *ListServersBindingsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers bindings forbidden response has a 4xx status code
func (o *ListServersBindingsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers bindings forbidden response has a 5xx status code
func (o *ListServersBindingsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers bindings forbidden response a status code equal to that given
func (o *ListServersBindingsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list servers bindings forbidden response
func (o *ListServersBindingsForbidden) Code() int {
	return 403
}

func (o *ListServersBindingsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsForbidden  %+v", 403, o.Payload)
}

func (o *ListServersBindingsForbidden) String() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsForbidden  %+v", 403, o.Payload)
}

func (o *ListServersBindingsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersBindingsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersBindingsNotFound creates a ListServersBindingsNotFound with default headers values
func NewListServersBindingsNotFound() *ListServersBindingsNotFound {
	return &ListServersBindingsNotFound{}
}

/*
ListServersBindingsNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListServersBindingsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers bindings not found response has a 2xx status code
func (o *ListServersBindingsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers bindings not found response has a 3xx status code
func (o *ListServersBindingsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers bindings not found response has a 4xx status code
func (o *ListServersBindingsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers bindings not found response has a 5xx status code
func (o *ListServersBindingsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers bindings not found response a status code equal to that given
func (o *ListServersBindingsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list servers bindings not found response
func (o *ListServersBindingsNotFound) Code() int {
	return 404
}

func (o *ListServersBindingsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsNotFound  %+v", 404, o.Payload)
}

func (o *ListServersBindingsNotFound) String() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsNotFound  %+v", 404, o.Payload)
}

func (o *ListServersBindingsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersBindingsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersBindingsTooManyRequests creates a ListServersBindingsTooManyRequests with default headers values
func NewListServersBindingsTooManyRequests() *ListServersBindingsTooManyRequests {
	return &ListServersBindingsTooManyRequests{}
}

/*
ListServersBindingsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListServersBindingsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers bindings too many requests response has a 2xx status code
func (o *ListServersBindingsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers bindings too many requests response has a 3xx status code
func (o *ListServersBindingsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers bindings too many requests response has a 4xx status code
func (o *ListServersBindingsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers bindings too many requests response has a 5xx status code
func (o *ListServersBindingsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers bindings too many requests response a status code equal to that given
func (o *ListServersBindingsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list servers bindings too many requests response
func (o *ListServersBindingsTooManyRequests) Code() int {
	return 429
}

func (o *ListServersBindingsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListServersBindingsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers-bindings][%d] listServersBindingsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListServersBindingsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersBindingsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
