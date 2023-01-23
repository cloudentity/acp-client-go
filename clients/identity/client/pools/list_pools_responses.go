// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// ListPoolsReader is a Reader for the ListPools structure.
type ListPoolsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListPoolsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListPoolsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListPoolsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListPoolsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListPoolsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListPoolsOK creates a ListPoolsOK with default headers values
func NewListPoolsOK() *ListPoolsOK {
	return &ListPoolsOK{}
}

/*
ListPoolsOK describes a response with status code 200, with default header values.

Pools
*/
type ListPoolsOK struct {
	Payload *models.Pools
}

// IsSuccess returns true when this list pools o k response has a 2xx status code
func (o *ListPoolsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list pools o k response has a 3xx status code
func (o *ListPoolsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list pools o k response has a 4xx status code
func (o *ListPoolsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list pools o k response has a 5xx status code
func (o *ListPoolsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list pools o k response a status code equal to that given
func (o *ListPoolsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListPoolsOK) Error() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsOK  %+v", 200, o.Payload)
}

func (o *ListPoolsOK) String() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsOK  %+v", 200, o.Payload)
}

func (o *ListPoolsOK) GetPayload() *models.Pools {
	return o.Payload
}

func (o *ListPoolsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Pools)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoolsUnauthorized creates a ListPoolsUnauthorized with default headers values
func NewListPoolsUnauthorized() *ListPoolsUnauthorized {
	return &ListPoolsUnauthorized{}
}

/*
ListPoolsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListPoolsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list pools unauthorized response has a 2xx status code
func (o *ListPoolsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list pools unauthorized response has a 3xx status code
func (o *ListPoolsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list pools unauthorized response has a 4xx status code
func (o *ListPoolsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list pools unauthorized response has a 5xx status code
func (o *ListPoolsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list pools unauthorized response a status code equal to that given
func (o *ListPoolsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListPoolsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPoolsUnauthorized) String() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPoolsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoolsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoolsForbidden creates a ListPoolsForbidden with default headers values
func NewListPoolsForbidden() *ListPoolsForbidden {
	return &ListPoolsForbidden{}
}

/*
ListPoolsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListPoolsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list pools forbidden response has a 2xx status code
func (o *ListPoolsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list pools forbidden response has a 3xx status code
func (o *ListPoolsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list pools forbidden response has a 4xx status code
func (o *ListPoolsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list pools forbidden response has a 5xx status code
func (o *ListPoolsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list pools forbidden response a status code equal to that given
func (o *ListPoolsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListPoolsForbidden) Error() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsForbidden  %+v", 403, o.Payload)
}

func (o *ListPoolsForbidden) String() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsForbidden  %+v", 403, o.Payload)
}

func (o *ListPoolsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoolsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoolsTooManyRequests creates a ListPoolsTooManyRequests with default headers values
func NewListPoolsTooManyRequests() *ListPoolsTooManyRequests {
	return &ListPoolsTooManyRequests{}
}

/*
ListPoolsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListPoolsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list pools too many requests response has a 2xx status code
func (o *ListPoolsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list pools too many requests response has a 3xx status code
func (o *ListPoolsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list pools too many requests response has a 4xx status code
func (o *ListPoolsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list pools too many requests response has a 5xx status code
func (o *ListPoolsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list pools too many requests response a status code equal to that given
func (o *ListPoolsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListPoolsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPoolsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /admin/pools][%d] listPoolsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPoolsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoolsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
