// Code generated by go-swagger; DO NOT EDIT.

package apis

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListAPIsByServiceReader is a Reader for the ListAPIsByService structure.
type ListAPIsByServiceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListAPIsByServiceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListAPIsByServiceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListAPIsByServiceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListAPIsByServiceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListAPIsByServiceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /services/{sid}/apis] listAPIsByService", response, response.Code())
	}
}

// NewListAPIsByServiceOK creates a ListAPIsByServiceOK with default headers values
func NewListAPIsByServiceOK() *ListAPIsByServiceOK {
	return &ListAPIsByServiceOK{}
}

/*
ListAPIsByServiceOK describes a response with status code 200, with default header values.

APIs
*/
type ListAPIsByServiceOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.APIs
}

// IsSuccess returns true when this list a p is by service o k response has a 2xx status code
func (o *ListAPIsByServiceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list a p is by service o k response has a 3xx status code
func (o *ListAPIsByServiceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a p is by service o k response has a 4xx status code
func (o *ListAPIsByServiceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list a p is by service o k response has a 5xx status code
func (o *ListAPIsByServiceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list a p is by service o k response a status code equal to that given
func (o *ListAPIsByServiceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list a p is by service o k response
func (o *ListAPIsByServiceOK) Code() int {
	return 200
}

func (o *ListAPIsByServiceOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceOK %s", 200, payload)
}

func (o *ListAPIsByServiceOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceOK %s", 200, payload)
}

func (o *ListAPIsByServiceOK) GetPayload() *models.APIs {
	return o.Payload
}

func (o *ListAPIsByServiceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.APIs)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAPIsByServiceUnauthorized creates a ListAPIsByServiceUnauthorized with default headers values
func NewListAPIsByServiceUnauthorized() *ListAPIsByServiceUnauthorized {
	return &ListAPIsByServiceUnauthorized{}
}

/*
ListAPIsByServiceUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListAPIsByServiceUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a p is by service unauthorized response has a 2xx status code
func (o *ListAPIsByServiceUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a p is by service unauthorized response has a 3xx status code
func (o *ListAPIsByServiceUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a p is by service unauthorized response has a 4xx status code
func (o *ListAPIsByServiceUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a p is by service unauthorized response has a 5xx status code
func (o *ListAPIsByServiceUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list a p is by service unauthorized response a status code equal to that given
func (o *ListAPIsByServiceUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list a p is by service unauthorized response
func (o *ListAPIsByServiceUnauthorized) Code() int {
	return 401
}

func (o *ListAPIsByServiceUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceUnauthorized %s", 401, payload)
}

func (o *ListAPIsByServiceUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceUnauthorized %s", 401, payload)
}

func (o *ListAPIsByServiceUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAPIsByServiceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAPIsByServiceForbidden creates a ListAPIsByServiceForbidden with default headers values
func NewListAPIsByServiceForbidden() *ListAPIsByServiceForbidden {
	return &ListAPIsByServiceForbidden{}
}

/*
ListAPIsByServiceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListAPIsByServiceForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a p is by service forbidden response has a 2xx status code
func (o *ListAPIsByServiceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a p is by service forbidden response has a 3xx status code
func (o *ListAPIsByServiceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a p is by service forbidden response has a 4xx status code
func (o *ListAPIsByServiceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a p is by service forbidden response has a 5xx status code
func (o *ListAPIsByServiceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list a p is by service forbidden response a status code equal to that given
func (o *ListAPIsByServiceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list a p is by service forbidden response
func (o *ListAPIsByServiceForbidden) Code() int {
	return 403
}

func (o *ListAPIsByServiceForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceForbidden %s", 403, payload)
}

func (o *ListAPIsByServiceForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceForbidden %s", 403, payload)
}

func (o *ListAPIsByServiceForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAPIsByServiceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAPIsByServiceTooManyRequests creates a ListAPIsByServiceTooManyRequests with default headers values
func NewListAPIsByServiceTooManyRequests() *ListAPIsByServiceTooManyRequests {
	return &ListAPIsByServiceTooManyRequests{}
}

/*
ListAPIsByServiceTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListAPIsByServiceTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a p is by service too many requests response has a 2xx status code
func (o *ListAPIsByServiceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a p is by service too many requests response has a 3xx status code
func (o *ListAPIsByServiceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a p is by service too many requests response has a 4xx status code
func (o *ListAPIsByServiceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a p is by service too many requests response has a 5xx status code
func (o *ListAPIsByServiceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list a p is by service too many requests response a status code equal to that given
func (o *ListAPIsByServiceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list a p is by service too many requests response
func (o *ListAPIsByServiceTooManyRequests) Code() int {
	return 429
}

func (o *ListAPIsByServiceTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceTooManyRequests %s", 429, payload)
}

func (o *ListAPIsByServiceTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /services/{sid}/apis][%d] listAPIsByServiceTooManyRequests %s", 429, payload)
}

func (o *ListAPIsByServiceTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAPIsByServiceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
