// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// ListOrganizationsReader is a Reader for the ListOrganizations structure.
type ListOrganizationsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListOrganizationsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListOrganizationsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListOrganizationsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListOrganizationsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListOrganizationsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListOrganizationsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /organizations] listOrganizations", response, response.Code())
	}
}

// NewListOrganizationsOK creates a ListOrganizationsOK with default headers values
func NewListOrganizationsOK() *ListOrganizationsOK {
	return &ListOrganizationsOK{}
}

/*
ListOrganizationsOK describes a response with status code 200, with default header values.

Orgs
*/
type ListOrganizationsOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.OrganizationsResponse
}

// IsSuccess returns true when this list organizations o k response has a 2xx status code
func (o *ListOrganizationsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list organizations o k response has a 3xx status code
func (o *ListOrganizationsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list organizations o k response has a 4xx status code
func (o *ListOrganizationsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list organizations o k response has a 5xx status code
func (o *ListOrganizationsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list organizations o k response a status code equal to that given
func (o *ListOrganizationsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list organizations o k response
func (o *ListOrganizationsOK) Code() int {
	return 200
}

func (o *ListOrganizationsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsOK %s", 200, payload)
}

func (o *ListOrganizationsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsOK %s", 200, payload)
}

func (o *ListOrganizationsOK) GetPayload() *models.OrganizationsResponse {
	return o.Payload
}

func (o *ListOrganizationsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.OrganizationsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOrganizationsUnauthorized creates a ListOrganizationsUnauthorized with default headers values
func NewListOrganizationsUnauthorized() *ListOrganizationsUnauthorized {
	return &ListOrganizationsUnauthorized{}
}

/*
ListOrganizationsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListOrganizationsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list organizations unauthorized response has a 2xx status code
func (o *ListOrganizationsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list organizations unauthorized response has a 3xx status code
func (o *ListOrganizationsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list organizations unauthorized response has a 4xx status code
func (o *ListOrganizationsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list organizations unauthorized response has a 5xx status code
func (o *ListOrganizationsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list organizations unauthorized response a status code equal to that given
func (o *ListOrganizationsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list organizations unauthorized response
func (o *ListOrganizationsUnauthorized) Code() int {
	return 401
}

func (o *ListOrganizationsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsUnauthorized %s", 401, payload)
}

func (o *ListOrganizationsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsUnauthorized %s", 401, payload)
}

func (o *ListOrganizationsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListOrganizationsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOrganizationsForbidden creates a ListOrganizationsForbidden with default headers values
func NewListOrganizationsForbidden() *ListOrganizationsForbidden {
	return &ListOrganizationsForbidden{}
}

/*
ListOrganizationsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListOrganizationsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list organizations forbidden response has a 2xx status code
func (o *ListOrganizationsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list organizations forbidden response has a 3xx status code
func (o *ListOrganizationsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list organizations forbidden response has a 4xx status code
func (o *ListOrganizationsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list organizations forbidden response has a 5xx status code
func (o *ListOrganizationsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list organizations forbidden response a status code equal to that given
func (o *ListOrganizationsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list organizations forbidden response
func (o *ListOrganizationsForbidden) Code() int {
	return 403
}

func (o *ListOrganizationsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsForbidden %s", 403, payload)
}

func (o *ListOrganizationsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsForbidden %s", 403, payload)
}

func (o *ListOrganizationsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListOrganizationsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOrganizationsNotFound creates a ListOrganizationsNotFound with default headers values
func NewListOrganizationsNotFound() *ListOrganizationsNotFound {
	return &ListOrganizationsNotFound{}
}

/*
ListOrganizationsNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListOrganizationsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list organizations not found response has a 2xx status code
func (o *ListOrganizationsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list organizations not found response has a 3xx status code
func (o *ListOrganizationsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list organizations not found response has a 4xx status code
func (o *ListOrganizationsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list organizations not found response has a 5xx status code
func (o *ListOrganizationsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list organizations not found response a status code equal to that given
func (o *ListOrganizationsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list organizations not found response
func (o *ListOrganizationsNotFound) Code() int {
	return 404
}

func (o *ListOrganizationsNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsNotFound %s", 404, payload)
}

func (o *ListOrganizationsNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsNotFound %s", 404, payload)
}

func (o *ListOrganizationsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListOrganizationsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOrganizationsTooManyRequests creates a ListOrganizationsTooManyRequests with default headers values
func NewListOrganizationsTooManyRequests() *ListOrganizationsTooManyRequests {
	return &ListOrganizationsTooManyRequests{}
}

/*
ListOrganizationsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListOrganizationsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list organizations too many requests response has a 2xx status code
func (o *ListOrganizationsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list organizations too many requests response has a 3xx status code
func (o *ListOrganizationsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list organizations too many requests response has a 4xx status code
func (o *ListOrganizationsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list organizations too many requests response has a 5xx status code
func (o *ListOrganizationsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list organizations too many requests response a status code equal to that given
func (o *ListOrganizationsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list organizations too many requests response
func (o *ListOrganizationsTooManyRequests) Code() int {
	return 429
}

func (o *ListOrganizationsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsTooManyRequests %s", 429, payload)
}

func (o *ListOrganizationsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /organizations][%d] listOrganizationsTooManyRequests %s", 429, payload)
}

func (o *ListOrganizationsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListOrganizationsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
