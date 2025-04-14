// Code generated by go-swagger; DO NOT EDIT.

package services

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

// ListServicesReader is a Reader for the ListServices structure.
type ListServicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServicesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListServicesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListServicesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListServicesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListServicesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListServicesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/services] listServices", response, response.Code())
	}
}

// NewListServicesOK creates a ListServicesOK with default headers values
func NewListServicesOK() *ListServicesOK {
	return &ListServicesOK{}
}

/*
ListServicesOK describes a response with status code 200, with default header values.

Services
*/
type ListServicesOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServicesResponse
}

// IsSuccess returns true when this list services o k response has a 2xx status code
func (o *ListServicesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list services o k response has a 3xx status code
func (o *ListServicesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services o k response has a 4xx status code
func (o *ListServicesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list services o k response has a 5xx status code
func (o *ListServicesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list services o k response a status code equal to that given
func (o *ListServicesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list services o k response
func (o *ListServicesOK) Code() int {
	return 200
}

func (o *ListServicesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesOK %s", 200, payload)
}

func (o *ListServicesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesOK %s", 200, payload)
}

func (o *ListServicesOK) GetPayload() *models.ServicesResponse {
	return o.Payload
}

func (o *ListServicesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServicesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesBadRequest creates a ListServicesBadRequest with default headers values
func NewListServicesBadRequest() *ListServicesBadRequest {
	return &ListServicesBadRequest{}
}

/*
ListServicesBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ListServicesBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list services bad request response has a 2xx status code
func (o *ListServicesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list services bad request response has a 3xx status code
func (o *ListServicesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services bad request response has a 4xx status code
func (o *ListServicesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list services bad request response has a 5xx status code
func (o *ListServicesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list services bad request response a status code equal to that given
func (o *ListServicesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list services bad request response
func (o *ListServicesBadRequest) Code() int {
	return 400
}

func (o *ListServicesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesBadRequest %s", 400, payload)
}

func (o *ListServicesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesBadRequest %s", 400, payload)
}

func (o *ListServicesBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServicesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesUnauthorized creates a ListServicesUnauthorized with default headers values
func NewListServicesUnauthorized() *ListServicesUnauthorized {
	return &ListServicesUnauthorized{}
}

/*
ListServicesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListServicesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list services unauthorized response has a 2xx status code
func (o *ListServicesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list services unauthorized response has a 3xx status code
func (o *ListServicesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services unauthorized response has a 4xx status code
func (o *ListServicesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list services unauthorized response has a 5xx status code
func (o *ListServicesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list services unauthorized response a status code equal to that given
func (o *ListServicesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list services unauthorized response
func (o *ListServicesUnauthorized) Code() int {
	return 401
}

func (o *ListServicesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesUnauthorized %s", 401, payload)
}

func (o *ListServicesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesUnauthorized %s", 401, payload)
}

func (o *ListServicesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServicesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesForbidden creates a ListServicesForbidden with default headers values
func NewListServicesForbidden() *ListServicesForbidden {
	return &ListServicesForbidden{}
}

/*
ListServicesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListServicesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list services forbidden response has a 2xx status code
func (o *ListServicesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list services forbidden response has a 3xx status code
func (o *ListServicesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services forbidden response has a 4xx status code
func (o *ListServicesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list services forbidden response has a 5xx status code
func (o *ListServicesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list services forbidden response a status code equal to that given
func (o *ListServicesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list services forbidden response
func (o *ListServicesForbidden) Code() int {
	return 403
}

func (o *ListServicesForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesForbidden %s", 403, payload)
}

func (o *ListServicesForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesForbidden %s", 403, payload)
}

func (o *ListServicesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServicesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesNotFound creates a ListServicesNotFound with default headers values
func NewListServicesNotFound() *ListServicesNotFound {
	return &ListServicesNotFound{}
}

/*
ListServicesNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListServicesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list services not found response has a 2xx status code
func (o *ListServicesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list services not found response has a 3xx status code
func (o *ListServicesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services not found response has a 4xx status code
func (o *ListServicesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list services not found response has a 5xx status code
func (o *ListServicesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list services not found response a status code equal to that given
func (o *ListServicesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list services not found response
func (o *ListServicesNotFound) Code() int {
	return 404
}

func (o *ListServicesNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesNotFound %s", 404, payload)
}

func (o *ListServicesNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesNotFound %s", 404, payload)
}

func (o *ListServicesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServicesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesTooManyRequests creates a ListServicesTooManyRequests with default headers values
func NewListServicesTooManyRequests() *ListServicesTooManyRequests {
	return &ListServicesTooManyRequests{}
}

/*
ListServicesTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListServicesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list services too many requests response has a 2xx status code
func (o *ListServicesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list services too many requests response has a 3xx status code
func (o *ListServicesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list services too many requests response has a 4xx status code
func (o *ListServicesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list services too many requests response has a 5xx status code
func (o *ListServicesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list services too many requests response a status code equal to that given
func (o *ListServicesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list services too many requests response
func (o *ListServicesTooManyRequests) Code() int {
	return 429
}

func (o *ListServicesTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesTooManyRequests %s", 429, payload)
}

func (o *ListServicesTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/services][%d] listServicesTooManyRequests %s", 429, payload)
}

func (o *ListServicesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServicesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
