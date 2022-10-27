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

// ListAuthorizationServersReader is a Reader for the ListAuthorizationServers structure.
type ListAuthorizationServersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListAuthorizationServersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListAuthorizationServersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListAuthorizationServersUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListAuthorizationServersForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListAuthorizationServersNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListAuthorizationServersTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListAuthorizationServersOK creates a ListAuthorizationServersOK with default headers values
func NewListAuthorizationServersOK() *ListAuthorizationServersOK {
	return &ListAuthorizationServersOK{}
}

/*
ListAuthorizationServersOK describes a response with status code 200, with default header values.

Servers
*/
type ListAuthorizationServersOK struct {
	Payload *models.ServersResponse
}

// IsSuccess returns true when this list authorization servers o k response has a 2xx status code
func (o *ListAuthorizationServersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list authorization servers o k response has a 3xx status code
func (o *ListAuthorizationServersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list authorization servers o k response has a 4xx status code
func (o *ListAuthorizationServersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list authorization servers o k response has a 5xx status code
func (o *ListAuthorizationServersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list authorization servers o k response a status code equal to that given
func (o *ListAuthorizationServersOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListAuthorizationServersOK) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersOK  %+v", 200, o.Payload)
}

func (o *ListAuthorizationServersOK) String() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersOK  %+v", 200, o.Payload)
}

func (o *ListAuthorizationServersOK) GetPayload() *models.ServersResponse {
	return o.Payload
}

func (o *ListAuthorizationServersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ServersResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuthorizationServersUnauthorized creates a ListAuthorizationServersUnauthorized with default headers values
func NewListAuthorizationServersUnauthorized() *ListAuthorizationServersUnauthorized {
	return &ListAuthorizationServersUnauthorized{}
}

/*
ListAuthorizationServersUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListAuthorizationServersUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list authorization servers unauthorized response has a 2xx status code
func (o *ListAuthorizationServersUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list authorization servers unauthorized response has a 3xx status code
func (o *ListAuthorizationServersUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list authorization servers unauthorized response has a 4xx status code
func (o *ListAuthorizationServersUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list authorization servers unauthorized response has a 5xx status code
func (o *ListAuthorizationServersUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list authorization servers unauthorized response a status code equal to that given
func (o *ListAuthorizationServersUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListAuthorizationServersUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersUnauthorized  %+v", 401, o.Payload)
}

func (o *ListAuthorizationServersUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersUnauthorized  %+v", 401, o.Payload)
}

func (o *ListAuthorizationServersUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuthorizationServersUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuthorizationServersForbidden creates a ListAuthorizationServersForbidden with default headers values
func NewListAuthorizationServersForbidden() *ListAuthorizationServersForbidden {
	return &ListAuthorizationServersForbidden{}
}

/*
ListAuthorizationServersForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListAuthorizationServersForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list authorization servers forbidden response has a 2xx status code
func (o *ListAuthorizationServersForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list authorization servers forbidden response has a 3xx status code
func (o *ListAuthorizationServersForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list authorization servers forbidden response has a 4xx status code
func (o *ListAuthorizationServersForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list authorization servers forbidden response has a 5xx status code
func (o *ListAuthorizationServersForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list authorization servers forbidden response a status code equal to that given
func (o *ListAuthorizationServersForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListAuthorizationServersForbidden) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersForbidden  %+v", 403, o.Payload)
}

func (o *ListAuthorizationServersForbidden) String() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersForbidden  %+v", 403, o.Payload)
}

func (o *ListAuthorizationServersForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuthorizationServersForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuthorizationServersNotFound creates a ListAuthorizationServersNotFound with default headers values
func NewListAuthorizationServersNotFound() *ListAuthorizationServersNotFound {
	return &ListAuthorizationServersNotFound{}
}

/*
ListAuthorizationServersNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListAuthorizationServersNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list authorization servers not found response has a 2xx status code
func (o *ListAuthorizationServersNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list authorization servers not found response has a 3xx status code
func (o *ListAuthorizationServersNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list authorization servers not found response has a 4xx status code
func (o *ListAuthorizationServersNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list authorization servers not found response has a 5xx status code
func (o *ListAuthorizationServersNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list authorization servers not found response a status code equal to that given
func (o *ListAuthorizationServersNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListAuthorizationServersNotFound) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersNotFound  %+v", 404, o.Payload)
}

func (o *ListAuthorizationServersNotFound) String() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersNotFound  %+v", 404, o.Payload)
}

func (o *ListAuthorizationServersNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuthorizationServersNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuthorizationServersTooManyRequests creates a ListAuthorizationServersTooManyRequests with default headers values
func NewListAuthorizationServersTooManyRequests() *ListAuthorizationServersTooManyRequests {
	return &ListAuthorizationServersTooManyRequests{}
}

/*
ListAuthorizationServersTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListAuthorizationServersTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list authorization servers too many requests response has a 2xx status code
func (o *ListAuthorizationServersTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list authorization servers too many requests response has a 3xx status code
func (o *ListAuthorizationServersTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list authorization servers too many requests response has a 4xx status code
func (o *ListAuthorizationServersTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list authorization servers too many requests response has a 5xx status code
func (o *ListAuthorizationServersTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list authorization servers too many requests response a status code equal to that given
func (o *ListAuthorizationServersTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListAuthorizationServersTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListAuthorizationServersTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers][%d] listAuthorizationServersTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListAuthorizationServersTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuthorizationServersTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
