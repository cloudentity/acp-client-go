// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/developer/models"
)

// ListServersForDeveloperReader is a Reader for the ListServersForDeveloper structure.
type ListServersForDeveloperReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServersForDeveloperReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServersForDeveloperOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListServersForDeveloperUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListServersForDeveloperForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListServersForDeveloperNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListServersForDeveloperTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListServersForDeveloperOK creates a ListServersForDeveloperOK with default headers values
func NewListServersForDeveloperOK() *ListServersForDeveloperOK {
	return &ListServersForDeveloperOK{}
}

/*
ListServersForDeveloperOK describes a response with status code 200, with default header values.

List developer servers
*/
type ListServersForDeveloperOK struct {
	Payload *models.ListServersDeveloperResponse
}

// IsSuccess returns true when this list servers for developer o k response has a 2xx status code
func (o *ListServersForDeveloperOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list servers for developer o k response has a 3xx status code
func (o *ListServersForDeveloperOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers for developer o k response has a 4xx status code
func (o *ListServersForDeveloperOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list servers for developer o k response has a 5xx status code
func (o *ListServersForDeveloperOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers for developer o k response a status code equal to that given
func (o *ListServersForDeveloperOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListServersForDeveloperOK) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperOK  %+v", 200, o.Payload)
}

func (o *ListServersForDeveloperOK) String() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperOK  %+v", 200, o.Payload)
}

func (o *ListServersForDeveloperOK) GetPayload() *models.ListServersDeveloperResponse {
	return o.Payload
}

func (o *ListServersForDeveloperOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListServersDeveloperResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersForDeveloperUnauthorized creates a ListServersForDeveloperUnauthorized with default headers values
func NewListServersForDeveloperUnauthorized() *ListServersForDeveloperUnauthorized {
	return &ListServersForDeveloperUnauthorized{}
}

/*
ListServersForDeveloperUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListServersForDeveloperUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers for developer unauthorized response has a 2xx status code
func (o *ListServersForDeveloperUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers for developer unauthorized response has a 3xx status code
func (o *ListServersForDeveloperUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers for developer unauthorized response has a 4xx status code
func (o *ListServersForDeveloperUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers for developer unauthorized response has a 5xx status code
func (o *ListServersForDeveloperUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers for developer unauthorized response a status code equal to that given
func (o *ListServersForDeveloperUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListServersForDeveloperUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServersForDeveloperUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServersForDeveloperUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersForDeveloperUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersForDeveloperForbidden creates a ListServersForDeveloperForbidden with default headers values
func NewListServersForDeveloperForbidden() *ListServersForDeveloperForbidden {
	return &ListServersForDeveloperForbidden{}
}

/*
ListServersForDeveloperForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListServersForDeveloperForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers for developer forbidden response has a 2xx status code
func (o *ListServersForDeveloperForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers for developer forbidden response has a 3xx status code
func (o *ListServersForDeveloperForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers for developer forbidden response has a 4xx status code
func (o *ListServersForDeveloperForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers for developer forbidden response has a 5xx status code
func (o *ListServersForDeveloperForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers for developer forbidden response a status code equal to that given
func (o *ListServersForDeveloperForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListServersForDeveloperForbidden) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperForbidden  %+v", 403, o.Payload)
}

func (o *ListServersForDeveloperForbidden) String() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperForbidden  %+v", 403, o.Payload)
}

func (o *ListServersForDeveloperForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersForDeveloperForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersForDeveloperNotFound creates a ListServersForDeveloperNotFound with default headers values
func NewListServersForDeveloperNotFound() *ListServersForDeveloperNotFound {
	return &ListServersForDeveloperNotFound{}
}

/*
ListServersForDeveloperNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListServersForDeveloperNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers for developer not found response has a 2xx status code
func (o *ListServersForDeveloperNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers for developer not found response has a 3xx status code
func (o *ListServersForDeveloperNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers for developer not found response has a 4xx status code
func (o *ListServersForDeveloperNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers for developer not found response has a 5xx status code
func (o *ListServersForDeveloperNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers for developer not found response a status code equal to that given
func (o *ListServersForDeveloperNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListServersForDeveloperNotFound) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperNotFound  %+v", 404, o.Payload)
}

func (o *ListServersForDeveloperNotFound) String() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperNotFound  %+v", 404, o.Payload)
}

func (o *ListServersForDeveloperNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersForDeveloperNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServersForDeveloperTooManyRequests creates a ListServersForDeveloperTooManyRequests with default headers values
func NewListServersForDeveloperTooManyRequests() *ListServersForDeveloperTooManyRequests {
	return &ListServersForDeveloperTooManyRequests{}
}

/*
ListServersForDeveloperTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListServersForDeveloperTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list servers for developer too many requests response has a 2xx status code
func (o *ListServersForDeveloperTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list servers for developer too many requests response has a 3xx status code
func (o *ListServersForDeveloperTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list servers for developer too many requests response has a 4xx status code
func (o *ListServersForDeveloperTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list servers for developer too many requests response has a 5xx status code
func (o *ListServersForDeveloperTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list servers for developer too many requests response a status code equal to that given
func (o *ListServersForDeveloperTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListServersForDeveloperTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListServersForDeveloperTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers][%d] listServersForDeveloperTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListServersForDeveloperTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListServersForDeveloperTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
