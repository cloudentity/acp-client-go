// Code generated by go-swagger; DO NOT EDIT.

package scopes

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// ListScopesSystemReader is a Reader for the ListScopesSystem structure.
type ListScopesSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListScopesSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListScopesSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListScopesSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListScopesSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListScopesSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListScopesSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /scopes/{wid}] listScopesSystem", response, response.Code())
	}
}

// NewListScopesSystemOK creates a ListScopesSystemOK with default headers values
func NewListScopesSystemOK() *ListScopesSystemOK {
	return &ListScopesSystemOK{}
}

/*
ListScopesSystemOK describes a response with status code 200, with default header values.

ScopesWithServices
*/
type ListScopesSystemOK struct {
	Payload *models.ScopesWithServices
}

// IsSuccess returns true when this list scopes system o k response has a 2xx status code
func (o *ListScopesSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list scopes system o k response has a 3xx status code
func (o *ListScopesSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list scopes system o k response has a 4xx status code
func (o *ListScopesSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list scopes system o k response has a 5xx status code
func (o *ListScopesSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list scopes system o k response a status code equal to that given
func (o *ListScopesSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list scopes system o k response
func (o *ListScopesSystemOK) Code() int {
	return 200
}

func (o *ListScopesSystemOK) Error() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemOK  %+v", 200, o.Payload)
}

func (o *ListScopesSystemOK) String() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemOK  %+v", 200, o.Payload)
}

func (o *ListScopesSystemOK) GetPayload() *models.ScopesWithServices {
	return o.Payload
}

func (o *ListScopesSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ScopesWithServices)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScopesSystemUnauthorized creates a ListScopesSystemUnauthorized with default headers values
func NewListScopesSystemUnauthorized() *ListScopesSystemUnauthorized {
	return &ListScopesSystemUnauthorized{}
}

/*
ListScopesSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListScopesSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list scopes system unauthorized response has a 2xx status code
func (o *ListScopesSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list scopes system unauthorized response has a 3xx status code
func (o *ListScopesSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list scopes system unauthorized response has a 4xx status code
func (o *ListScopesSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list scopes system unauthorized response has a 5xx status code
func (o *ListScopesSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list scopes system unauthorized response a status code equal to that given
func (o *ListScopesSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list scopes system unauthorized response
func (o *ListScopesSystemUnauthorized) Code() int {
	return 401
}

func (o *ListScopesSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *ListScopesSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *ListScopesSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScopesSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScopesSystemForbidden creates a ListScopesSystemForbidden with default headers values
func NewListScopesSystemForbidden() *ListScopesSystemForbidden {
	return &ListScopesSystemForbidden{}
}

/*
ListScopesSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListScopesSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list scopes system forbidden response has a 2xx status code
func (o *ListScopesSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list scopes system forbidden response has a 3xx status code
func (o *ListScopesSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list scopes system forbidden response has a 4xx status code
func (o *ListScopesSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list scopes system forbidden response has a 5xx status code
func (o *ListScopesSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list scopes system forbidden response a status code equal to that given
func (o *ListScopesSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list scopes system forbidden response
func (o *ListScopesSystemForbidden) Code() int {
	return 403
}

func (o *ListScopesSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemForbidden  %+v", 403, o.Payload)
}

func (o *ListScopesSystemForbidden) String() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemForbidden  %+v", 403, o.Payload)
}

func (o *ListScopesSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScopesSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScopesSystemNotFound creates a ListScopesSystemNotFound with default headers values
func NewListScopesSystemNotFound() *ListScopesSystemNotFound {
	return &ListScopesSystemNotFound{}
}

/*
ListScopesSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListScopesSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list scopes system not found response has a 2xx status code
func (o *ListScopesSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list scopes system not found response has a 3xx status code
func (o *ListScopesSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list scopes system not found response has a 4xx status code
func (o *ListScopesSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list scopes system not found response has a 5xx status code
func (o *ListScopesSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list scopes system not found response a status code equal to that given
func (o *ListScopesSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list scopes system not found response
func (o *ListScopesSystemNotFound) Code() int {
	return 404
}

func (o *ListScopesSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemNotFound  %+v", 404, o.Payload)
}

func (o *ListScopesSystemNotFound) String() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemNotFound  %+v", 404, o.Payload)
}

func (o *ListScopesSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScopesSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScopesSystemTooManyRequests creates a ListScopesSystemTooManyRequests with default headers values
func NewListScopesSystemTooManyRequests() *ListScopesSystemTooManyRequests {
	return &ListScopesSystemTooManyRequests{}
}

/*
ListScopesSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListScopesSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list scopes system too many requests response has a 2xx status code
func (o *ListScopesSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list scopes system too many requests response has a 3xx status code
func (o *ListScopesSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list scopes system too many requests response has a 4xx status code
func (o *ListScopesSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list scopes system too many requests response has a 5xx status code
func (o *ListScopesSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list scopes system too many requests response a status code equal to that given
func (o *ListScopesSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list scopes system too many requests response
func (o *ListScopesSystemTooManyRequests) Code() int {
	return 429
}

func (o *ListScopesSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListScopesSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /scopes/{wid}][%d] listScopesSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListScopesSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScopesSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
