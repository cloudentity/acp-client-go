// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListConsentsReader is a Reader for the ListConsents structure.
type ListConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListConsentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListConsentsOK creates a ListConsentsOK with default headers values
func NewListConsentsOK() *ListConsentsOK {
	return &ListConsentsOK{}
}

/*
ListConsentsOK describes a response with status code 200, with default header values.

Consents
*/
type ListConsentsOK struct {
	Payload *models.Consents
}

// IsSuccess returns true when this list consents o k response has a 2xx status code
func (o *ListConsentsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list consents o k response has a 3xx status code
func (o *ListConsentsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list consents o k response has a 4xx status code
func (o *ListConsentsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list consents o k response has a 5xx status code
func (o *ListConsentsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list consents o k response a status code equal to that given
func (o *ListConsentsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListConsentsOK) Error() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsOK  %+v", 200, o.Payload)
}

func (o *ListConsentsOK) String() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsOK  %+v", 200, o.Payload)
}

func (o *ListConsentsOK) GetPayload() *models.Consents {
	return o.Payload
}

func (o *ListConsentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Consents)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConsentsUnauthorized creates a ListConsentsUnauthorized with default headers values
func NewListConsentsUnauthorized() *ListConsentsUnauthorized {
	return &ListConsentsUnauthorized{}
}

/*
ListConsentsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListConsentsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list consents unauthorized response has a 2xx status code
func (o *ListConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list consents unauthorized response has a 3xx status code
func (o *ListConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list consents unauthorized response has a 4xx status code
func (o *ListConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list consents unauthorized response has a 5xx status code
func (o *ListConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list consents unauthorized response a status code equal to that given
func (o *ListConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListConsentsUnauthorized) String() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListConsentsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConsentsForbidden creates a ListConsentsForbidden with default headers values
func NewListConsentsForbidden() *ListConsentsForbidden {
	return &ListConsentsForbidden{}
}

/*
ListConsentsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListConsentsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list consents forbidden response has a 2xx status code
func (o *ListConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list consents forbidden response has a 3xx status code
func (o *ListConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list consents forbidden response has a 4xx status code
func (o *ListConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list consents forbidden response has a 5xx status code
func (o *ListConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list consents forbidden response a status code equal to that given
func (o *ListConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListConsentsForbidden) Error() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsForbidden  %+v", 403, o.Payload)
}

func (o *ListConsentsForbidden) String() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsForbidden  %+v", 403, o.Payload)
}

func (o *ListConsentsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListConsentsTooManyRequests creates a ListConsentsTooManyRequests with default headers values
func NewListConsentsTooManyRequests() *ListConsentsTooManyRequests {
	return &ListConsentsTooManyRequests{}
}

/*
ListConsentsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListConsentsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list consents too many requests response has a 2xx status code
func (o *ListConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list consents too many requests response has a 3xx status code
func (o *ListConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list consents too many requests response has a 4xx status code
func (o *ListConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list consents too many requests response has a 5xx status code
func (o *ListConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list consents too many requests response a status code equal to that given
func (o *ListConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /consents][%d] listConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListConsentsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
