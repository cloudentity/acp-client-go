// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
)

// RpInitiatedLogoutReader is a Reader for the RpInitiatedLogout structure.
type RpInitiatedLogoutReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RpInitiatedLogoutReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRpInitiatedLogoutOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRpInitiatedLogoutUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRpInitiatedLogoutNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRpInitiatedLogoutTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /oidc/logout] rpInitiatedLogout", response, response.Code())
	}
}

// NewRpInitiatedLogoutOK creates a RpInitiatedLogoutOK with default headers values
func NewRpInitiatedLogoutOK() *RpInitiatedLogoutOK {
	return &RpInitiatedLogoutOK{}
}

/*
RpInitiatedLogoutOK describes a response with status code 200, with default header values.

Empty response
*/
type RpInitiatedLogoutOK struct {
}

// IsSuccess returns true when this rp initiated logout o k response has a 2xx status code
func (o *RpInitiatedLogoutOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rp initiated logout o k response has a 3xx status code
func (o *RpInitiatedLogoutOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout o k response has a 4xx status code
func (o *RpInitiatedLogoutOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this rp initiated logout o k response has a 5xx status code
func (o *RpInitiatedLogoutOK) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout o k response a status code equal to that given
func (o *RpInitiatedLogoutOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the rp initiated logout o k response
func (o *RpInitiatedLogoutOK) Code() int {
	return 200
}

func (o *RpInitiatedLogoutOK) Error() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutOK ", 200)
}

func (o *RpInitiatedLogoutOK) String() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutOK ", 200)
}

func (o *RpInitiatedLogoutOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRpInitiatedLogoutUnauthorized creates a RpInitiatedLogoutUnauthorized with default headers values
func NewRpInitiatedLogoutUnauthorized() *RpInitiatedLogoutUnauthorized {
	return &RpInitiatedLogoutUnauthorized{}
}

/*
RpInitiatedLogoutUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout unauthorized response has a 2xx status code
func (o *RpInitiatedLogoutUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout unauthorized response has a 3xx status code
func (o *RpInitiatedLogoutUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout unauthorized response has a 4xx status code
func (o *RpInitiatedLogoutUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout unauthorized response has a 5xx status code
func (o *RpInitiatedLogoutUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout unauthorized response a status code equal to that given
func (o *RpInitiatedLogoutUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the rp initiated logout unauthorized response
func (o *RpInitiatedLogoutUnauthorized) Code() int {
	return 401
}

func (o *RpInitiatedLogoutUnauthorized) Error() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutUnauthorized  %+v", 401, o.Payload)
}

func (o *RpInitiatedLogoutUnauthorized) String() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutUnauthorized  %+v", 401, o.Payload)
}

func (o *RpInitiatedLogoutUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRpInitiatedLogoutNotFound creates a RpInitiatedLogoutNotFound with default headers values
func NewRpInitiatedLogoutNotFound() *RpInitiatedLogoutNotFound {
	return &RpInitiatedLogoutNotFound{}
}

/*
RpInitiatedLogoutNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout not found response has a 2xx status code
func (o *RpInitiatedLogoutNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout not found response has a 3xx status code
func (o *RpInitiatedLogoutNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout not found response has a 4xx status code
func (o *RpInitiatedLogoutNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout not found response has a 5xx status code
func (o *RpInitiatedLogoutNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout not found response a status code equal to that given
func (o *RpInitiatedLogoutNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the rp initiated logout not found response
func (o *RpInitiatedLogoutNotFound) Code() int {
	return 404
}

func (o *RpInitiatedLogoutNotFound) Error() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutNotFound  %+v", 404, o.Payload)
}

func (o *RpInitiatedLogoutNotFound) String() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutNotFound  %+v", 404, o.Payload)
}

func (o *RpInitiatedLogoutNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRpInitiatedLogoutTooManyRequests creates a RpInitiatedLogoutTooManyRequests with default headers values
func NewRpInitiatedLogoutTooManyRequests() *RpInitiatedLogoutTooManyRequests {
	return &RpInitiatedLogoutTooManyRequests{}
}

/*
RpInitiatedLogoutTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout too many requests response has a 2xx status code
func (o *RpInitiatedLogoutTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout too many requests response has a 3xx status code
func (o *RpInitiatedLogoutTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout too many requests response has a 4xx status code
func (o *RpInitiatedLogoutTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout too many requests response has a 5xx status code
func (o *RpInitiatedLogoutTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout too many requests response a status code equal to that given
func (o *RpInitiatedLogoutTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the rp initiated logout too many requests response
func (o *RpInitiatedLogoutTooManyRequests) Code() int {
	return 429
}

func (o *RpInitiatedLogoutTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutTooManyRequests  %+v", 429, o.Payload)
}

func (o *RpInitiatedLogoutTooManyRequests) String() string {
	return fmt.Sprintf("[GET /oidc/logout][%d] rpInitiatedLogoutTooManyRequests  %+v", 429, o.Payload)
}

func (o *RpInitiatedLogoutTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}