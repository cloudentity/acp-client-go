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

// RpInitiatedLogoutPostReader is a Reader for the RpInitiatedLogoutPost structure.
type RpInitiatedLogoutPostReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RpInitiatedLogoutPostReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRpInitiatedLogoutPostOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRpInitiatedLogoutPostUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRpInitiatedLogoutPostNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRpInitiatedLogoutPostTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /oidc/logout] rpInitiatedLogoutPost", response, response.Code())
	}
}

// NewRpInitiatedLogoutPostOK creates a RpInitiatedLogoutPostOK with default headers values
func NewRpInitiatedLogoutPostOK() *RpInitiatedLogoutPostOK {
	return &RpInitiatedLogoutPostOK{}
}

/*
RpInitiatedLogoutPostOK describes a response with status code 200, with default header values.

Empty response
*/
type RpInitiatedLogoutPostOK struct {
}

// IsSuccess returns true when this rp initiated logout post o k response has a 2xx status code
func (o *RpInitiatedLogoutPostOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rp initiated logout post o k response has a 3xx status code
func (o *RpInitiatedLogoutPostOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout post o k response has a 4xx status code
func (o *RpInitiatedLogoutPostOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this rp initiated logout post o k response has a 5xx status code
func (o *RpInitiatedLogoutPostOK) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout post o k response a status code equal to that given
func (o *RpInitiatedLogoutPostOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the rp initiated logout post o k response
func (o *RpInitiatedLogoutPostOK) Code() int {
	return 200
}

func (o *RpInitiatedLogoutPostOK) Error() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostOK ", 200)
}

func (o *RpInitiatedLogoutPostOK) String() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostOK ", 200)
}

func (o *RpInitiatedLogoutPostOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRpInitiatedLogoutPostUnauthorized creates a RpInitiatedLogoutPostUnauthorized with default headers values
func NewRpInitiatedLogoutPostUnauthorized() *RpInitiatedLogoutPostUnauthorized {
	return &RpInitiatedLogoutPostUnauthorized{}
}

/*
RpInitiatedLogoutPostUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutPostUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout post unauthorized response has a 2xx status code
func (o *RpInitiatedLogoutPostUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout post unauthorized response has a 3xx status code
func (o *RpInitiatedLogoutPostUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout post unauthorized response has a 4xx status code
func (o *RpInitiatedLogoutPostUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout post unauthorized response has a 5xx status code
func (o *RpInitiatedLogoutPostUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout post unauthorized response a status code equal to that given
func (o *RpInitiatedLogoutPostUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the rp initiated logout post unauthorized response
func (o *RpInitiatedLogoutPostUnauthorized) Code() int {
	return 401
}

func (o *RpInitiatedLogoutPostUnauthorized) Error() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostUnauthorized  %+v", 401, o.Payload)
}

func (o *RpInitiatedLogoutPostUnauthorized) String() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostUnauthorized  %+v", 401, o.Payload)
}

func (o *RpInitiatedLogoutPostUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutPostUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRpInitiatedLogoutPostNotFound creates a RpInitiatedLogoutPostNotFound with default headers values
func NewRpInitiatedLogoutPostNotFound() *RpInitiatedLogoutPostNotFound {
	return &RpInitiatedLogoutPostNotFound{}
}

/*
RpInitiatedLogoutPostNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutPostNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout post not found response has a 2xx status code
func (o *RpInitiatedLogoutPostNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout post not found response has a 3xx status code
func (o *RpInitiatedLogoutPostNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout post not found response has a 4xx status code
func (o *RpInitiatedLogoutPostNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout post not found response has a 5xx status code
func (o *RpInitiatedLogoutPostNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout post not found response a status code equal to that given
func (o *RpInitiatedLogoutPostNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the rp initiated logout post not found response
func (o *RpInitiatedLogoutPostNotFound) Code() int {
	return 404
}

func (o *RpInitiatedLogoutPostNotFound) Error() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostNotFound  %+v", 404, o.Payload)
}

func (o *RpInitiatedLogoutPostNotFound) String() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostNotFound  %+v", 404, o.Payload)
}

func (o *RpInitiatedLogoutPostNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutPostNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRpInitiatedLogoutPostTooManyRequests creates a RpInitiatedLogoutPostTooManyRequests with default headers values
func NewRpInitiatedLogoutPostTooManyRequests() *RpInitiatedLogoutPostTooManyRequests {
	return &RpInitiatedLogoutPostTooManyRequests{}
}

/*
RpInitiatedLogoutPostTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type RpInitiatedLogoutPostTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this rp initiated logout post too many requests response has a 2xx status code
func (o *RpInitiatedLogoutPostTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rp initiated logout post too many requests response has a 3xx status code
func (o *RpInitiatedLogoutPostTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rp initiated logout post too many requests response has a 4xx status code
func (o *RpInitiatedLogoutPostTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this rp initiated logout post too many requests response has a 5xx status code
func (o *RpInitiatedLogoutPostTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this rp initiated logout post too many requests response a status code equal to that given
func (o *RpInitiatedLogoutPostTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the rp initiated logout post too many requests response
func (o *RpInitiatedLogoutPostTooManyRequests) Code() int {
	return 429
}

func (o *RpInitiatedLogoutPostTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostTooManyRequests  %+v", 429, o.Payload)
}

func (o *RpInitiatedLogoutPostTooManyRequests) String() string {
	return fmt.Sprintf("[POST /oidc/logout][%d] rpInitiatedLogoutPostTooManyRequests  %+v", 429, o.Payload)
}

func (o *RpInitiatedLogoutPostTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RpInitiatedLogoutPostTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}